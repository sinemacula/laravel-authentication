# Fail-Closed `pid` / `did`

## Purpose

This note records the rule that `pid` and `did` are treated as commitments, not best-effort hints. If a token claims a
specific principal or device and the runtime cannot prove that claim, authentication fails.

## Invariants

- A present `pid` must resolve to that exact principal identifier. The same check verifies a principal pinned on
  `attempt()`, which must also come back as the same class and be owned by the authenticated identity: its
  `getIdentity()`, read from the write connection, must be that identity's class and auth identifier, so a resolver
  whose hinted lookup is not scoped to the identity cannot bind another identity's principal.
- A present bearer `did` must resolve to a real, unrevoked device owned by the resolved identity. A device with
  `revoked_at` set is treated exactly like a missing one, so revoking a device ends its access tokens at once; the check
  reads the row the lookup already loaded, with no extra query. Any stored `revoked_at` counts, so a custom model using
  `ActsAsDevice` without a `datetime` cast on the column is rejected too. The same lookup verifies a device pinned on
  `attempt()`, which must also come back as the same class.
- Refresh is stricter than bearer auth: refresh always requires a valid `did`, because refresh is device-backed.
- A `did` is checked against the device model's key format before any query; one that cannot be a key fails closed as
  an unresolved device, and a database error on a well-formed `did` propagates instead of reading as a missing device.
- Unsupported or transient identifiers stringify to `null` and therefore fail matching rather than being tolerated.
- Failure attribution should still point at the already resolved identity when `pid` or `did` rejection happens late in
  the bearer flow.
- `pid`, `did`, and active-state checks run live on every request; nothing is cached across requests.
- The identity, principal, tenant, and device reads behind those checks go to the write connection, so a lagging read
  replica cannot satisfy a `pid` or `did`, or an activity check, the primary no longer recognises. The identity and
  principal lookups run with their model's connection pinned, so relations they eager-load (a `$with` tenant, say) come
  from the writer too, not only the lookup's own query, and so does each `CanBeActive::isActive()` check.

## Success Path

- An access token must carry `pid`: one without it fails to parse, so the bearer path never falls back to the resolver's
  default principal. A refresh token may omit `pid`, in which case refresh uses the default principal policy.
- Issuing enforces the same claims: `issueAccessToken()` and `issueRefreshToken()` throw an `InvalidArgumentException`
  instead of minting a token with an empty `sub`, `pid`, `did`, or `jti` (an unsaved model or a non-scalar identifier),
  so a token that could never authenticate, or would silently drop its device or principal, is never issued.
- If no bearer `did` is present, auth can still succeed with `device = null`.
- If `pid` is present and the resolver returns the exact matching principal, auth continues normally.
- If refresh carries `pid`, the same exact-match rule is applied before the rotated pair is issued.

## Failure / Edge Cases

- The default resolver may fall through from a hinted miss to the 2D or 3D default principal path. The guard and the
  refresh exchange explicitly prevent that fallback from becoming an auth downgrade by re-checking the resolved
  identifier against the hinted `pid`.
- Identities may implement `ResolvesHintedPrincipal` to short-circuit the hinted lookup, but a `null` / non-Principal
  result still falls through to the existing default resolver path and is therefore subject to the same fail-closed
  `pid` re-check.
- A resolver that returns an unsaved principal with a `null` identifier is rejected for the same reason.
- On the bearer path, `did` resolution is identity-scoped through `HasDevices`; a token that claims a device against an
  identity with no device capability fails closed instead of silently binding no device.
- On the refresh path, `did` resolution is global through the configured device model, and the device's owner is
  reloaded through the guard's identity provider (see `guard-bound-tokens.md`).
- When bearer auth rejects a token after the identity has already been loaded, the emitted `Failed` event still carries
  that resolved identity for attribution.

## Implementation Anchors

- `src/Guards/JwtGuard.php`: `resolveContextFromToken()`, `resolvePrincipalFromClaims()`, `loadIdentityFromClaims()`.
- `src/Guards/Concerns/VerifiesPinnedContext.php`: `matchesPidHint()` and `resolveDeviceFromHint()`, each shared by the
  bearer path and the pinned-context check in `attempt()`, plus `resolvePinnedPrincipal()` and `resolvePinnedDevice()`.
- `src/Jwt/RefreshTokenExchange.php`: `extractRefreshClaims()`, `loadDeviceForRefresh()`, `resolveRefreshPrincipal()`.
- `src/Jwt/IdentifierCoercion.php`: `stringify()` and `matches()`, the exact-match rule behind `matchesPidHint()` and the
  refresh `pid` check.
- `src/Jwt/Enums/TokenType.php`: `requiredClaims()`, enforced by `JwtTokenService::parse()`.
- `src/Jwt/DeviceKeyShape.php`: `matches()`, the `did` shape check shared by the bearer and refresh paths.
- `src/Database/WriteConnection.php`: `query()` and `during()`, which pin the identity, principal, tenant, and device
  reads to the write connection.
- `src/Resolvers/DefaultPrincipalResolver.php`: default resolver behavior that the guard hardens with explicit pid
  matching, including the optional `ResolvesHintedPrincipal` shortcut ahead of the generic `HasPrincipals` lookup.
- `src/Contracts/ResolvesHintedPrincipal.php`: optional 3D optimization seam for hinted principal hydration.
- `src/AuthenticationServiceProvider.php` and `src/Guards/JwtGuard.php`: resolver-rebind wiring so bearer and refresh
  stay on the same principal policy.

## Authoritative Tests

- `tests/Feature/Guards/JwtGuardUserResolutionTest.php`
  `testUserAttributesFailedEventToResolvedIdentityWhenPidHintRejectsToken`
- `tests/Feature/Guards/JwtGuardUserResolutionTest.php`
  `testUserRejectsTokenWithoutPrincipalClaimInsteadOfUsingTheDefault`
- `tests/Unit/Jwt/JwtTokenServiceTest.php`
  `testParseRejectsATokenMissingARequiredClaim`
- `tests/Unit/Jwt/JwtTokenServiceIssueTest.php`
  `testIssueAccessTokenRefusesAPrincipalWithoutUsableIdentifier`
- `tests/Unit/Jwt/JwtTokenServiceIssueTest.php`
  `testIssueRefreshTokenRefusesADeviceWithoutUsableIdentifier`
- `tests/Feature/Guards/JwtGuardUserResolutionTest.php`
  `testUserRejectsTokenWhenPidHintResolvesToNullPrincipal`
- `tests/Feature/Guards/JwtGuardUserResolutionTest.php`
  `testUserRejectsTokenWhenPidHintDoesNotMatchResolvedPrincipal`
- `tests/Feature/Guards/JwtGuardUserResolutionTest.php`
  `testUserRejectsTokenWhenResolvedPrincipalIdentifierIsNull`
- `tests/Feature/Guards/JwtGuardUserResolutionTest.php`
  `testUserRejectsTokenWhenDidHintCannotBeResolved`
- `tests/Feature/Guards/JwtGuardUserResolutionTest.php`
  `testUserAttributesFailedEventToResolvedIdentityWhenDidHintCannotBeResolved`
- `tests/Feature/Guards/JwtGuardUserResolutionTest.php`
  `testUserRejectsTokenWhenDidHintNamesRevokedDevice`
- `tests/Integration/Guards/JwtGuardIntegrationTest.php`
  `testRevokingDeviceBlocksRefreshAndExistingAccessToken`
- `tests/Integration/Guards/JwtGuardWriteConnectionIntegrationTest.php`
  `testBearerRejectsDeviceRevokedOnThePrimaryWhileTheReplicaLags`
- `tests/Integration/Guards/UncastRevokedDeviceIntegrationTest.php`
  `testBearerRejectsTheRevokedDevice`, `testAttemptRejectsTheRevokedDeviceWhenPinned`
- `tests/Feature/Guards/JwtGuardUserResolutionTest.php`
  `testUserRejectsMalformedDidHintWithoutQueryingDevices`
- `tests/Feature/Guards/JwtGuardUserResolutionTest.php`
  `testUserPropagatesDatabaseErrorFromDeviceLookup`
- `tests/Feature/Guards/JwtGuardRefreshResolutionTest.php`
  `testRefreshReturnsNullWhenPrincipalIsUnresolved`
- `tests/Feature/Guards/JwtGuardRefreshResolutionTest.php`
  `testRefreshReturnsNullWhenPidHintDoesNotMatchResolvedPrincipal`
- `tests/Feature/Guards/JwtGuardRefreshResolutionTest.php`
  `testRefreshReturnsNullWhenResolvedPrincipalIdentifierIsNull`
- `tests/Integration/Guards/GuardScopedPrincipalResolverIntegrationTest.php`
  `testGuardsResolveDifferentPrincipalsWithoutCrossContamination`
- `tests/Integration/Guards/AccessOnlyIntegrationTest.php`
  `testForgedDeviceHintFailsClosedWithoutDevicesTable`
- `tests/Integration/Guards/JwtGuardResolutionFreshnessIntegrationTest.php`
  `testBearerRejectsPreviouslyIssuedTokenWhenResolvedPrincipalBecomesInactiveBetweenRequests`
- `tests/Integration/Guards/JwtGuardResolutionFreshnessIntegrationTest.php`
  `testBearerRejectsPreviouslyIssuedTokenWhenHintedDeviceIsDeletedBetweenRequests`
- `tests/Integration/Guards/JwtGuardWriteConnectionIntegrationTest.php`
  `testBearerReadsIdentityAndDeviceFromTheWriteConnection`
- `tests/Integration/Guards/JwtGuardWriteConnectionIntegrationTest.php`
  `testDefaultResolverReadsPrincipalsFromTheWriteConnection`
- `tests/Integration/Guards/JwtGuardEagerLoadWriteConnectionIntegrationTest.php`
  `testBearerRejectsMemberWhoseEagerLoadedTenantIsDeactivatedOnThePrimary`
- `tests/Integration/Guards/JwtGuardEagerLoadWriteConnectionIntegrationTest.php`
  `testBearerRejectsUserWhoseEagerLoadedTenantIsDeactivatedOnThePrimary`
- `tests/Integration/Guards/JwtGuardWriteConnectionIntegrationTest.php`
  `testBearerRejectsIdentitySuspendedOnThePrimaryWhileTheReplicaLags`

## Change Triggers

Update this note when any of the following change:

- how `pid` and `did` are matched or coerced
- which claims each token type requires (`TokenType::requiredClaims()`)
- how a `did` is checked against the device model's key format before the lookup
- whether hinted principal resolution can short-circuit through `ResolvesHintedPrincipal`
- whether bearer `did` remains identity-scoped through `HasDevices`
- whether a revoked device is still rejected on the bearer path like a missing one
- whether refresh `did` remains backed by the configured device model
- how late-path bearer failures are attributed on the `Failed` event
- whether the identity, principal, tenant, and device reads still go to the write connection
- how guard-local or rebound principal resolvers are propagated into refresh
