# Fail-Closed `pid` / `did`

## Purpose

This note records the rule that `pid` and `did` are treated as commitments, not best-effort hints. If a token claims a
specific principal or device and the runtime cannot prove that claim, authentication fails.

## Invariants

- A present `pid` must resolve to that exact principal identifier. The same check verifies a principal pinned on
  `attempt()`, which must also come back as the same class.
- A present bearer `did` must resolve to a real, unrevoked device owned by the resolved identity. A device with
  `revoked_at` set is treated exactly like a missing one, so revoking a device ends its access tokens at once; the check
  reads the row the lookup already loaded, with no extra query.
- Refresh is stricter than bearer auth: refresh always requires a valid `did`, because refresh is device-backed.
- A `did` is checked against the device model's key format before any query; one that cannot be a key fails closed as
  an unresolved device, and a database error on a well-formed `did` propagates instead of reading as a missing device.
- Unsupported or transient identifiers stringify to `null` and therefore fail matching rather than being tolerated.
- Failure attribution should still point at the already resolved identity when `pid` or `did` rejection happens late in
  the bearer flow.
- `pid`, `did`, and active-state checks run live on every request; nothing is cached across requests.
- The identity, principal, and device reads behind those checks go to the write connection, so a lagging read replica
  cannot satisfy a `pid` or `did` the primary no longer recognises.

## Success Path

- If no `pid` is present, the guard may use the resolver's default principal policy.
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

- `src/Guards/JwtGuard.php`: `resolveContextFromToken()`, `resolveDeviceFromHint()`, `resolvePrincipalFromClaims()`,
  `loadIdentityFromClaims()`.
- `src/Guards/Concerns/VerifiesPinnedContext.php`: `matchesPidHint()`, shared by the bearer path and the
  pinned-principal check in `attempt()`, plus `resolvePinnedPrincipal()` and `resolvePinnedDevice()`.
- `src/Jwt/RefreshTokenExchange.php`: `extractRefreshClaims()`, `loadDeviceForRefresh()`, `resolveRefreshPrincipal()`,
  `matchesPidHint()`.
- `src/Jwt/IdentifierCoercion.php`: `stringify()`.
- `src/Jwt/DeviceKeyShape.php`: `matches()`, the `did` shape check shared by the bearer and refresh paths.
- `src/Database/WriteConnection.php`: `query()` and `during()`, which pin the identity, principal, and device reads to
  the write connection.
- `src/Resolvers/DefaultPrincipalResolver.php`: default resolver behavior that the guard hardens with explicit pid
  matching, including the optional `ResolvesHintedPrincipal` shortcut ahead of the generic `HasPrincipals` lookup.
- `src/Contracts/ResolvesHintedPrincipal.php`: optional 3D optimization seam for hinted principal hydration.
- `src/AuthenticationServiceProvider.php` and `src/Guards/JwtGuard.php`: resolver-rebind wiring so bearer and refresh
  stay on the
  same principal policy.

## Authoritative Tests

- `tests/Feature/Guards/JwtGuardUserResolutionTest.php`
  `testUserAttributesFailedEventToResolvedIdentityWhenPidHintRejectsToken`
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
- `tests/Feature/Guards/JwtGuardUserResolutionTest.php`
  `testUserRejectsMalformedDidHintWithoutQueryingDevices`
- `tests/Feature/Guards/JwtGuardUserResolutionTest.php`
  `testUserPropagatesDatabaseErrorFromDeviceLookup`
- `tests/Feature/Guards/JwtGuardRefreshTest.php`
  `testRefreshReturnsNullWhenPrincipalIsUnresolved`
- `tests/Feature/Guards/JwtGuardRefreshTest.php`
  `testRefreshReturnsNullWhenPidHintDoesNotMatchResolvedPrincipal`
- `tests/Feature/Guards/JwtGuardRefreshTest.php`
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

## Change Triggers

Update this note when any of the following change:

- how `pid` and `did` are matched or coerced
- how a `did` is checked against the device model's key format before the lookup
- whether hinted principal resolution can short-circuit through `ResolvesHintedPrincipal`
- whether bearer `did` remains identity-scoped through `HasDevices`
- whether a revoked device is still rejected on the bearer path like a missing one
- whether refresh `did` remains backed by the configured device model
- how late-path bearer failures are attributed on the `Failed` event
- whether the identity, principal, and device reads still go to the write connection
- how guard-local or rebound principal resolvers are propagated into refresh
