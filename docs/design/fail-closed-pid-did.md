# Fail-Closed `pid` / `did`

## Purpose

This note records the rule that `pid` and `did` are treated as commitments, not best-effort hints. If a token claims a
specific principal or device and the runtime cannot prove that claim, authentication fails.

## Invariants

- A present `pid` must resolve to that exact principal identifier. The same check verifies a principal pinned on
  `attempt()`, which must also come back as the same class and be owned by the authenticated identity: its
  `getIdentity()`, read from the write connection and from the principal's stored key rather than a relation the
  resolver set (lazily, even when the principal was hydrated with lazy loading prevented), must be that identity's class
  and auth identifier, so a resolver whose hinted lookup is not scoped to the identity cannot bind another identity's
  principal. An owner that cannot be read fails closed.
- A present bearer `did` must resolve to a real, unrevoked device owned by the resolved identity whose session has not
  ended. A device with `revoked_at` set, or past its idle or absolute deadline (or without one), is rejected like a
  missing one, with its own reason (`device_revoked`, `session_expired`; a device of another guard
  `device_guard_mismatch`, a missing one `device_unknown`), so revoking a device or ending its session ends its access
  tokens at once; the check reads the row the lookup already loaded, with no extra query, and applies no JWT leeway, so
  an access token cannot outlive its session. Any stored `revoked_at` counts, so a custom model using `ActsAsDevice`
  without a `datetime` cast on the column is rejected too, and a device loaded without one of its state columns throws a
  `LogicException` instead of being read as not revoked. The same lookup verifies a device pinned on `attempt()`, which
  must also come back as the same class.
- A bearer `did` is accepted only for the principal the device's session records: the device's `principal_type` and
  `principal_id` must name the token's principal (a device that records none fails closed), and the token's `iat` must
  not be before the second of the session's last principal switch (`principal_switched_at`), else
  `device_principal_mismatch`. A switch from A to B ends A's tokens at once, and a switch back to A does not revive the
  A tokens issued before it; the switch's own tokens are issued in its second, so they pass. The one residue is an A
  token issued in the same second as an A -> B -> A pair completed within that second. A device pinned on `attempt()`
  must record the principal being bound, else `device_mismatch`. Both read the row already loaded, with no query, and
  a device loaded without `principal_switched_at` throws a `LogicException` rather than reading as never switched.
- Refresh is stricter than bearer auth: refresh always requires a valid `did`, because refresh is device-backed.
- A `did` is checked against the device model's key format before any query; one that cannot be a key fails closed as
  an unresolved device, and a database error on a well-formed `did` propagates instead of reading as a missing device.
- Unsupported or transient identifiers stringify to `null` and therefore fail matching rather than being tolerated.
- Failure attribution should still point at the already resolved identity when `pid` or `did` rejection happens late in
  the bearer flow.
- `pid`, `did`, and active-state checks run live on every request; nothing is cached across requests.
- The identity, principal, tenant, and device reads behind those checks go to the write connection, so a lagging read
  replica cannot satisfy a `pid` or `did`, or an activity check, the primary no longer recognises. The identity,
  principal, and device lookups run inside `WriteConnection::during()`, which pins their model's connection and every
  connection a model resolves while they run, so relations they eager-load (a `$with` tenant, say) come from the writer
  too, not only the lookup's own query, even on another connection; so does each `CanBeActive::isActive()` check, the
  tenant read, and a device's revocation and deadline reads, whether or not the subject is an Eloquent model. The
  identity's `devices()` relation is built inside the identity's window, so a relation that queries while it is built
  reads the writer as well.

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
  identity with no device capability fails closed instead of silently binding no device, and a `devices()` relation
  over a model that is not an `EloquentDevice` throws a `LogicException` before it is queried.
- On the refresh path, `did` resolution is global through the configured device model, and the device's owner is
  reloaded through the guard's identity provider (see `guard-bound-tokens.md`).
- When bearer auth rejects a token after the identity has already been loaded, the `AuthenticationFailed` event still
  carries that resolved identity (and the principal and device, once found) for attribution, and the `did` the token
  named.

## Implementation Anchors

- `src/Guards/BearerAuthentication.php`: `authenticate()`, `admitAs()` (the exact `pid` match), `onDevice()` and
  `principalRefusal()`; `src/Guards/OwnedDevice.php`: `refusal()`, `actsAs()` and `isIssuedSinceSwitch()`, shared with
  the `attempt()` device pin.
- `src/Sessions/IdentityDevices.php`: `find()`, the identity-scoped device lookup behind a bearer `did`, a device pinned
  on `attempt()` and the session service's `revokeDevice()`.
- `src/Guards/Concerns/VerifiesPinnedContext.php`: `resolvePinnedPrincipal()`, `resolvePinnedDevice()` and
  `resolveDeviceFromHint()`, the pinned-context checks in `attempt()`.
- `src/Jwt/RefreshTokenExchange.php`: `extractRefreshClaims()`; `src/Jwt/RefreshJudgement.php`: `classify()`;
  `src/Jwt/RefreshAdmission.php`: `principal()`; the device is found by `src/Jwt/DeviceLookup.php`'s `find()`.
- `src/Support/IdentifierCoercion.php`: `stringify()` and `matches()`, the exact-match rule behind the bearer and
  refresh `pid` checks.
- `src/Jwt/Enums/TokenType.php`: `requiredClaims()`, enforced by `JwtTokenService::parse()`.
- `src/Jwt/DeviceKeyShape.php`: `matches()`, the `did` shape check shared by the bearer and refresh paths.
- `src/Jwt/TokenLifetimes.php`: `hasEnded()`, the one deadline rule the bearer path, pins, refresh, and issuance share.
- `src/Database/WriteConnection.php`: `query()` and `during()`, which pin the identity, principal, tenant, and device
  reads to the write connection; `src/Database/PinningConnectionResolver.php` carries the pin to every connection a
  model resolves inside `during()`.
- `src/Resolvers/DefaultPrincipalResolver.php`: default resolver behavior that the guard hardens with explicit pid
  matching, including the optional `ResolvesHintedPrincipal` shortcut ahead of the generic `HasPrincipals` lookup.
- `src/Contracts/ResolvesHintedPrincipal.php`: optional 3D optimization seam for hinted principal hydration.
- `src/AuthenticationServiceProvider.php` and `src/Guards/JwtGuard.php`: resolver-rebind wiring so bearer and refresh
  stay on the same principal policy.

## Authoritative Tests

- `tests/Feature/Guards/JwtGuardUserResolutionTest.php`
  `testUserAttributesTheFailureToTheResolvedIdentityWhenPidHintRejectsToken`
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
  `testUserAttributesTheFailureToTheResolvedIdentityWhenDidHintCannotBeResolved`
- `tests/Feature/Guards/JwtGuardUserResolutionTest.php`
  `testUserRejectsTokenWhenDidHintNamesRevokedDevice`, `testUserRejectsTokenWhenDidHintNamesDeviceWhoseSessionHasEnded`
- `tests/Integration/Guards/SessionLifetimeIntegrationTest.php`
  `testBearerRejectsADeviceWhoseSessionHasEnded`, `testLeewayDoesNotOutliveTheAbsoluteDeadline`,
  `testAttemptCannotPinADeviceWhoseSessionHasEnded`
- `tests/Integration/Guards/JwtGuardIntegrationTest.php`
  `testRevokingDeviceBlocksRefreshAndExistingAccessToken`
- `tests/Integration/Guards/JwtGuardWriteConnectionIntegrationTest.php`
  `testBearerRejectsDeviceRevokedOnThePrimaryWhileTheReplicaLags`
- `tests/Integration/Guards/JwtGuardWriteConnectionIntegrationTest.php`
  `testBearerRejectsDeviceWhoseRevocationIsRecordedOnThePrimaryWhileTheReplicaLags`
- `tests/Integration/Guards/JwtGuardWriteConnectionIntegrationTest.php`
  `testBearerRejectsDeviceWhoseSessionEndIsRecordedOnThePrimaryWhileTheReplicaLags`,
  `testAttemptRejectsPinnedDeviceWhoseSessionEndIsRecordedOnThePrimaryWhileTheReplicaLags`
- `tests/Integration/Guards/UncastRevokedDeviceIntegrationTest.php`
  `testBearerRejectsTheRevokedDevice`, `testAttemptRejectsTheRevokedDeviceWhenPinned`
- `tests/Feature/Guards/JwtGuardUserResolutionTest.php`
  `testUserReportsDidHintNamingDeviceLoadedWithoutItsRevocation`,
  `testUserBuildsTheDevicesRelationWithReadsPinnedToTheWriteConnection`
- `tests/Integration/Guards/PartiallySelectedDeviceIntegrationTest.php`
- `tests/Integration/Guards/DeviceRelationWriteConnectionIntegrationTest.php`
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
- `tests/Integration/Guards/JwtGuardCrossConnectionTenantIntegrationTest.php`
  `testBearerRejectsMemberWhoseLandlordTenantIsDeactivatedOnItsPrimary`
- `tests/Integration/Guards/JwtGuardCrossConnectionTenantIntegrationTest.php`
  `testBearerRejectsMemberWhoseEagerLoadedLandlordTenantIsDeactivatedOnItsPrimary`
- `tests/Integration/Guards/JwtGuardWriteConnectionIntegrationTest.php`
  `testBearerRejectsIdentitySuspendedOnThePrimaryWhileTheReplicaLags`

## Change Triggers

Update this note when any of the following change:

- how `pid` and `did` are matched or coerced
- which claims each token type requires (`TokenType::requiredClaims()`)
- how a `did` is checked against the device model's key format before the lookup
- whether hinted principal resolution can short-circuit through `ResolvesHintedPrincipal`
- whether bearer `did` remains identity-scoped through `HasDevices`
- whether a revoked or ended device is still rejected on the bearer path like a missing one
- whether refresh `did` remains backed by the configured device model
- how late-path bearer failures are attributed on the `AuthenticationFailed` event
- whether the identity, principal, tenant, and device reads still go to the write connection
- how guard-local or rebound principal resolvers are propagated into refresh
