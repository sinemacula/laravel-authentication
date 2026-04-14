# Fail-Closed `pid` / `did`

## Purpose

This note records the rule that `pid` and `did` are treated as commitments, not best-effort hints. If a token claims a
specific principal or device and the runtime cannot prove that claim, authentication fails.

## Invariants

- A present `pid` must resolve to that exact principal identifier.
- A present bearer `did` must resolve to a real device owned by the resolved identity.
- Refresh is stricter than bearer auth: refresh always requires a valid `did`, because refresh is device-backed.
- Unsupported or transient identifiers stringify to `null` and therefore fail matching rather than being tolerated.
- Failure attribution should still point at the already resolved identity when `pid` or `did` rejection happens late in
  the bearer flow.
- An optional shared bearer identity cache does not relax `pid`, `did`, or active-state checks; those remain live on
  every request.

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
- On the refresh path, `did` resolution is global through the configured device model and the device's `authenticatable`
  relation.
- When bearer auth rejects a token after the identity has already been loaded, the emitted `Failed` event still carries
  that resolved identity for attribution.
- A warm bearer identity cache entry does not bypass principal re-resolution, principal activity checks, or live device
  lookup for hinted `did` values.

## Implementation Anchors

- `src/Guards/JwtGuard.php`: `resolveContextFromToken()`, `resolveDeviceFromHint()`, `resolvePrincipalFromClaims()`,
  `matchesPidHint()`, `loadIdentityFromClaims()`.
- `src/Jwt/RefreshTokenExchange.php`: `extractRefreshClaims()`, `loadDeviceForRefresh()`, `resolveRefreshPrincipal()`,
  `matchesPidHint()`.
- `src/Jwt/IdentifierCoercion.php`: `stringify()`.
- `src/Resolvers/DefaultPrincipalResolver.php`: default resolver behavior that the guard hardens with explicit pid
  matching, including the optional `ResolvesHintedPrincipal` shortcut ahead of the generic `HasPrincipals` lookup.
- `src/Contracts/ResolvesHintedPrincipal.php`: optional 3D optimization seam for hinted principal hydration.
- `src/AuthServiceProvider.php` and `src/Guards/JwtGuard.php`: resolver-rebind wiring so bearer and refresh stay on the
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

## Change Triggers

Update this note when any of the following change:

- how `pid` and `did` are matched or coerced
- whether hinted principal resolution can short-circuit through `ResolvesHintedPrincipal`
- whether bearer `did` remains identity-scoped through `HasDevices`
- whether refresh `did` remains backed by the configured device model
- how late-path bearer failures are attributed on the `Failed` event
- how guard-local or rebound principal resolvers are propagated into refresh
- whether shared caching ever expands beyond bearer identity lookups
