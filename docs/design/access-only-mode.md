# Access-Only Mode

## Purpose

This note describes the supported bearer-only operating mode for applications that want contextual identity and
principal auth without device tracking or refresh rotation.

## Invariants

- The package can boot and authenticate bearer requests without a `devices` table, or any of the package's tables.
- `attempt()` counts its attempts in the `rate_limits` table, unless the guard turns its sign-in limits off
  (`rate_limits.sign_in = null`): a deployment that signs in with `attempt()` keeps that table, and the `devices` and
  `pending_sign_ins` tables stay empty.
- Access tokens for this mode must be issued with `device = null`, which means the JWT carries `did = null`. `did` is
  the one access-token claim that may be absent or null, apart from the optional `pty` (the principal's type); `sub`,
  `pid`, `exp`, `iat`, `jti`, `typ`, and `grd` are required as on every access token. With no session to bound it,
  such a token lives exactly the guard's `access_ttl_minutes`.
- The identity model does not need to implement `HasDevices`.
- Bearer auth still rehydrates the identity through the configured provider and resolves the principal through the
  configured resolver.
- `Auth::device()` remains `null`, `DeviceAuthenticated` is not emitted, and last-use persistence does not run.
- A device-less token has no device to revoke, so an identity or principal that implements `HasTokensValidAfter` ends
  them instead: the bearer path rejects a token whose `iat` is at or before either one's time
  (`issued_before_cutoff`), read from the models it already loaded, with no extra query. Whole seconds: a token issued
  in the cutoff's own second is rejected too, so a flow that moves the time and then issues a token waits for the
  next second or issues a device session. Tokens that name a device are never held to it; revoking the device ends
  them.

## Success Path

- Leave the `devices` table out (or empty); keep the `rate_limits` table only for a guard that signs in with
  `attempt()`.
- Do not implement `HasDevices` on the identity model.
- Issue access tokens with `Auth::jwt('api')->issueAccessToken($identity, $principal, null)`.
- On the bearer path, the guard binds identity and principal normally and leaves device unset.
- Query cost stays low because the access-only bearer path only needs the identity read, a recorded "tokens valid
  after" time included.

## Failure / Edge Cases

- A forged non-null `did` does not cause a best-effort downgrade. The bearer path fails closed even in a deployment that
  has no `devices` table.
- This mode is intentionally bearer-only. `JwtTokenService::issueRefreshToken()` still requires a `Device`, and the
  refresh exchange still depends on an `EloquentDevice` model plus persisted device state. The session service refuses
  to start a session (`signIn()`, `start()`) for an identity without `HasDevices` with a `LogicException`: every session
  it starts lives on a device, and the access token it would issue names one this identity can never resolve.
- Its revocation methods work, and are how device-less tokens end early: for an identity without `HasDevices`, or a
  principal whose owner is one, a bulk revocation (`revokeDevices()`, `signOutEverywhere()`, the security-change
  methods, `principalDeactivated()`, `revokePrincipalDevices()`) only moves the scope's "tokens valid after" cutoff and
  reports it; it reads no `devices` row and deletes no `pending_sign_ins` row, since no session of such an identity can
  hold either, so neither table needs to exist.
- Guard construction still validates the configured device model: its class, and that it lives on the storage
  connection. The package tolerates a missing table on this path because bearer auth with `did = null` never tries to
  query it.
- Access-token `jti` values are not consulted on the bearer path. Revocation behavior therefore comes from identity and
  principal rehydration, not from a server-side access-token store.

## Implementation Anchors

- `src/Jwt/JwtTokenService.php`: `issueAccessToken()` and `issueRefreshToken()`.
- `src/Guards/JwtGuard.php`: `resolveBearerToken()`; `src/Guards/BearerAuthentication.php`: `isIssuedAfterCutoff()`.
- `src/Sessions/IdentityDevices.php`: `find()`, which finds no device for an identity without `HasDevices`.
- `src/Sessions/RevocationScope.php`: `identity()`, `principal()`, which leave the package's tables alone for an
  identity without `HasDevices`, but for the `identifier_changes` rows an identity's scope cancels when the identity
  implements `HasChangeableIdentifiers` (so such an identity needs that migration).
- `src/Guards/AbstractGuard.php`: `bindAuthenticationLifecycle()`.
- `src/AuthenticationServiceProvider.php`: `createJwtGuard()`; `src/Jwt/DeviceLookup.php`: `model()`;
  `src/Exceptions/InvalidDeviceModelConfigurationException.php`: `validate()`, `offStorage()`.

## Authoritative Tests

- `tests/Integration/Guards/AccessOnlyIntegrationTest.php`
  `testAccessTokenFlowSucceedsWithoutDevice`
- `tests/Integration/Guards/AccessOnlyIntegrationTest.php`
  `testForgedDeviceHintFailsClosedWithoutDevicesTable`
- `tests/Unit/Jwt/JwtTokenServiceIssueTest.php`
  `testIssueAccessTokenWithoutDeviceSetsNullDeviceClaim`
- `tests/Feature/Guards/JwtGuardUserResolutionTest.php`
  `testUserSkipsDeviceWhenNoDidClaimPresent`
- `tests/Performance/JwtGuardQueryBudgetTest.php`
  `testAccessOnlyBearerPathUsesSingleReadAndNoWrites`
- `tests/Integration/Guards/TokensValidAfterIntegrationTest.php`
  `testATimeEndsTheDevicelessTokensIssuedUpToItsSecond`, `testADevicesTokenIsNotHeldToTheTime`
- `tests/Feature/Guards/BearerAuthenticationTest.php`
  `testTheIdentitysTimeLimitsADevicelessToken`, `testThePrincipalsTimeLimitsADevicelessToken`,
  `testThePrincipalsTimeLimitsATokenWhoseIdentityRecordsNone`
- `tests/Integration/Guards/TokensValidAfterIntegrationTest.php`
  `testThePrincipalsTimeLimitsATokenWhoseIdentityRecordsNone`
- `tests/Integration/Sessions/RevocationScopeTest.php`
  `testAnAccessOnlyIdentitysRevocationsOnlyMoveItsCutoff`, `testAPrincipalOfAnAccessOnlyIdentityOnlyMovesItsCutoff`
- `tests/Performance/TokensValidAfterQueryBudgetTest.php`
  `testAnAcceptedTokenCostsOneRead`, `testARejectedTokenCostsOneRead`

## Change Triggers

Update this note when any of the following change:

- the rule that access-only tokens carry `did = null`
- whether bearer auth can still succeed without `HasDevices`
- whether access-only bearer auth remains free of device writes
- whether refresh becomes supported without persisted device state
- which package tables `attempt()` or bearer auth need
- how a "tokens valid after" time limits device-less tokens
- whether guard construction still validates the configured device model class up front
