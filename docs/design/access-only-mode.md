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

## Success Path

- Leave the `devices` table out (or empty); keep the `rate_limits` table only for a guard that signs in with
  `attempt()`.
- Do not implement `HasDevices` on the identity model.
- Issue access tokens with `Auth::jwt('api')->issueAccessToken($identity, $principal, null)`.
- On the bearer path, the guard binds identity and principal normally and leaves device unset.
- Query cost stays low because the access-only bearer path only needs the identity read.

## Failure / Edge Cases

- A forged non-null `did` does not cause a best-effort downgrade. The bearer path fails closed even in a deployment that
  has no `devices` table.
- This mode is intentionally bearer-only. `JwtTokenService::issueRefreshToken()` still requires a `Device`, and the
  refresh exchange still depends on an `EloquentDevice` model plus persisted device state.
- Guard construction still validates the configured device model class. The package tolerates a missing table on this
  path because bearer auth with `did = null` never tries to query it.
- Access-token `jti` values are not consulted on the bearer path. Revocation behavior therefore comes from identity and
  principal rehydration, not from a server-side access-token store.

## Implementation Anchors

- `src/Jwt/JwtTokenService.php`: `issueAccessToken()` and `issueRefreshToken()`.
- `src/Guards/JwtGuard.php`: `resolveContextFromToken()`.
- `src/Guards/Concerns/VerifiesPinnedContext.php`: `resolveDeviceFromHint()`.
- `src/Guards/AbstractGuard.php`: `bindAuthenticationLifecycle()`.
- `src/AuthenticationServiceProvider.php`: `createJwtGuard()` and `assertValidDeviceModelConfiguration()`.

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

## Change Triggers

Update this note when any of the following change:

- the rule that access-only tokens carry `did = null`
- whether bearer auth can still succeed without `HasDevices`
- whether access-only bearer auth remains free of device writes
- whether refresh becomes supported without persisted device state
- which package tables `attempt()` or bearer auth need
- whether guard construction still validates the configured device model class up front
