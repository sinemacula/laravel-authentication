# Access-Only Mode

## Purpose

This note describes the supported bearer-only operating mode for applications that want contextual identity and
principal auth without device tracking or refresh rotation.

## Invariants

- The package can boot and authenticate bearer requests without a `devices` table.
- Access tokens for this mode must be issued with `device = null`, which means the JWT carries `did = null`.
- The identity model does not need to implement `HasDevices`.
- Bearer auth still rehydrates the identity through the configured provider and resolves the principal through the
  configured resolver.
- `Auth::device()` remains `null`, `DeviceAuthenticated` is not emitted, and last-seen persistence does not run.

## Success Path

- Skip the package devices migration.
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
- `src/Guards/JwtGuard.php`: `resolveDeviceFromHint()` and `resolveContextFromToken()`.
- `src/Guards/AbstractGuard.php`: `bindAuthenticationLifecycle()`.
- `src/AuthServiceProvider.php`: `createJwtGuard()` and `assertValidDeviceModelConfiguration()`.

## Authoritative Tests

- `tests/Integration/Guards/AccessOnlyIntegrationTest.php`
  `testPackageBootsWithoutDevicesTable`
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
- whether guard construction still validates the configured device model class up front
