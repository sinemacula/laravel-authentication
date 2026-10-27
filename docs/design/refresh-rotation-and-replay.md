# Refresh Rotation and Replay

## Purpose

This note documents the package's refresh-token contract. Access tokens are self-verifying JWTs; refresh tokens are
stateful per-device credentials with server-side replay detection.

## Invariants

- Refresh tokens are bound to a device via `did`.
- The token carries a plaintext rotation id in `jti`; the device row stores only a SHA-256 digest of that value.
- Verification is constant-time against the stored digest.
- Every successful refresh rotates the stored digest with a compare-and-swap update before issuing the next token pair.
- Refresh reuse is handled at the device-family level. When the package detects a lost CAS race, it revokes the device
  by clearing the digest and setting `revoked_at`.
- Refresh can preserve principal continuity by carrying `pid` forward into both the rotated refresh token and the new
  access token.
- Refresh reads device state, revocation, and replay detection live on every exchange, from the write connection, so
  a lagging read replica cannot serve a stale digest or miss a revocation.

## Success Path

- Parse the refresh JWT (which must carry this guard's `grd`) and extract `did`, `jti`, and optional `pid`.
- Load the configured device model and reject revoked rows before digest verification.
- Verify the plaintext `jti` against the stored digest.
- Reload the device's owner through the guard's identity provider, confirm it is that exact owner (see
  `guard-bound-tokens.md`), and resolve the active principal.
- Rotate the stored digest with a single CAS update keyed on device id, old digest, and `revoked_at IS NULL`.
- Issue a fresh access token and a fresh refresh token bound to the same device and principal context.

## Failure / Edge Cases

- Missing or malformed claims produce `token_invalid`.
- Unknown device ids produce `device_unknown`, and so does a `did` that cannot be a key of the device model, which is
  rejected before any query.
- Database errors are not a failure reason: they propagate to the caller as server errors, so an outage is never
  reported as an unknown device.
- A digest mismatch on a token that is already stale produces `rotation_mismatch`.
- `rotation_reuse` is narrower than `rotation_mismatch`: it is reserved for the branch where the token verified against
  the in-memory digest but lost the CAS race before rotation completed.
- `rotation_reuse` revokes the device family immediately; a plain stale-token `rotation_mismatch` does not.
- Revoked devices produce `device_revoked`. Revocation is not refresh-only: the bearer path rejects an access token
  naming a revoked device as if the device were missing (see `fail-closed-pid-did.md`).
- Refresh does not rely on Eloquent observers. The raw update path deliberately bypasses them; consumers should hang
  side effects off `RefreshFailed` and `Refreshed` instead.

## Implementation Anchors

- `src/Jwt/RefreshTokenExchange.php`: `exchange()`, `extractRefreshClaims()`, `loadDeviceForRefresh()`,
  `hydrateRefreshContext()`, `completeExchange()`, `atomicallyRotateRefreshKey()`, `revokeDevice()`.
- `src/Jwt/RefreshTokenHasher.php`: digest generation and constant-time verification.
- `src/Jwt/DeviceKeyShape.php` and `src/Contracts/ValidatesDeviceKey.php`: the `did` shape check run before the device
  lookup.
- `src/Database/WriteConnection.php`: pins the device and owner reads to the write connection.
- `src/Jwt/JwtTokenService.php`: `issueRefreshToken()` and `issueAccessToken()`.
- `src/Events/Enums/RefreshFailureReason.php`: failure taxonomy.
- `src/Guards/JwtGuard.php`: `refresh()` delegates straight to the live refresh exchange.

## Authoritative Tests

- `tests/Feature/Guards/JwtGuardRefreshTest.php`
  `testRefreshReturnsNullWhenRefreshKeyDoesNotMatch`
- `tests/Feature/Guards/JwtGuardRefreshTest.php`
  `testRefreshRevokesDeviceOnRotationReuseWhenCasAffectsZeroRows`
- `tests/Feature/Guards/JwtGuardRefreshTest.php`
  `testRefreshRotatesAndIssuesNewTokenPairOnSuccess`
- `tests/Feature/Guards/JwtGuardRefreshTest.php`
  `testRefreshRejectsOldRefreshTokenAfterSuccessfulRotationWithoutRevokingDevice`
- `tests/Feature/Guards/JwtGuardRefreshTest.php`
  `testRefreshReturnsNullWhenDeviceHasBeenRevoked`
- `tests/Feature/Jwt/RefreshTokenExchangeTest.php`
  `testExchangeUsesPidHintWhenRefreshTokenCarriesPrincipalId`
- `tests/Integration/Guards/JwtGuardRefreshPrincipalContinuityIntegrationTest.php`
  `testRefreshPreservesOriginalPrincipalTenantAndTypeWhenDefaultDiffers`
- `tests/Integration/Guards/JwtGuardIntegrationTest.php`
  `testRevokingDeviceBlocksRefreshAndExistingAccessToken`
- `tests/Integration/Guards/JwtGuardResolutionFreshnessIntegrationTest.php`
  `testRefreshRejectsTokenWhenIdentityBecomesInactiveAfterIssuance`
- `tests/Integration/Guards/JwtGuardResolutionFreshnessIntegrationTest.php`
  `testRefreshRejectsTokenWhenDeviceIsDeletedAfterIssuance`
- `tests/Integration/Guards/JwtGuardWriteConnectionIntegrationTest.php`
  `testRefreshReadsDeviceAndIdentityFromTheWriteConnection`
- `tests/Feature/Jwt/RefreshTokenExchangeTest.php`
  `testExchangeRejectsMalformedDeviceIdWithoutQuerying`
- `tests/Integration/Guards/JwtGuardDatabaseFailureIntegrationTest.php`
  `testRefreshPropagatesAConnectionFailureDuringDeviceLookup`

## Change Triggers

Update this note when any of the following change:

- the digest algorithm or the decision to store digests rather than plaintext rotation ids
- the CAS predicate used for rotation
- the meanings of `rotation_mismatch`, `rotation_reuse`, `device_revoked`, or `device_unknown`
- whether database errors still propagate instead of mapping to a failure reason
- whether replay revokes one device row or a broader credential family
- whether refresh still preserves `pid` across the rotated pair
- whether refresh ever starts consulting shared cross-request caches
- whether refresh still reads the device and its owner from the write connection
