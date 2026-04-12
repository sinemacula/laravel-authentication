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

## Success Path

- Parse the refresh JWT and extract `did`, `jti`, and optional `pid`.
- Load the configured device model and reject revoked rows before digest verification.
- Verify the plaintext `jti` against the stored digest.
- Hydrate the identity from the device's `authenticatable` relation and resolve the active principal.
- Rotate the stored digest with a single CAS update keyed on device id, old digest, and `revoked_at IS NULL`.
- Issue a fresh access token and a fresh refresh token bound to the same device and principal context.

## Failure / Edge Cases

- Missing or malformed claims produce `token_invalid`.
- Unknown device ids produce `device_unknown`.
- A digest mismatch on a token that is already stale produces `rotation_mismatch`.
- `rotation_reuse` is narrower than `rotation_mismatch`: it is reserved for the branch where the token verified
  against the in-memory digest but lost the CAS race before rotation completed.
- `rotation_reuse` revokes the device family immediately; a plain stale-token `rotation_mismatch` does not.
- Revoked devices produce `device_revoked`.
- Refresh does not rely on Eloquent observers. The raw update path deliberately bypasses them; consumers should hang
  side effects off `RefreshFailed` and `Refreshed` instead.

## Implementation Anchors

- `src/Jwt/RefreshTokenExchange.php`: `exchange()`, `extractRefreshClaims()`, `loadDeviceForRefresh()`,
  `hydrateRefreshContext()`, `completeExchange()`, `atomicallyRotateRefreshKey()`, `revokeDevice()`.
- `src/Jwt/RefreshTokenHasher.php`: digest generation and constant-time verification.
- `src/Jwt/JwtTokenService.php`: `issueRefreshToken()` and `issueAccessToken()`.
- `src/Events/Enums/RefreshFailureReason.php`: failure taxonomy.

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
  `testRevokingDeviceBlocksRefreshButNotExistingAccessToken`

## Change Triggers

Update this note when any of the following change:

- the digest algorithm or the decision to store digests rather than plaintext rotation ids
- the CAS predicate used for rotation
- the meanings of `rotation_mismatch`, `rotation_reuse`, or `device_revoked`
- whether replay revokes one device row or a broader credential family
- whether refresh still preserves `pid` across the rotated pair
