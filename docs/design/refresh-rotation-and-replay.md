# Refresh Rotation and Replay

## Purpose

This note documents the package's refresh-token contract. Access tokens are self-verifying JWTs; refresh tokens are
stateful per-device credentials with server-side replay detection.

## Invariants

- Refresh tokens are bound to a device via `did`.
- The token carries a plaintext rotation id in `jti`; the device row stores only a SHA-256 digest of that value.
- Verification is constant-time against the stored digest.
- Every successful refresh issues the next token pair first and then rotates the stored digest with a compare-and-swap
  update; the pair is returned only once the update has committed. A failure while issuing (signing, randomness, an
  identifier that cannot be read) therefore happens before anything is written and leaves the presented refresh token
  valid.
- Refresh reuse is handled at the device-family level. When the package detects a lost CAS race, it revokes the device
  by clearing the digest and setting `revoked_at`.
- Refresh can preserve principal continuity by carrying `pid` forward into both the rotated refresh token and the new
  access token.
- Refresh reads device state, revocation, and replay detection live on every exchange, from the write connection, so
  a lagging read replica cannot serve a stale digest or miss a revocation. The owner, principal, and tenant behind the
  activity checks are read from the write connection too, including a tenant the owner or principal eager-loads and a
  tenant kept on another connection.
- Refresh applies the same opt-in activation checks as sign-in and bearer requests: the reloaded owner, the resolved
  principal, and the tenant it acts within must each be active when they implement `CanBeActive`.

## Success Path

- Parse the refresh JWT (which must carry this guard's `grd`) and extract `did`, `jti`, and optional `pid`.
- Load the configured device model and reject revoked rows before digest verification.
- Verify the plaintext `jti` against the stored digest.
- Reload the device's owner through the guard's identity provider, confirm it is that exact owner (see
  `guard-bound-tokens.md`) and that it is active.
- Resolve the principal (the `pid` one when the token carries it) and confirm it and its tenant are active.
- Issue a fresh access token and a fresh refresh token bound to the same device and principal context.
- Rotate the stored digest with a single CAS update keyed on device id, old digest, and `revoked_at IS NULL`, and return
  the new pair only if it affected the row.

## Failure / Edge Cases

- Missing or malformed claims produce `token_invalid`: a refresh token must carry `exp`, `iat`, `jti`, `typ`, `grd`, and
  `did` (`pid` is optional).
- Unknown device ids produce `device_unknown`, and so does a `did` that cannot be a key of the device model, which is
  rejected before any query.
- Database errors are not a failure reason: they propagate to the caller as server errors, so an outage is never
  reported as an unknown device.
- A digest mismatch on a token that is already stale produces `rotation_mismatch`.
- `rotation_reuse` is narrower than `rotation_mismatch`: it is reserved for the branch where the token verified against
  the in-memory digest but lost the CAS race before rotation completed.
- `rotation_reuse` revokes the device family immediately; a plain stale-token `rotation_mismatch` does not. The pair
  already issued for the losing request is discarded.
- An exception while issuing the new pair propagates without a `RefreshFailed` event and without touching the device
  row, so the client can retry with the same refresh token.
- That retry guarantee ends when the rotation commits. `refresh()` then binds the new context through `login()` and
  dispatches `Refreshed`, so an exception from a listener at that point (on `Login`, `Authenticated`,
  `PrincipalAssigned`, `DeviceAuthenticated`, or `Refreshed`, including the package's own last-seen update) propagates
  after the presented token has been rotated: the new pair is never returned, a retry fails with `rotation_mismatch`,
  and the client has to sign in again. Listeners on these events should not throw, or should be queued.
- An inactive owner, principal, or tenant produces `identity_inactive`, `principal_inactive`, or `tenant_inactive`. A
  principal whose tenant key names a tenant that implements `CanBeActive` but cannot be loaded (deleted or
  soft-deleted) also produces `tenant_inactive`.
- An `UnresolvableIdentityException` from the principal resolver is a misconfiguration, not a failure reason: it
  propagates as a server error without a `RefreshFailed` event, and the stored digest is left as it was.
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
- `src/Database/WriteConnection.php`: pins the device and owner reads to the write connection (the principal and tenant
  reads are pinned by the resolver and by `ActivationPolicy`).
- `src/Guards/ActivationPolicy.php`: the opt-in identity, principal, and tenant activity checks.
- `src/Jwt/JwtTokenService.php`: `issueRefreshToken()` and `issueAccessToken()`.
- `src/Events/Enums/RefreshFailureReason.php`: failure taxonomy.
- `src/Guards/JwtGuard.php`: `refresh()` delegates straight to the live refresh exchange.

## Authoritative Tests

- `tests/Feature/Guards/JwtGuardRefreshTest.php`
  `testRefreshReturnsNullWhenRefreshKeyDoesNotMatch`
- `tests/Feature/Guards/JwtGuardRefreshTest.php`
  `testRefreshRevokesDeviceOnRotationReuseWhenCasAffectsZeroRows`
- `tests/Feature/Guards/JwtGuardRefreshResolutionTest.php`
  `testRefreshRotatesAndIssuesNewTokenPairOnSuccess`
- `tests/Feature/Guards/JwtGuardRefreshTest.php`
  `testRefreshRejectsOldRefreshTokenAfterSuccessfulRotationWithoutRevokingDevice`
- `tests/Feature/Guards/JwtGuardRefreshTest.php`
  `testRefreshReturnsNullWhenDeviceHasBeenRevoked`
- `tests/Integration/Guards/UncastRevokedDeviceIntegrationTest.php`
  `testRefreshRejectsTheRevokedDeviceWithDeviceRevokedReason`
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
- `tests/Feature/Jwt/RefreshTokenExchangeTest.php`
  `testExchangeLeavesTheRefreshTokenValidWhenIssuingFails`
- `tests/Integration/Guards/JwtGuardDatabaseFailureIntegrationTest.php`
  `testRefreshPropagatesAConnectionFailureDuringDeviceLookup`
- `tests/Integration/Guards/TenantActivityIntegrationTest.php`
  `testRefreshRejectsMemberOfInactiveTenantWithTenantInactiveReason`
- `tests/Integration/Guards/TenantActivityIntegrationTest.php`
  `testRefreshRejectsMemberOfSoftDeletedTenantWithTenantInactiveReason`
- `tests/Feature/Jwt/RefreshTokenExchangeTest.php`
  `testExchangePropagatesUnresolvableIdentityException`

## Change Triggers

Update this note when any of the following change:

- the digest algorithm or the decision to store digests rather than plaintext rotation ids
- the CAS predicate used for rotation
- whether the new pair is still issued before the CAS commits
- the meanings of `rotation_mismatch`, `rotation_reuse`, `device_revoked`, or `device_unknown`
- whether database errors still propagate instead of mapping to a failure reason
- whether replay revokes one device row or a broader credential family
- whether refresh still preserves `pid` across the rotated pair
- whether refresh ever starts consulting shared cross-request caches
- whether refresh still reads the device and its owner from the write connection
- which activity checks refresh applies, or whether an `UnresolvableIdentityException` still propagates
