# Guard-Bound Tokens

## Purpose

This note records how a token is tied to the guard that issued it. Guards commonly share the package-wide key map and,
often, one identity model, and `iss` / `aud` are optional, so neither the signature nor those claims can tell one
guard's tokens from another's. Without a binding, a token minted for one guard authenticates on any other guard that
can verify its signature, and the `sub` is then looked up in the wrong guard's provider.

## Invariants

- Every access and refresh token carries a `grd` claim whose value is the name of the guard whose token service issued
  it. Each guard's `JwtTokenService` is built for that guard, so issuing for one guard and verifying on another uses
  two different services.
- Parsing always requires `grd` to equal the verifying service's guard, whatever token type is expected. A missing or
  different `grd` rejects the token, even when the signature verifies.
- Refresh reloads the device's owner through the refreshing guard's own identity provider, so the provider's scoping
  (tenants, soft deletes, audiences) applies on refresh exactly as it does on the bearer path.
- The reloaded identity must be the device's exact owner: an Eloquent identity of the device row's morph type with the
  device row's owner key. Anything else is rejected.

## Success Path

- `Auth::jwt('<guard>')` issues tokens with `grd = <guard>`.
- The guard named `<guard>` parses them, then resolves the identity through its provider as usual.
- On refresh it asks its provider for the owner key stored on the device row and continues with that identity.

## Failure / Edge Cases

- A token issued by another guard fails parsing: the bearer path is unauthenticated and refresh fails with
  `token_invalid`.
- A refresh whose owner the provider does not return (outside the provider's scope, deleted, or not an `Identity`)
  fails with `authenticatable_missing`, and so does one where the provider returns a different model or key.
- A device row with no owner key fails with `authenticatable_missing` without asking the provider.
- The provider is asked for the owner key the device row stores, which is the identity's primary key. Providers find
  identities by their auth identifier, which is the primary key unless the identity model overrides
  `getAuthIdentifierName()`; refresh does not work for such a model.

## Implementation Anchors

- `src/Jwt/Enums/Claims.php`: `GUARD`.
- `src/Jwt/JwtTokenService.php`: the guard constructor argument, `baseClaims()`, `firstClaimMismatch()`.
- `src/Jwt/JwtTokenServiceFactory.php`: `buildForGuard()` passes the guard name.
- `src/Jwt/RefreshTokenExchange.php`: `resolveRefreshIdentity()`.
- `src/Jwt/DeviceOwnership.php`: `ownerKey()` and `isOwner()`.
- `src/AuthenticationServiceProvider.php`: `createJwtGuard()` gives the exchange the guard's provider.

## Authoritative Tests

- `tests/Integration/Guards/GuardBoundTokenIntegrationTest.php`
  `testAccessTokenAuthenticatesOnlyOnTheIssuingGuardWithSharedKeyAndModel`
- `tests/Integration/Guards/GuardBoundTokenIntegrationTest.php`
  `testRefreshTokenRotatesOnlyOnTheIssuingGuardWithSharedKeyAndModel`
- `tests/Integration/Guards/GuardBoundTokenIntegrationTest.php`
  `testAccessTokenIsRejectedByAGuardOverAnotherModelWithTheSameKey`
- `tests/Integration/Guards/GuardBoundTokenIntegrationTest.php`
  `testRefreshRejectsAnOwnerOfAnotherModelThatSharesTheKey`
- `tests/Integration/Guards/GuardBoundTokenIntegrationTest.php`
  `testRefreshHonoursTheGuardProviderScope`
- `tests/Unit/Jwt/JwtTokenServiceTest.php`
  `testParseRejectsATokenWithoutAGuardClaim`
- `tests/Feature/Guards/JwtGuardRefreshResolutionTest.php`
  `testRefreshRejectsAProviderAnswerThatIsNotTheDeviceOwner`
- `tests/Feature/Jwt/DeviceOwnershipTest.php`
  `testIsOwnerAcceptsOnlyTheExactOwner`

## Change Triggers

Update this note when any of the following change:

- the name or value of the guard claim, or whether it is issued on every token
- whether parsing requires the guard claim regardless of token type
- how refresh loads the device's owner, or how it decides the loaded identity is that owner
