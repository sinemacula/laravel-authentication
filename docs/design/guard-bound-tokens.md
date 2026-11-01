# Guard-Bound Tokens

## Purpose

This note records how a token is tied to the guard that issued it. Each guard is an application, and guards commonly
share the package-wide key map, the package-wide `iss` and `aud`, and, often, one identity model, so neither the
signature nor those claims can tell one guard's tokens from another's. Without a binding, a token minted for one guard
authenticates on any other guard that can verify its signature, and the `sub` is then looked up in the wrong guard's
provider.

## Invariants

- Every access and refresh token carries a `client_id` claim (RFC 9068's name for the client the token was issued to)
  whose value is the name of the guard, the application, whose token service issued it. Each guard's
  `JwtTokenService` is built for that guard, so issuing for one guard and verifying on another uses two different
  services.
- Parsing always requires `client_id` to equal the verifying service's guard, whatever token type is expected. A
  missing or different `client_id` rejects the token, even when the signature verifies.
- Every token also carries the guard's `iss` and `aud`, which are required and checked strictly on every parse (an
  array `aud` never matches). They bind a token to the issuer and the API it was minted for; a guard may override
  either, but only `client_id` tells guards that share them apart.
- Refresh reloads the session's owner through the refreshing guard's own identity provider, so the provider's scoping
  (tenants, soft deletes, applications) applies on refresh exactly as it does on the bearer path.
- The reloaded identity must be the session's exact owner: an Eloquent identity of the session row's morph type with the
  session row's owner key. Anything else is rejected.
- The reloaded owner, not a relation cached on the session row, is what the activity checks see: it, its principal, and
  its tenant go through the same opt-in `ActivationPolicy` as on the bearer path.

## Success Path

- `Auth::jwt('<guard>')` issues tokens with `client_id = <guard>`.
- The guard named `<guard>` parses them, then resolves the identity through its provider as usual.
- On refresh it asks its provider for the owner key stored on the session row and continues with that identity.

## Failure / Edge Cases

- A token issued by another guard fails parsing: the bearer path is unauthenticated and refresh fails with
  `token_invalid`.
- A refresh whose owner the provider does not return (outside the provider's scope, deleted, or not an `Identity`)
  fails with `identity_unknown`, and so does one where the provider returns a different model or key.
- A session row with no owner key fails with `identity_unknown` without asking the provider.
- The provider is asked for the owner key the session row stores, which is the identity's primary key. Providers find
  identities by their auth identifier, which is the primary key unless the identity model overrides
  `getAuthIdentifierName()`; refresh does not work for such a model.

## Implementation Anchors

- `src/Jwt/Enums/Claims.php`: `CLIENT_ID`, `ISSUER`, `AUDIENCE`.
- `src/Jwt/JwtTokenService.php`: the guard, issuer and audience constructor arguments, `baseClaims()`,
  `firstClaimMismatch()`.
- `src/Jwt/JwtTokenServiceFactory.php`: `buildForGuard()` passes the guard name, and `resolveJwtRequiredString()` the
  issuer and audience, failing closed when either is unset.
- `src/Jwt/RefreshAdmission.php`: `owner()`.
- `src/SessionRecords/SessionOwnership.php`: `ownerKey()` and `isOwner()`.
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
  `testRefreshHonorsTheGuardProviderScope`
- `tests/Unit/Jwt/JwtTokenServiceTest.php`
  `testParseRejectsATokenWithoutAGuardClaim`, `testParseRejectsAForeignBinding`
- `tests/Feature/Jwt/JwtTokenServiceFactoryTest.php`
  `testInvalidClaimPolicyOverrideFailsClosed`, `testMissingClaimPolicyFailsClosed`
- `tests/Feature/Guards/JwtGuardRefreshResolutionTest.php`
  `testRefreshRejectsAProviderAnswerThatIsNotTheSessionOwner`
- `tests/Feature/SessionRecords/SessionOwnershipTest.php`
  `testIsOwnerAcceptsOnlyTheExactOwner`

## Change Triggers

Update this note when any of the following change:

- the name or value of the guard claim, or whether it is issued on every token
- whether `iss` and `aud` are required, and how they are compared
- whether parsing requires the guard claim regardless of token type
- how refresh loads the session's owner, or how it decides the loaded identity is that owner
