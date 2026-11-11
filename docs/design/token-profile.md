# Token Profile

## Purpose

This note records the shape of the tokens the package issues and accepts: a private profile that borrows RFC 9068's
claim names and header type, so a resource server or a sibling package reads familiar claims, without claiming RFC 9068
conformance, which needs asymmetric keys. It says which claims each token carries, how a token's type and subject type
are told apart, which claims are checked on every parse, and which the bearer path does not read.

## Invariants

- A token's type is its JOSE header `typ`, never a claim: `at+jwt` for an access token and the private `refresh+jwt`
  for a refresh token. The header is compared case-insensitively, with an optional `application/` prefix removed (RFC
  7515 section 4.1.9). A parse that expects a type requires that type's header; one that expects none requires one of
  the two. A missing header type, php-jwt's default `JWT`, an unknown one or the other type's fails the parse.
- The header is trusted only once the signature has verified: it is read through `JWT::decode()`'s header argument,
  which is filled before the signature is checked, so it is consulted only after `decode()` returns, or throws
  `ExpiredException`, which it throws only after verifying the signature, kid, algorithm and `iat`.
- Every token carries `iss`, `aud`, `client_id`, `jti`, `iat` and `exp`, each required and non-empty. `iss` and `aud`
  are the guard's, required in configuration (a guard with either unset fails closed when it is built, and
  `authentication:check` reports it) and compared strictly, so an array `aud` never matches. `client_id` is the
  application (the guard) that issued the token (see `guard-bound-tokens.md`).
- An access token also requires `sub`, `sub_type` and `principal`; a refresh token requires `sid`. `principal` and
  `sid` are commitments, never hints (see `fail-closed-pid-did.md`).
- `sub_type` is `person` or `machine` (`Jwt\Enums\SubjectType`), written from the identity's kind. A parse holds it
  to `machine` exactly when the token names an API key in `cid` (which still requires `scope` and no `sid`), and the
  bearer path checks the class of the identity it loads against the kind `cid` gives, so a human's token can never be
  read as a machine's or the other way round. A machine token's `sub` is the client: the non-human identity the API key
  belongs to.
- A session's access token carries `sid`, `auth_time` and `amr`; a token without a session carries none of them. Both
  are derived from the session's proofs when the token is issued (`Proofs\AuthenticationClaims::forSession()`, see
  `proofs-and-freshness.md`), read on the write connection, and `auth_time` is never later than `iat`. Every issuer
  takes `iat` once it holds the session's row (after its issuance guard for a refresh, a switch and a direct issue given
  no `$issuedAt`, after its lock for a step-up or reauthentication, which writes the guard before its proof), and reads
  the proofs current after its write of the row, so a proof committed before the issuer held the row is never later than
  its `iat`, and the clamp to `iat` never moves a session's `auth_time` back on a token committed before (with
  synchronised clocks). A direct issue given an `$issuedAt` keeps it as given, so the guarantee holds for it only when
  its caller took it after locking the session in its own transaction around the call. A sign-in's row is new and its
  proofs only its own; an activation issues at its operation's time, taken before its lock: no token of a pending
  session can have committed meanwhile (`Sessions\SessionActivation`). A parse holds `auth_time` to an integer not after
  `iat` plus the leeway and `amr` to a list of non-empty strings.
- A session's access token expires at the guard's access lifetime from `iat`, never past the end of the session as it
  stands after the issuer's write of the row. Its issuer is told exactly what it signed:
  `issueGuardedAccessToken()` returns a `Jwt\IssuedAccessToken` (the token, the `exp` it encoded as a time in the issue
  time's timezone, and `exp` minus `iat` in seconds), taken from the claims `accessClaims()` built, so a `TokenPair`'s
  `expiresAt` and `expiresIn` and a step-up's or reauthentication's `AccessTokenResult::$expiresAt` are the token's own
  `exp`, never a second reading of the session's deadlines that a session deriving them elsewhere could answer
  differently. No token is parsed for it, and no query is added.
- `tenant_id` is always the session's active tenant, never the principal's own when they differ: the tenant the session
  records (`tenant_id` on the row, an opaque identifier), absent for a session that acts in none, a non-empty string
  when present. Issuing a session's token refuses any other tenant, and none for a session in a tenant
  (`TokenProfile::sessionTenant()`); a token without a session acts only in the principal's own tenant, so issuing one
  refuses any other (`TokenProfile::ownTenant()`). The principal's own tenant is derived from the principal and is no
  claim.
- Past the parse, the bearer path reads `sub`, `principal`, `sid`, `iat`, `tenant_id`, `cid` and `scope`. A session's
  token must name the tenant the session records (`session_tenant_mismatch`), be the session's principal's
  (`session_principal_mismatch`), and have been issued no earlier than the session's last context change,
  `switched_at` (`session_switched`); the tenant must then still resolve and be active (`tenant_inactive`). It does
  not read `auth_time` or `amr`, and makes no query for them: they are for the token's readers, derived at issue, and
  live no longer than the access token does. On a request the package exposes neither, and a decision about how fresh
  or how strong the authentication is asks `FreshnessPolicy`. `Auth::tenant()` is the active tenant the request was
  admitted in.

## Success Path

1. A sign-in, refresh, switch, step-up or reauthentication issues an access token with the header `typ: at+jwt`, the
   guard's `iss`, `aud` and `client_id`, `sub_type: person`, the session's `sid` and the `auth_time` and `amr` its
   proofs give; a refresh token has `typ: refresh+jwt` and the session's `sid`.
2. A client credentials exchange issues an access token with `sub_type: machine`, `cid` and `scope`, and no session.
3. A request through `auth:<guard>` parses the access token (header, `client_id`, `iss`, `aud`, required claims, the
   access shape, `sub_type` against `cid`), then loads the subject and checks its kind.

## Failure / Edge Cases

- A token with a `typ` claim, `pid`, `did` or `grd` and no header type fails the parse: nothing reads those names.
- A token whose header type is the other type's, or that breaks the access shape (`sub_type` not matching `cid`,
  `auth_time` or `amr` without `sid`, a malformed `amr`, an `auth_time` after `iat` plus the leeway, an empty
  `tenant_id`), fails as `token_invalid`.
- A `person` token whose subject loads as a `MachineIdentity` is refused as `machine_identity`; a `machine` token whose
  subject is not one is refused as `credential_invalid`.
- An expired refresh token offered as proof of a previous session keeps every header and claim check; only its expiry
  is waived.
- Issuing a session token for a session with no counting first factor is a `LogicException`: no token says it
  authenticated without saying when.

## Implementation Anchors

- `src/Jwt/Enums/TokenType.php`: the header values and each type's required claims.
- `src/Jwt/Enums/Claims.php` and `src/Jwt/Enums/SubjectType.php`.
- `src/Jwt/TokenProfile.php`: `headerType()`, `accessFailure()`, `refreshFailure()`, `ownTenant()` (a token without a
  session names only the principal's own tenant), `sessionTenant()` (a session's token names only its active tenant).
- `src/Guards/BearerAuthentication.php`: `onSession()`, `contextRefusal()` (the tenant, principal and switched-at
  checks), `inActiveTenant()`.
- `src/Jwt/JwtTokenService.php`: `encode()` (the header), `issueAccessToken()`, `sessionClaims()`, `parse()`,
  `parseRefreshProof()`, `issueGuardedAccessToken()` and `accessClaims()` (the claims and the `exp` they carry).
- `src/Jwt/IssuedAccessToken.php`; `src/Jwt/SessionTokens.php`: `pair()` (a session's pair with its access token's
  expiry); `src/Sessions/ProofIssuance.php` (a step-up's or reauthentication's `expiresAt`).
- `src/Jwt/JwtTokenServiceFactory.php`: `resolveJwtRequiredString()` for `iss` and `aud`.
- `src/Jwt/MachineTokens.php`: `credential()`.
- `src/Guards/BearerAuthentication.php`: `authenticate()`, `admit()`.
- `src/Proofs/AuthenticationClaims.php`: `forSession()`.

## Authoritative Tests

- `tests/Feature/Jwt/TokenProfileTest.php`
  `testASignInsTokensKeepTheProfile`, `testATokenNeverCarriesAnAuthenticationAfterItsIssueTime`,
  `testATenantPrincipalsTokenCarriesTheTenant`, `testATokenNeverNamesATenantThePrincipalIsNotIn`,
  `testTheAccessTokenOfAGraceRetryCarriesTheTenant`, `testARequestRejectsATokenThatBreaksTheProfile`,
  `testARequestAcceptsTheMediaTypeOfTheHeaderType`, `testAnExpiredRefreshTokenOfferedAsProofKeepsItsChecks`
- `tests/Unit/Jwt/JwtTokenServiceIssueTest.php`
  `testIssueAccessTokenRefusesATenantThePrincipalIsNotIn`, `testIssuingLetsATenantThatCannotBeLoadedPropagate`
- `tests/Integration/Guards/JwtGuardWriteConnectionIntegrationTest.php`
  `testIssuanceFindsThePrincipalsTenantOnTheWriteConnection`
- `tests/Performance/AccessTokenIssueQueryBudgetTest.php`: the tenant check's read, none for a tenant loaded through the
  principal; a session's token, its issuance guard and one read of its proofs.
- `tests/Feature/Sessions/SessionStepUpTest.php` `testARefreshAndASwitchKeepTheStepUpsAuthentication`, and
  `tests/Feature/Proofs/SignInProofsTest.php` `testAnExternalSignInRecordsTheProvidersFirstFactorAndProvenance`:
  `auth_time` is the authentication's time, never the token's issue time; a refreshed token names the session's
  tenant, and a switched one the destination tenant.
- `tests/Unit/Jwt/TokenProfileTest.php`
  `testHeaderTypeNamesItsTokenType`, `testAccessFailureNamesTheRuleTheClaimsBreak`,
  `testAccessFailureAppliesTheGivenLeeway`
- `tests/Unit/Jwt/JwtTokenServiceTest.php`
  `testParseHoldsTheTokenToItsHeaderType`, `testParseRejectsATokenWithoutAHeaderType`,
  `testParseRejectsATokenInTheOldProfile`, `testParseRejectsAMisshapenAccessToken`,
  `testParseRejectsAuthenticationClaimsWithoutASession`
- `tests/Unit/Jwt/JwtTokenServiceParseTest.php`
  `testParseRejectsTokenWithMismatchedIssuer`, `testParseRejectsTokenWithMismatchedAudience`,
  `testConstructorRejectsAnEmptyIssuerOrAudience`
- `tests/Integration/Config/ShippedJwtKeyConfigTest.php`
  `testGuardRejectsShippedConfigWithoutIssuerOrAudience`
- `tests/Feature/Jwt/SessionTokensTest.php`
  `testThePairSaysWhenItsAccessTokenExpiresAsTheTokenDoes`, `testThePairsExpiryIsCappedByTheSessionsDeadlines`,
  `testTheExpiryIsTheOneTheAccessTokenWasSignedWith`; `tests/Feature/Jwt/JwtTokenServiceTest.php`
  `testAGuardedIssueWritesNothingAndRefusesAMachine`; `tests/Feature/Sessions/ProofIssuanceTest.php`
  `testTheGuardIsWrittenBeforeTheProofInTheLockingTransaction` (a step-up's `expiresAt` is its token's `exp`)

## Change Triggers

Update this note when any of the following change:

- a header type, or how the header is compared or when it is trusted
- the claims a token type requires, or the name or meaning of any claim
- how `sub_type` is decided or checked
- where `auth_time` and `amr` come from, or whether the bearer path reads them
- how a session's access token's `exp` is derived, or where the expiry its issuers report comes from
- what `tenant_id` names, how it is checked on a request, or in what order against the principal and `switched_at`
