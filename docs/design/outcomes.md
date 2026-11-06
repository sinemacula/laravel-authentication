# Outcomes and Throttling

## Purpose

This note records how the package's own APIs (the session, code, passkey, password, identifier change, API key and
client credentials services, and the verification links) answer: which outcomes are values, what `null` and `bool` may
mean, what shape a result takes, and how throttling is answered. It is a default with named exceptions, not one result
type: each flow keeps its own type, and the convention is the shape. Laravel's guard methods keep Laravel's types.

## Invariants

- **Expected refusals are values.** An expected refusal is a refusal of untrusted authentication input (a wrong
  password, code, token or passkey, a malformed credential) or of policy (a method or principal the guard does not
  admit, an inactive identity, throttling). It is returned, never thrown. Exceptions mean a misconfiguration or an
  invalid argument from application code (`InvalidArgumentException`, `LogicException`, such as a machine identity given
  to a passkey ceremony or an unknown sign-in method) or a server error, which propagates.
- **`null` never means success and never means a refusal.** A nullable return means there is nothing to act on: a lookup
  that found nothing (`sessions()->pending()`, `apiKeys()->find()`, `identifierChanges()->pending()`),
  `apiKeys()->rotate()` when the principal has no rotatable key by that id (unknown, revoked, expired or already
  rotated, so nothing changed), or a call handed `null` for a credential the request did not carry (`refresh()` and
  `switchTo()`), in which case nothing was dispatched.
- **A result object when success carries a payload or the flow can be throttled.** It is `final readonly`, made only
  through named constructors (one per outcome), and says which outcome it is through `is<Outcome>()` predicates. The
  payload is in nullable public properties, set only for the outcome that has it. A refusal is named by `status` or by
  `reason` (`?FailureReason`, the reason the flow reports, concealed where the flow conceals it), and a flow that can be
  throttled carries `retryAfter` (`?int`). A result with more than two outcomes exposes `status`, a string-backed enum
  naming every outcome, success included. `SignInResult`, `RefreshResult`, `SwitchResult`, `CodeRequest`, `ResetResult`,
  `PasswordResult`, `IdentifierChangeRequest`, `PasskeyRegistration`, `PasskeyRemoval`, `PasskeyFactorResult` and
  `FactorChangeResult` take this shape. A flow whose outcomes an enum already names and that came to be throttled (a
  check of a verification code, a confirmation of a change of identifier) answers a result carrying that enum as
  `outcome` with `retryAfter` (`LimitedOutcome`, generic over the enum, with `is()`; and `FactorCodeCheck` for a factor
  code), so the enum stays the one place its outcomes are named.
- **An outcome enum when success carries nothing and the flow cannot be throttled.** It is string-backed and names its
  success case (`VerificationLinkOutcome::VERIFIED`), so matching on the enum, not on a type, tells success from
  refusal.
- **`bool` only for "did this call change something"** on an idempotent operation (`discard()`, `signOut()`,
  `revokeSession()`, `apiKeys()->revoke()`, `identifierChanges()->cancel()`), and `int` for how many it changed
  (`signOutEverywhere()`, `revokeSessions()`, the security-change methods). `false` and `0` are not refusals: the thing
  was already as asked.
- **No union of a success type with a failure type** in a return, and no enum of another seam's outcomes mixed with a
  failure reason: one type answers every outcome.
- **Throttling is an outcome.** A throttled operation returns `rate_limited`, as its status or its reason, with
  `retryAfter`, after the events that report it.
- **Laravel adapters keep Laravel's types.** `attempt()`, `validate()`, `check()`, `user()` and `logout()` answer
  `bool`, a nullable or nothing, and report details through `Failed` and `AuthenticationFailed`. A sign-in that may need
  a further factor or a choice of principal goes through the session service.

## Success Path

- Success is a named outcome: `isSignedIn()`, `isRefreshed()`, `isSwitched()`, `isSent()`, `isReset()`, `isSet()`,
  `isGranted()`, `isRegistered()`, `isVerified()`, or the enum's success case. Its payload (the session, the passkey's
  summary, the code's expiry) is read only once the predicate or the case says it is there.
- `sessions()->refresh()` answers a `RefreshResult`: refreshed on the same session, with its rotated `TokenPair`, or
  failed with the exchange's or the transport's reason, `rate_limited` with `retryAfter`, or `session_mismatch` for a
  token proving a session other than the `$expectedSession` given; one with a presented token says where its token came
  from (`source`). `switchTo()` and `signOutWith()` refuse the same way.
- Every `TokenPair` (a sign-in's, a pending session's once it activates, a refresh's and its grace retry's, a switch's)
  says when its access token expires, as the token itself does: `expiresAt`, the signed `exp`, and `expiresIn`, `exp`
  minus `iat` in seconds and at least one, the `expires_in` of an RFC 6749 section 5.1 response, so a caller answers a
  token response without decoding the token. Both come from the claims the token was signed with
  (`Jwt\SessionTokens::pair()`, see `token-profile.md`), never from a second reading of the session's deadlines, and a
  cookie application's pair keeps them. A step-up's or reauthentication's `AccessTokenResult::$expiresAt` is that same
  signed `exp`.
- `passkeys()->verifyFactor()` answers a `PasskeyFactorResult`: verified with a `PasskeyFactorAssertion` (the passkey,
  its observed properties and its summary as its use left it), or failed with the reason (not concealed: the caller
  already holds the identity).
- `codes()->verifyFactorCode()` answers a `FactorCodeCheck` whose `outcome`, a `FactorCodeOutcome`, is `verified`,
  `invalid` (a malformed or wrong code; only a wrong one counts), `not_found` (a malformed, unknown, replaced or
  other-binding challenge), `used` (the binding's own challenge, used up), `expired`, `exhausted`, `locked`, `refused`
  or `rate_limited`. Neither `not_found` nor `used` counts an attempt, and both report `invalid_credentials`.
- `passkeys()->register()` answers a `PasskeyRegistration`: `registered` with the passkey's summary and the factor
  gate's association, if any, or `challenge_invalid`, `challenge_expired`, `challenge_used`, `response_invalid` or
  `already_registered`; given a pending sign-in's credential, also `pending_invalid` (the credential proves no live
  pending session of this identity on this guard, or none the challenge was bound to, without saying which check
  failed) or `cross_site_request` (a cookie application's client from outside its own site, answered before the
  pending session is read). The association may carry the factor package's completion of the registration
  (`completion`, an opaque `?object`).
- `passkeys()->remove()` answers a `PasskeyRemoval`: removed by this call (`isRemoved()`), with the factor gate's
  completion of the removal, if any (an opaque `?object`, such as the factor package's own result carrying a new
  pending credential), or not removed, with none: it would be a `bool`, but its success carries a payload.
- `sessions()->factorChanged()` answers a `FactorChangeResult` whose `status` (`FactorChangeStatus`) is `active`,
  `pending` (with the pending session and its credential), `revoked` or `skipped` (this call neither kept, returned nor
  revoked the session, which says nothing of whether it is usable).
- `codes()->verify()` answers a `LimitedOutcome` whose `outcome`, a `VerificationOutcome`, is `verified`,
  `already_verified` or `mismatch` as the `IdentifierVerifier` answered an accepted code, `invalid`, `expired` or
  `exhausted` for a code that was not, or `rate_limited` with `retryAfter`. `AuthenticationFailed` still carries the
  `FailureReason` (`invalid_credentials`, `code_expired`, `code_exhausted`, `rate_limited`).
  `identifierChanges()->confirmByCode()` and `confirmByLink()` answer a `LimitedOutcome` of an `IdentifierChangeOutcome`
  the same way.
- `VerificationLinks::consume()` answers a `VerificationLinkOutcome`: `verified`, `already_verified` or `mismatch` as
  the `IdentifierVerifier` answered an accepted link, or `invalid` or `expired` for a link that was not, reported by
  `AuthenticationFailed` as `invalid_credentials` or `link_expired` on the `identifier_verification` flow. The link's
  fields and purpose, then its signature, then its expiry are checked before any identity is read, so a tampered link
  is `invalid` even once expired, and an authentic expired one `expired` whatever became of its identity. Every refusal
  after that (no JWT guard, no identity that can verify identifiers, no identifier, or one the link's digest no longer
  matches) is `invalid`, never `mismatch`, so the answer says nothing about the account: `mismatch` stays the verifier's
  own answer, for an identifier that changed while it was being verified.

## Failure / Edge Cases

- Named exceptions to the shape, kept deliberately:
  - `ClientCredentialsResult` stays RFC 6749-shaped: its `error` is the protocol's error code and its response the
    protocol's body, so it answers a token endpoint as written; `reason` is the server-side event's alone.
  - `PasswordResult` and `ResetResult` carry the password policy's structured `violations`, not a `FailureReason`: a
    refused password is answered rule by rule. A refused reset otherwise says `invalid` without saying why.
  - `passkeys()->signInOptions()` throws Laravel's `ThrottleRequestsException` (429 with `Retry-After`) once the
    client's IP address has used up its `passkey_options` limit. Throttling there is still an expected refusal,
    delivered as Laravel's own throttle exception, as the `throttle` middleware would: it answers an anonymous ceremony
    request before any authentication, throttling is its only refusal, and a result would make every caller unwrap the
    options only to throw the same 429.
- Refresh goes through the session service and returns every refusal, `rate_limited` included.
- `Verification\Enums\IdentifierVerification` stays the `IdentifierVerifier` seam's own answer (`verified`,
  `already_verified`, `mismatch`): a verifier knows nothing of codes or links, so `codes()->verify()` and
  `VerificationLinks::consume()` each map it into their own enum. The two enums stay apart, as the convention asks a
  shape and not a shared type: a link has no attempts to exhaust.
- Laravel's `signed` middleware, when the application puts it on the verification route, answers an expired or tampered
  link with its own 403 (`InvalidSignatureException`) before `consume()` runs, so that route never answers `expired` and
  no `AuthenticationFailed` is reported. `consume()` checks the signature and expiry itself, with every key and previous
  key, from the `SignedLink` that `SignedLink::fromRequest()` captured (the address and the raw query string as
  received), so the route needs no middleware.

## Implementation Anchors

- `src/Sessions/SignInResult.php`, `src/Sessions/RefreshResult.php`, `src/Sessions/SwitchResult.php`,
  `src/Codes/CodeRequest.php`, `src/Passwords/ResetResult.php`, `src/Passwords/PasswordResult.php`,
  `src/IdentifierChanges/IdentifierChangeRequest.php`, `src/ClientCredentials/ClientCredentialsResult.php`.
- `src/Sessions/FactorChangeResult.php`, `src/Sessions/Enums/FactorChangeStatus.php`.
- `src/Passkeys/PasskeyRegistration.php`, `src/Passkeys/PasskeyRemoval.php`,
  `src/Passkeys/Enums/PasskeyRegistrationStatus.php`, `src/Passkeys/PasskeyFactorResult.php`,
  `src/Passkeys/PasskeyService.php` (`register()`, `verifyFactor()`, `signInOptions()`).
- `src/Sessions/SessionRefresh.php` (every refusal returned, `rate_limited` with its wait), `src/Jwt/TokenPair.php`
  (the access token's `expiresAt` and `expiresIn`), `src/Jwt/SessionTokens.php` (`pair()`, every session's pair).
- `src/RateLimiting/LimitedOutcome.php`, `src/Codes/Enums/VerificationOutcome.php`, `src/Codes/CodeService.php`
  (`verify()`),
  `src/IdentifierChanges/Enums/IdentifierChangeOutcome.php`.
- `src/Verification/Enums/VerificationLinkOutcome.php`, `src/Verification/VerificationLinks.php` (`consume()`),
  `src/Http/SignedLink.php`.

## Authoritative Tests

- `tests/Unit/Sessions/FactorChangeResultTest.php`, `tests/Unit/Passkeys/PasskeyRemovalTest.php`.
- `tests/Unit/Passkeys/PasskeyRegistrationTest.php`, `tests/Unit/Passkeys/PasskeyFactorResultTest.php`,
  `tests/Unit/Passkeys/EnumsTest.php`, `tests/Unit/Codes/VerificationOutcomeTest.php`,
  `tests/Unit/Verification/VerificationLinkOutcomeTest.php`.
- `tests/Feature/Passkeys/PasskeyServiceTest.php`, `tests/Feature/Codes/CodeServiceTest.php`,
  `tests/Feature/Verification/VerificationLinksTest.php` (every outcome of `register()`, `verifyFactor()`,
  `codes()->verify()` and `consume()`).
- `tests/Integration/Passkeys/PasskeyOutcomesTest.php`, `tests/Integration/Codes/CodeVerificationOutcomesTest.php`,
  `tests/Integration/Verification/VerificationLinkOutcomesTest.php` (what each outcome wrote, on every engine).
- `tests/Unit/Sessions/SignInResultTest.php`, `tests/Unit/Sessions/RefreshResultTest.php`,
  `tests/Unit/Sessions/SwitchResultTest.php`, `tests/Unit/Codes/CodeRequestTest.php`.
- `tests/Unit/Jwt/TokenPairTest.php`, `tests/Feature/Jwt/SessionTokensTest.php` and
  `tests/Feature/Jwt/TokenPairTest.php` (every pair's `expiresAt` is its access token's `exp` and `expiresIn` its `exp`
  minus `iat`, through `Auth::sessions()` for a sign-in, a cookie sign-in, an activation, a choice, a refresh and its
  grace retry, and a switch).
- `tests/Feature/Sessions/SessionRefreshTest.php` (each refusal's reason, `rate_limited` with its wait and nothing
  thrown, the source of a refresh read from the request).

## Change Triggers

- A new public operation on a package service, or a change to what one returns.
- A new outcome of an existing operation, or a refusal that becomes or stops being an exception.
- A new exception to the shape, or one of the named exceptions brought into it.
