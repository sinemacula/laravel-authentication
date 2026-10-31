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
  that found nothing (`sessions()->pending()`, `choice()`, `apiKeys()->find()`, `identifierChanges()->pending()`),
  `apiKeys()->rotate()` when the principal has no rotatable key by that id (unknown, revoked, expired or already
  rotated, so nothing changed), or a call that reads a credential from the request when the request carries none
  (`switchPrincipalFromRequest()`), in which case nothing was dispatched.
- **A result object when success carries a payload or the flow can be throttled.** It is `final readonly`, made only
  through named constructors (one per outcome), and says which outcome it is through `is<Outcome>()` predicates. The
  payload is in nullable public properties, set only for the outcome that has it. A refusal is named by `status` or by
  `reason` (`?FailureReason`, the reason the flow reports, concealed where the flow conceals it), and a flow that can be
  throttled carries `retryAfter` (`?int`). A result with more than two outcomes exposes `status`, a string-backed enum
  naming every outcome, success included. `SignInResult`, `SwitchResult`, `CodeRequest`, `ResetResult`,
  `PasswordResult`, `IdentifierChangeRequest`, `PasskeyRegistration` and `PasskeyFactorResult` take this shape.
- **An outcome enum when success carries nothing and the flow cannot be throttled.** It is string-backed and names its
  success case (`IdentifierChangeOutcome::CHANGED`, `VerificationOutcome::VERIFIED`,
  `VerificationLinkOutcome::VERIFIED`), so matching on the enum, not on a type, tells success from refusal.
- **`bool` only for "did this call change something"** on an idempotent operation (`discard()`, `signOut()`,
  `revokeDevice()`, `apiKeys()->revoke()`, `passkeys()->remove()`, `identifierChanges()->cancel()`), and `int` for how
  many it changed (`signOutEverywhere()`, `revokeDevices()`, the security-change methods). `false` and `0` are not
  refusals: the thing was already as asked.
- **No union of a success type with a failure type** in a return, and no enum of another seam's outcomes mixed with a
  failure reason: one type answers every outcome.
- **Throttling is an outcome.** A throttled operation returns `rate_limited`, as its status or its reason, with
  `retryAfter`, after the events that report it.
- **Laravel adapters keep Laravel's types.** `attempt()`, `validate()`, `check()`, `user()` and `logout()` answer
  `bool`, a nullable or nothing, and report details through `Failed` and `AuthenticationFailed`. A sign-in that may need
  a further factor or a choice of principal goes through the session service.

## Success Path

- Success is a named outcome: `isSignedIn()`, `isSwitched()`, `isSent()`, `isReset()`, `isSet()`, `isGranted()`,
  `isRegistered()`, `isVerified()`, or the enum's success case. Its payload (the session, the passkey's summary, the
  code's expiry) is read only once the predicate or the case says it is there.
- `passkeys()->verifyFactor()` answers a `PasskeyFactorResult`: verified with the passkey's summary as its use left it,
  or failed with the reason (not concealed: the caller already holds the identity).
- `passkeys()->register()` answers a `PasskeyRegistration`: `registered` with the passkey's summary, or
  `challenge_invalid`, `response_invalid` or `already_registered`.
- `codes()->verify()` answers a `VerificationOutcome`: `verified`, `already_verified` or `mismatch` as the
  `IdentifierVerifier` answered an accepted code, or `invalid`, `expired` or `exhausted` for a code that was not.
  `AuthenticationFailed` still carries the `FailureReason` (`invalid_credentials`, `code_expired`, `code_exhausted`).
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
- Not yet in the shape: the guard's `refresh()` (`?RefreshResult`, `null` for any refusal) and `refreshFromRequest()`
  (`FailureReason|RefreshResult|null`), which both throw `ThrottleRequestsException` for `rate_limited` after the
  events.
- `Verification\Enums\IdentifierVerification` stays the `IdentifierVerifier` seam's own answer (`verified`,
  `already_verified`, `mismatch`): a verifier knows nothing of codes or links, so `codes()->verify()` and
  `VerificationLinks::consume()` each map it into their own enum. The two enums stay apart, as the convention asks a
  shape and not a shared type: a link has no attempts to exhaust.
- Laravel's `signed` middleware, when the application puts it on the verification route, answers an expired or tampered
  link with its own 403 (`InvalidSignatureException`) before `consume()` runs, so that route never answers `expired` and
  no `AuthenticationFailed` is reported. `consume()` checks the signature itself, so the route needs no middleware.
- A caller that checked an old shape can change behaviour silently, not fail to compile: a `null`, `!== null` or
  truthiness check on `verifyFactor()` (whose `null` meant verified) or on `VerificationLinks::consume()` (whose `null`
  meant a refused link) is now always given a value, refusals included, and a check that `register()` answered a
  `PasskeySummary`, or that `codes()->verify()` or `consume()` answered an `IdentifierVerification`, is now never true.
  The guides show each migration.

## Implementation Anchors

- `src/Sessions/SignInResult.php`, `src/Sessions/SwitchResult.php`, `src/Codes/CodeRequest.php`,
  `src/Passwords/ResetResult.php`, `src/Passwords/PasswordResult.php`,
  `src/IdentifierChanges/IdentifierChangeRequest.php`, `src/ClientCredentials/ClientCredentialsResult.php`.
- `src/Passkeys/PasskeyRegistration.php`, `src/Passkeys/Enums/PasskeyRegistrationStatus.php`,
  `src/Passkeys/PasskeyFactorResult.php`, `src/Passkeys/PasskeyService.php` (`register()`, `verifyFactor()`,
  `signInOptions()`).
- `src/Codes/Enums/VerificationOutcome.php`, `src/Codes/CodeService.php` (`verify()`),
  `src/IdentifierChanges/Enums/IdentifierChangeOutcome.php`.
- `src/Verification/Enums/VerificationLinkOutcome.php`, `src/Verification/VerificationLinks.php` (`consume()`).

## Authoritative Tests

- `tests/Unit/Passkeys/PasskeyRegistrationTest.php`, `tests/Unit/Passkeys/PasskeyFactorResultTest.php`,
  `tests/Unit/Passkeys/EnumsTest.php`, `tests/Unit/Codes/VerificationOutcomeTest.php`,
  `tests/Unit/Verification/VerificationLinkOutcomeTest.php`.
- `tests/Feature/Passkeys/PasskeyServiceTest.php`, `tests/Feature/Codes/CodeServiceTest.php`,
  `tests/Feature/Verification/VerificationLinksTest.php` (every outcome of `register()`, `verifyFactor()`,
  `codes()->verify()` and `consume()`).
- `tests/Integration/Passkeys/PasskeyOutcomesTest.php`, `tests/Integration/Codes/CodeVerificationOutcomesTest.php`,
  `tests/Integration/Verification/VerificationLinkOutcomesTest.php` (what each outcome wrote, on every engine).
- `tests/Unit/Sessions/SignInResultTest.php`, `tests/Unit/Sessions/SwitchResultTest.php`,
  `tests/Unit/Codes/CodeRequestTest.php`.

## Change Triggers

- A new public operation on a package service, or a change to what one returns.
- A new outcome of an existing operation, or a refusal that becomes or stops being an exception.
- A new exception to the shape, or one of the named exceptions brought into it.
