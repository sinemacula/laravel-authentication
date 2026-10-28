# One-Time Codes

## Purpose

This note records how the package issues, delivers and checks one-time codes: the `phone_code` and `email_code` sign-in
methods (a numeric code sent to a verified phone number or email address) and identifier verification by code. It states
what a code is bound to, what is stored, how the attempt, cooldown and request limits hold under concurrency, why a
request for a code looks the same whether or not anyone has the identifier, and who a code is ever delivered to.

## Invariants

- A code is bound to a purpose (`sign_in` or `verify_identifier`), a guard, an identifier type and the identifier in its
  normal form, and, for a verification, the identity (`AccountAttempts::account()`). One live code exists per binding:
  its row is keyed by `HMAC-SHA256(key', "binding\0purpose\0guard\0type\0identifier\0identity")`.
- The code is `length` digits from `random_int()`, zero-padded, stored only as `HMAC-SHA256(key'', "code\0binding
  digest\0issue id\0code")`, compared with `hash_equals()`. `key'` and `key''` are separate derivations of
  `authentication.codes.key` (at least 32 bytes) or, when it is not set, of `app.key`. The table holds no code and no
  identifier; `OneTimeCode::toArray()` hides the binding digest, the issuance and the hash.
- Every issuance has a random `issue_id`. Every attempt, use and delivery is conditional on the `issue_id` the caller
  read, so a check or a delivery job for an issuance a resend replaced never touches the replacement, even when the
  resend drew the same digits.
- Issuing replaces the binding's code only when it was issued at least `resend_cooldown_seconds` ago (one conditional
  `UPDATE`), and otherwise creates it with `insertOrIgnore` against the primary key; neither writing means a code was
  issued within the cooldown, and the answer is the seconds left (at least 1). No unique violation is ever caught, so a
  PostgreSQL transaction around a request is never aborted.
- A check reads the row on the write connection. No row or a used code is `invalid`; an expired code (`expires_at <=
  now`) is `expired`; one with `attempts >= max_attempts` is `exhausted`; none of these counts. Otherwise the attempt is
  counted before anything is compared, by `UPDATE ... SET attempts = attempts + 1 WHERE id AND issue_id AND consumed_at
  IS NULL AND expires_at > now AND attempts < max`. A check whose increment matched no row never compares: it answers
  from a fresh read (`expired` or `exhausted` when that issuance now is, otherwise `invalid`). A matching code is
  accepted only when `UPDATE ... SET consumed_at = now WHERE id AND issue_id AND consumed_at IS NULL` changed the row,
  so of two correct submissions exactly one is accepted.
- Every time is a whole second; one `now` per operation; a deadline has passed from the second it names.
- Every read that decides a code, its recipient or a verification is on the write connection.
- A request for a sign-in code does no identity-dependent work: the method must be allowed, the identifier must be one
  its type's normaliser accepts, the `code_request` limits (per identifier, in normal form, and per IP address) must have
  room, taken on every request and never given back, and the cooldown must have passed. A code is then issued for any
  identifier and its delivery queued, so the result, the statements and the time are the same for an identifier no one
  has.
- Delivery is the `SendOneTimeCode` job (`ShouldQueue`, `ShouldBeEncrypted`), dispatched through `AfterCommit` on the
  code row's connection, so only a committed code is delivered and a rolled-back one never is. It is never inline: on a
  connection whose driver is `sync` it is dispatched with `dispatchAfterResponse()`, which runs in the application's
  terminating callbacks; `authentication:check` warns about that setting. The job sets `beforeCommit()`, since the
  package has already waited for its own row's commit.
- The job first checks, on the write connection, that its issuance is still the binding's live, unused, unexpired code;
  otherwise it sends nothing. A sign-in code goes only to the identity the guard's provider finds by the identifier
  that is an `Identity`, not a `MachineIdentity`, active, `HasVerifiableIdentifiers`, and reports the identifier of the
  type verified. A verification code goes only to the identity it carries, read again from the write connection, not a
  `MachineIdentity`, whose identifier of the type still normalises to the bound one. Otherwise nothing is sent, and
  nothing says so.
- A sign-in by code (`CodeSignIn::authenticate()`, inside the session service's credential timebox) refuses a missing
  or malformed identifier or a code that is not exactly `length` ASCII digits as `invalid_credentials`, counting
  nothing; looks the identity up; reserves an account attempt for a known identity (refused: `invalid_credentials`, the
  code untouched); then checks the code against the sign-in binding whether or not an identity was found.
  `expired` and `exhausted` answer `code_expired` and `code_exhausted`, concealed as `invalid_credentials` in the
  result. An accepted code for no identity is `invalid_credentials`, for an identity that does not report the
  identifier verified `identifier_unverified`, otherwise the identity.
- Verification by code (`CodeService::sendVerification()` / `verify()`) binds the code to the identity and its current
  identifier of the type in normal form, as the identity given reports it. An accepted code hands that identifier to
  `IdentifierVerifier::verify()`, which records it only if it is still the identity's; a refused check returns its
  reason unconcealed and reports it on the `identifier_verification` flow. It never signs anyone in. A machine identity
  is refused with an `InvalidArgumentException`, an identity without `HasVerifiableIdentifiers` with a `LogicException`.

## Success Path

- `Auth::codes('mobile')->send('phone_code', ['phone' => '+447700900123'])`: method resolved and allowed; identifier
  normalised; `code_request` reservation; `OneTimeCodes::issue()` (an `UPDATE`, plus an `INSERT` the first time);
  `SendOneTimeCode` dispatched once committed; `CodeRequest::sent($expiresAt)`.
- The worker runs the job: live issuance; recipient found and eligible; `OneTimeCodeSender::send(OneTimeCodeMessage)`.
- `Auth::sessions('mobile')->signIn('phone_code', ['phone' => ..., 'code' => ...])`: the session service's
  `Attempting`, method check and `sign_in` reservation; `CodeSignIn::authenticate()` (lookup, account reservation,
  `OneTimeCodes::check()`: `SELECT`, counting `UPDATE`, using `UPDATE`); admission, factor policy, device and tokens as
  for a password, with `phone_code` recorded on the device.
- `sendVerification($identity, 'phone')` then `verify($identity, 'phone', $code)`: the same issue, delivery and check
  for the verification binding, then `IdentifierVerifier::verify()` and `IdentifierVerified` once committed.

## Failure / Edge Cases

- Request refusals: `method_not_allowed` (nothing counted), `identifier_invalid` (nothing counted; reported as
  `invalid_credentials`), `rate_limited` with the limit's wait, or with the cooldown's seconds left. Each dispatches
  `AuthenticationFailed` on the `code_request` flow with the identifier as given.
- After `max_attempts` checks a code is locked until another is requested, which the cooldown and the `code_request`
  limits bound; per identifier and per IP address the `sign_in` limits, and per account the account limit shared with
  the password method, bound the checks as well.
- With a cooldown of 0 two concurrent first requests for one binding still create one code: the one that waited on the
  other's insert is answered `rate_limited` with 1 second.
- The code's attempt and use share the device connection's transactions: a caller that rolls back a transaction there
  gives the attempt back (the `sign_in` limits, on `rate_limits.connection`, still count it).
- A delivery that throws fails the job; the queue's retry policy applies, and a retry checks the issuance again. An
  unbound sender is a `BindingResolutionException`. A verification job whose identity was deleted is dropped, not
  failed. A sign-in job for a guard that is not a `jwt` guard throws an `InvalidArgumentException`.
- On a `sync` connection with after-response dispatching turned off (`Bus::withoutDispatchingAfterResponses()`) Laravel
  runs the job during the call; this is the documented fallback, not the package's choice.
- Malformed settings (`length` 6 to 10, `ttl_seconds` 60 to 3600, `max_attempts` 1 to 20, `resend_cooldown_seconds` 0
  to `ttl_seconds`, a queue connection that is not configured, a key shorter than 32 bytes, no key and no `app.key`)
  fail closed with an `InvalidArgumentException` naming the key before anything is counted or issued, and
  `authentication:check` reports each under `[codes]`, with a guard that allows a code method while no
  `OneTimeCodeSender` is bound.
- Expired rows are deleted by `model:prune` with `Models\OneTimeCode` (`expires_at <= now`); the cooldown, never longer
  than the lifetime, has ended with them.

## Implementation Anchors

- `src/Codes/OneTimeCodes.php` (engine), `src/Codes/CodeKeys.php`, `src/Codes/CodeBinding.php`,
  `src/Codes/CodeSettings.php`, `src/Codes/Enums/CodeCheck.php`.
- `src/Codes/CodeService.php` (`Auth::codes()`), `src/Codes/CodeSignIn.php` (`phone_code`, `email_code`),
  `src/Codes/SendOneTimeCode.php`.
- `src/Contracts/OneTimeCodeSender.php`, `src/Codes/OneTimeCodeMessage.php`, `src/Testing/FakeOneTimeCodeSender.php`.
- `src/Identifiers/E164PhoneNormaliser.php`, `src/Models/OneTimeCode.php`,
  `database/migrations/2026_04_06_000003_create_one_time_codes_table.php`.
- `src/Console/CheckConfigurationCommand.php` (`[codes]` checks and the `sync` warning).

## Authoritative Tests

- `tests/Integration/Codes/OneTimeCodesTest.php`: issue, cooldown, replacement, attempts, expiry, single use, the
  repeated-digits resend and checks overtaken between read and write.
- `tests/Integration/Codes/ConcurrentOneTimeCodesTest.php`: races on PostgreSQL and MySQL.
- `tests/Integration/Codes/SendOneTimeCodeTest.php`: recipients, live issuance, encrypted payload on a real queue,
  after-response delivery on `sync`.
- `tests/Integration/Codes/ReplicaOneTimeCodesTest.php`: write-connection reads.
- `tests/Feature/Codes/CodeSignInTest.php`, `tests/Feature/Codes/EmailCodeSignInTest.php`,
  `tests/Feature/Codes/CodeServiceTest.php`, `tests/Feature/Codes/CodeRoutesTest.php`.
- `tests/Performance/OneTimeCodeQueryBudgetTest.php`.

## Change Triggers

- Changing what a binding includes, the digest or hash construction, or the key derivation (outstanding codes stop
  working; say so in the changelog).
- Adding identity-dependent work to a code request, or delivering inside the request.
- Changing which reasons a sign-in by code may answer, or which are concealed.
- Letting a machine identity, an inactive identity or an unverified identifier receive a sign-in code.
