# Application Policy

## Purpose

This note records what an application decides about the sessions it holds, beyond the token itself: which sign-in
methods may start them and which machine credentials it accepts, which principals may hold them, whether the identifier
a sign-in used must be verified, and how long they last. An application is the app being signed into, and each
application is a guard, so these are per-guard settings, read by one contract (`ApplicationPolicy`) that every path that
starts or continues a session consults. "Audience" names only the API a token is for, its `aud` claim
(`jwt.audience`), which this policy does not touch. The note also records how the attempt limits and the identifier
normalisers meet that policy, since a sign-in passes through all three.

## Invariants

- The shipped `Applications\GuardApplicationPolicy` reads the guard's `application` block over the package defaults in
  `authentication.application`: a key present at guard level wins, `null` included. `methods` (default `[]`) is a list,
  possibly empty, of method names; `require_verified_identifier` (default `false`) is a boolean. A missing, malformed or
  unknown key (a leftover `principal_types` included), at either level, fails closed with an `InvalidArgumentException`
  naming the guard and the key. Every call reads and checks the whole block, so a malformed key fails whichever check
  runs first and nothing is cached past a configuration change.
- An empty `methods` list is a valid state, not a misconfiguration (decided: D21, every feature is opt-in). It allows
  nothing, through the same refusals as a method the application does not list, with no code path of its own:
  `attempt()`, `signIn()` and `start()` are refused as `method_not_allowed` before any attempt slot is reserved or the
  method runs; a pending further factor or principal choice is consumed first (an unknown, expired or spent credential
  is still `pending_invalid`) and then refused, so the person signs in again and the slots it held stay counted until
  their window ends; code and password reset requests answer `method_not_allowed`, and a password never
  reauthenticates; refresh and switch are refused without revoking the device; an `api_key` guard refuses every key and
  a client credentials exchange answers `unauthorized_client`. Access tokens already issued keep working until they
  expire: the list is admission, not revocation. It does not throw because the package default is `[]`, so throwing
  would turn every application not yet configured into a server error, and because an application with no methods is
  legitimate (access-only mode, or sign-ins stopped without revoking). `null` stays malformed, so "none" has one
  spelling. `authentication:check` warns about a `jwt` guard whose package settings list nothing, or only `api_key`
  (which a `jwt` guard never accepts), and reports an `api_key` guard whose policy, whichever is bound, does not allow
  `api_key` as a problem, since such a guard has no other use. Any other name counts, registered or not, since
  `start()` signs in under it; a policy of the application's own is asked every registered name and
  `client_credentials` so an exception it throws is reported, and a guard it allows `passkey` has its relying party
  checked, but no such policy, even one that wraps the package's, gets the warning, since the names it allows are its
  own to know.
- A method is allowed only when the guard lists its exact name: the key a method the package runs is registered under on
  the `SignInMethodManager`, or the name the application passes to `start()` for a session it starts itself (which needs
  no registration), and in either case the name a device records in `sign_in_method`. The same list names the machine
  credentials the guard accepts (`SignInMethodManager::CREDENTIAL_METHODS`): `api_key` on an `api_key` guard,
  `client_credentials` on a `jwt` guard whose client credentials exchange is open; neither is a sign-in method, and the
  manager refuses to register a method under either name (see `machine-credentials.md`).
- The package has no rule about which principals may hold a guard's sessions: its `admit()` admits every principal and
  is exactly `admitIdentifier()`. An application with such a rule rebinds the policy and refuses from `admit()` as
  `principal_ineligible`, the one reason every path reports as such: a refresh, and a switch's check with no identifier
  type, report any refusal as `principal_ineligible`, but a sign-in, a switch's check with the session's identifier type
  and an API key report the reason the policy gives, and a client credentials exchange answers `unauthorized_client` for
  `principal_ineligible` and `invalid_client` for any other reason. A caller's category (staff, a client's
  administrator, a service) is the application's or authorization's to model, never the token's: no claim carries it and
  no accessor returns it.
- The verified-identifier gate applies only when the guard sets `require_verified_identifier` and the sign-in names an
  identifier type: the password method's is the guard's `sign_in.password_identifier`, else
  `authentication.sign_in.password_identifier` (default `email`), whatever the credentials look like, so a query closure
  in `attempt()` cannot skip it. The identity must then implement `HasVerifiableIdentifiers` (otherwise a
  `LogicException`: a misconfiguration) and report that identifier verified, read on the write connection; otherwise
  `identifier_unverified`. `start()`, `complete()` without a stored type, and refresh carry no identifier type and are
  never gated: an external verifier or an existing session vouches for them. A switch of principal is admitted with the
  type the session's sign-in used (recorded on the device), as that sign-in was.
- The gate depends on the identity alone, so it is the contract's `admitIdentifier($guard, $identity,
  $identifierType)`, which every sign-in (`attempt()` included) asks of whatever policy is bound after the identity's
  activity check and before resolving any principal: an unverified identifier is refused alike whether the identity
  has principals or not. A switch of principal asks it with the session's identifier type before `admit()`. The
  package's `admit()` also asks its own `admitIdentifier()`; a policy that wraps another asks the wrapped one's, and a
  policy with no identity-level rule returns `null`.
- `admit()` is asked only after the identity, the principal and its tenant have passed their activity checks.
- Every `admitIdentifier()` runs inside `WriteConnection::during()` for the identity, and every `admit()` for the
  identity and the principal (`Admission\ApplicationAdmission`), on every path: sign-in, `start()`, `complete()`,
  `choose()` and the choice list, refresh, switch, API keys and their issue, client credentials and password resets. A
  policy of the application's own decides from rows of its own (a grant, a membership), and a replica that lags behind
  their withdrawal must not admit the principal, as the package's activity and tenant checks never do. Model reads and
  query-builder reads on those two connections are covered; a policy pins any other read itself.
- Lifetimes are per guard only: `lifetimes($guard)` is the guard's token service's lifetimes, the same for every
  principal. Unlike the `application` block, they are read only when the token service is built: the token service
  factory keeps the service, so a later change reaches it only once the process restarts. Issuing an access token reads
  nothing from the principal beyond its identifier.
- Policy decisions never revoke a device. A session the policy stops admitting is refused on its next refresh and
  refreshes again once the policy admits it.

## Success Path

- `signIn()` and `attempt()`: `Attempting`; `allowsMethod()` (nothing counted when it refuses); the attempt limiter's
  reservation; inside the credential timebox, the method's verification, activity, `admitIdentifier($guard,
  $identity, $identifierType)`, the principal, then `admit($guard, $identity, $principal, $identifierType)`; the
  session's device takes its deadlines from `lifetimes($guard)`.
- `start()`: `allowsMethod()` and `admit()` with no identifier type; no limiter, no timebox.
- `complete()` and `choose()`: the pending row is consumed first, then `allowsMethod()` for the stored method, and
  `admitIdentifier()` and `admit()` with the stored identifier type, rechecked when the pending sign-in is used, so a
  policy change while a factor is verified or a principal chosen still applies.
- Refresh: right after the device lookup, the device must record this guard (`device_guard_mismatch`); after the owner
  and principal are reloaded, the recorded method must still be allowed (`method_not_allowed`, also when the device
  records none) and `admit()` must pass with no identifier type (`principal_ineligible`, whatever reason the policy
  gives); a rotation's idle deadline comes from `lifetimes($guard)`.
- Bearer requests and `attempt()`'s device pin treat a device of another guard, or of none, as missing.

## Failure / Edge Cases

- Attempt limits: a sign-in reserves a slot on its identifier's and its IP address's counters before the method runs
  (`rate_limited` with the wait, the method never asked); a success gives its own slots back, a pending sign-in only
  when it completes, and failures keep theirs until the window ends. A refresh counts only its failures, against the
  device and the IP address, and is refused as `rate_limited`, with the wait, once either is full. Counters are kept per
  guard, flow and scope as HMAC-SHA256 digests keyed from `app.key` (an enumerable IP address or identifier cannot be
  recovered from the table alone), on `rate_limits.connection`. They are written outside the session's own transaction,
  but a caller transaction on the same connection holds them: with the default (`null`, the storage connection) a
  sign-in its caller rolls back takes its counts with it and is not counted. Counters on a connection of their own still
  count it.
- An identifier is counted in its canonical form: through the normaliser registered for the method's identifier type
  when there is one (the form `ModelProvider` looks it up in), otherwise trimmed and lower-cased. Every casing of an
  address therefore shares one counter, and a lookup by a designated identifier normalises the credential before it
  queries, so the address is found however it was typed.
- A lookup can still find one account by spellings no normaliser folds (a collation that ignores accents, widths or
  invisible characters, a query closure, a list of values, another column), so the password method counts every password
  it checks against the account it checks it for (`AttemptSubject::$account`, a `per_account` counter under the
  `per_identifier` limit; an Eloquent identity's account is its row, named by connection, database, prefixed table and
  key, so model classes that read one table share it and tenants' databases do not), taking the slot after the lookup
  and holding it with the sign-in's other slots: given back when the sign-in starts its session, kept by a pending
  sign-in until it completes, counted on a failure. The account's counter is keyed without the guard, so every guard
  whose provider returns the account counts in it, each held to its own `per_identifier` limit (a guard with that limit
  off neither checks nor counts it). The account's guesses are therefore bounded by the most permissive limit among the
  guards that check it, at most the largest `max` in each window of the shortest `decay_seconds`: a guard with a looser
  limit raises the bound for every guard, a stricter one only stops its own sign-ins sooner, and another guard with the
  same limit adds no guesses. An account with no attempts left is not checked and fails as `invalid_credentials`, so the
  refusal is no existence oracle; only `AuthenticationFailed`, which goes to server-side listeners, says
  `account_rate_limited`, with the wait. `attempt()` refuses an identifier that is neither a string, a `Stringable`, an
  integer nor a query closure before any lookup, and an IPv6 client is counted per /64 network, except that an address
  carrying an IPv4 client's address (IPv4-mapped, or the NAT64 well-known prefix `64:ff9b::/96`) is counted as that IPv4
  address.
- A custom `ApplicationPolicy` decides the session's deadlines (the device's on sign-in, the idle deadline on each
  rotation) through `lifetimes($guard)`; the access token's expiry is still computed by the guard's token service from
  the guard's `jwt` lifetimes, and is capped at the session's end, and the refresh grace window and its leeway are
  always the guard's token service's, whatever lifetimes the policy returns. A policy that returns lifetimes the
  guard's configuration does not describe therefore shortens or lengthens sessions, not access tokens or the grace
  window.
- The policy is resolved from the container on every call, on every path, so a binding an application makes at any
  time is the one used.
- A switch of principal asks `admitIdentifier()` and `admit()` with the identifier type its session's sign-in used
  (recorded on the device), besides the refresh's own `admit()` with none, and `lifetimes($guard)`, and never
  extends the session's absolute deadline (see `principal-choice-and-switch.md`).

## Implementation Anchors

- `src/Contracts/ApplicationPolicy.php`, `src/Applications/GuardApplicationPolicy.php`,
  `src/Console/ApplicationChecks.php` (`authentication:check`).
- `src/Admission/ApplicationAdmission.php` (every `admitIdentifier()` and `admit()` asked on the write connection).
- `src/Jwt/JwtTokenServiceFactory.php` (the guard's lifetimes) and `src/Jwt/JwtTokenService.php` (`lifetimes()`).
- `src/Sessions/SessionService.php`, `src/Sessions/CredentialAttempt.php` (the method check) and
  `src/Admission/SignInAdmission.php`, shared with `src/Guards/Concerns/SignsInWithCredentials.php` (`attempt()`).
- `src/Jwt/RefreshTokenExchange.php` (`exchangeOn()`, `rotate()`), `src/Jwt/RefreshAdmission.php` (`admitByPolicy()`)
  and `src/Guards/Concerns/VerifiesPinnedContext.php` (`resolveDeviceFromHint()`).
- `src/Contracts/AttemptLimiter.php`, `src/RateLimiting/DatabaseAttemptLimiter.php`,
  `src/RateLimiting/AttemptLimits.php`, `src/RateLimiting/RateLimitStore.php`.
- `src/Identifiers/IdentifierNormalisers.php`, `src/Casts/NormalisedIdentifier.php`, `src/Providers/ModelProvider.php`.
- `src/Verification/IdentifierVerifier.php` (`verifiable()`) and `src/Verification/VerificationLinks.php`.

## Authoritative Tests

- `tests/Integration/Sessions/SignInPolicyEndToEndTest.php` (every piece above, through the shipped bindings)
- `tests/Unit/Admission/SignInAdmissionTest.php` `testAnyPolicysRefusalOfTheIdentityComesBeforeItsPrincipal`
- `tests/Feature/Applications/GuardApplicationPolicyTest.php`,
  `tests/Integration/Guards/ApplicationPolicyIntegrationTest.php`
- `tests/Integration/Applications/EmptyApplicationIntegrationTest.php` (the shipped empty default, end to end), with
  `testAPendingSignInWhoseMethodIsRemovedIsSpentAndRefused` in `SignInPolicyEndToEndTest` and
  `testAChoiceWhoseMethodIsRemovedIsSpentAndRefused` in `tests/Integration/Sessions/PrincipalChoiceEndToEndTest.php`
- `tests/Feature/Console/CheckConfigurationCommandTest.php` (the application checks and the warning)
- `tests/Performance/AccessTokenIssueQueryBudgetTest.php`
- `tests/Integration/Guards/RefreshApplicationIntegrationTest.php`
- `tests/Feature/Jwt/RefreshTokenExchangeTest.php`
  `testTheGraceWindowIsTheTokenServicesWhateverLifetimesThePolicyReturns`
- `tests/Integration/Admission/ApplicationAdmissionTest.php`,
  `tests/Integration/Applications/ReplicaApplicationPolicyTest.php` (sign-in, start, refresh, switch and choices),
  `testTheApplicationPolicyIsAskedOnThePrimary` in `tests/Integration/ApiKeys/ReplicaApiKeysTest.php` (API keys, their
  issue and client credentials) and in `tests/Integration/Passwords/ReplicaPasswordResetsTest.php`
- `tests/Integration/RateLimiting/DatabaseAttemptLimiterTest.php`,
  `tests/Integration/RateLimiting/ConcurrentDatabaseAttemptLimiterTest.php`
- `tests/Performance/AttemptLimiterQueryBudgetTest.php`, `tests/Performance/SessionServiceQueryBudgetTest.php`,
  `tests/Performance/JwtGuardAttemptBudgetTest.php`

## Change Triggers

Update this note when any of the following change:

- the keys of an `application` block, their defaults, or how a guard's keys combine with the package's
- what an empty `methods` list allows or refuses, or whether `authentication:check` warns about it
- whether the package decides which principals may hold a guard's sessions, or how a rebound policy's refusal is
  reported
- which sign-ins carry an identifier type, and so which the verified-identifier gate applies to
- which paths consult the policy (sign-in, start, completion, refresh, bearer, pins), in what order, or whether any of
  its refusals revokes a device
- whether lifetimes vary by anything but the guard, or where access-token and session lifetimes and the grace window
  are computed
- which connection the policy is asked on
- whether an access token carries anything about the principal beyond its identifier
- what the attempt limits count, in which form, where, or whether they share the session's transaction
