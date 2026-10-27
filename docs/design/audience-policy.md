# Audience Policy

## Purpose

This note records what a guard decides about the sessions it holds, beyond the token itself: which sign-in methods may
start them, which principals may hold them, whether the identifier a sign-in used must be verified, and how long they
last for each principal type. An audience is a guard, so these are per-guard settings, read by one contract
(`AudiencePolicy`) that every path that starts or continues a session consults. It also records how the attempt limits
and the identifier normalisers meet that policy, since a sign-in passes through all three.

## Invariants

- The shipped `Audience\GuardAudiencePolicy` reads the guard's `audience` block over the package defaults in
  `authentication.audience`: a key present at guard level wins, `null` included. `methods` (default `['password']`) is
  a non-empty list of method names; `principal_types` (default `null`, any principal) is `null` or a non-empty list;
  `require_verified_identifier` (default `false`) is a boolean. A missing, malformed or unknown key, at either level,
  fails closed with an `InvalidArgumentException` naming the guard and the key. Every call reads and checks the whole
  block, so a malformed key fails whichever check runs first and nothing is cached past a configuration change.
- A method is allowed only when the guard lists its exact name, the key it is registered under on the
  `SignInMethodManager` and the name a device records in `sign_in_method`.
- A principal's type is its own non-empty `HasType::getType()`, otherwise the non-empty type of the tenant it acts
  within, otherwise none (`Audience\PrincipalType::of()`), read on the write connection. A guard that lists types admits
  only principals whose type it lists; a principal without a type is refused. Refusal is `principal_ineligible`.
- The verified-identifier gate applies only when the guard sets `require_verified_identifier` and the sign-in names an
  identifier type: the password method's is the guard's `sign_in.password_identifier`, else
  `authentication.sign_in.password_identifier` (default `email`), whatever the credentials look like, so a query closure
  in `attempt()` cannot skip it. The identity must then implement `HasVerifiableIdentifiers` (otherwise a
  `LogicException`: a misconfiguration) and report that identifier verified, read on the write connection; otherwise
  `identifier_unverified`. `start()`, `complete()` without a stored type, and refresh carry no identifier type and are
  never gated: an external verifier or an existing session vouches for them.
- `admit()` is asked only after the identity, the principal and its tenant have passed their activity checks, and runs
  eligibility before the gate.
- Lifetimes come from `jwt.by_principal_type.<type>` on the guard (any of `access_ttl_minutes`,
  `refresh_idle_ttl_minutes`, `refresh_absolute_ttl_minutes`, each falling back to the guard's own); the grace window
  and leeway stay the guard's, because a refresh judges them before it knows the principal. A guard without the map
  never reads a principal's type for its lifetimes. Malformed entries fail closed with an
  `InvalidJwtConfigurationException` when the guard's token service is built.
- An access token carries the principal's type in `pty` when it has one, read when the token is issued; a refresh
  token never does. Nothing checks `pty` on a bearer request: eligibility is enforced when a session is issued and
  each time it refreshes, and `Auth::type()` reads the bound principal live.
- Policy decisions never revoke a device. A session the policy stops admitting is refused on its next refresh and
  refreshes again once the policy admits it.

## Success Path

- `signIn()` and `attempt()`: `Attempting`; `allowsMethod()` (nothing counted when it refuses); the attempt limiter's
  reservation; inside the credential timebox, the method's verification, activity, the principal, then
  `admit($guard, $identity, $principal, $identifierType)`; the session's device takes its deadlines from
  `lifetimes($guard, $principal)`.
- `start()`: `allowsMethod()` and `admit()` with no identifier type; no limiter, no timebox.
- `complete()`: `allowsMethod()` for the stored method and `admit()` with the stored identifier type, rechecked when
  the pending sign-in is used, so a policy change while a factor is verified still applies.
- Refresh: right after the device lookup, the device must record this guard (`device_guard_mismatch`); after the owner
  and principal are reloaded, the recorded method must still be allowed (`method_not_allowed`, also when the device
  records none) and `admit()` must pass with no identifier type (`principal_ineligible`, whatever reason the policy
  gives); a rotation's idle deadline comes from `lifetimes($guard, $principal)`.
- Bearer requests and `attempt()`'s device pin treat a device of another guard, or of none, as missing.

## Failure / Edge Cases

- Attempt limits: a sign-in reserves a slot on its identifier's and its IP address's counters before the method runs
  (`rate_limited` with the wait, the method never asked); a success gives its own slots back, a pending sign-in only
  when it completes, and failures keep theirs until the window ends. A refresh counts only its failures, against the
  device and the IP address, and is answered `429` with `Retry-After` once either is full. Counters are kept per guard,
  flow and scope as HMAC-SHA256 digests keyed from `app.key` (an enumerable IP address or identifier cannot be recovered
  from the table alone), on `rate_limits.connection`. They are written outside the session's own transaction, but a
  caller transaction on the same connection holds them: with the default (`null`, the default connection) a sign-in its
  caller rolls back takes its counts with it and is not counted. Counters on a connection of their own still count it.
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
  whose provider returns the account counts in it, each held to its own `per_identifier` maximum (a guard with that
  limit off neither checks nor counts it): adding a guard adds no guesses. An account with no attempts left is not
  checked and fails as `invalid_credentials`, so the refusal is no existence oracle; only `SignInFailed`, which goes to
  server-side listeners, says `account_rate_limited`, with the wait. `attempt()` refuses an identifier that is neither a
  string, a `Stringable`, an integer nor a query closure before any lookup, and an IPv6 client is counted per /64
  network, except that an address carrying an IPv4 client's address (IPv4-mapped, or the NAT64 well-known prefix
  `64:ff9b::/96`) is counted as that IPv4 address.
- A custom `AudiencePolicy` decides the session's deadlines (the device's on sign-in, the idle deadline on each
  rotation) through `lifetimes()`; the access token's expiry is still computed by the guard's token service from
  `jwt.by_principal_type`, and is capped at the session's end. A policy that returns lifetimes the guard's
  configuration does not describe therefore shortens or lengthens sessions, not access tokens.
- The policy is resolved from the container on every call, on every path, so a binding an application makes at any
  time is the one used.
- Principal switching (not in the package yet) is designed to ask `admit()` and `lifetimes()` for the new principal and
  to keep the session's absolute deadline.

## Implementation Anchors

- `src/Contracts/AudiencePolicy.php`, `src/Audience/GuardAudiencePolicy.php`, `src/Audience/PrincipalType.php`.
- `src/Jwt/JwtTokenServiceFactory.php` (`jwt.by_principal_type`) and `src/Jwt/JwtTokenService.php` (`lifetimesFor()`,
  `pty` in `issueAccessToken()`).
- `src/Sessions/SessionService.php` and `src/Sessions/Admission/SignInAdmission.php`, shared with
  `src/Guards/Concerns/SignsInWithCredentials.php` (`attempt()`).
- `src/Jwt/RefreshTokenExchange.php` (`exchangeOn()`, `hydrateRefreshContext()`, `rotate()`) and
  `src/Guards/Concerns/VerifiesPinnedContext.php` (`resolveDeviceFromHint()`).
- `src/Contracts/AttemptLimiter.php`, `src/RateLimiting/DatabaseAttemptLimiter.php`,
  `src/RateLimiting/AttemptLimits.php`, `src/RateLimiting/RateLimitStore.php`.
- `src/Identifiers/IdentifierNormalisers.php`, `src/Casts/NormalisedIdentifier.php`, `src/Providers/ModelProvider.php`.
- `src/Verification/IdentifierVerifier.php` (`verifiable()`) and `src/Verification/VerificationLinks.php`.

## Authoritative Tests

- `tests/Integration/Sessions/SignInPolicyEndToEndTest.php` (every piece above, through the shipped bindings)
- `tests/Feature/Audience/GuardAudiencePolicyTest.php`, `tests/Integration/Guards/AudiencePolicyIntegrationTest.php`
- `tests/Unit/Audience/PrincipalTypeTest.php`
- `tests/Integration/Guards/RefreshAudienceIntegrationTest.php`
- `tests/Integration/RateLimiting/DatabaseAttemptLimiterTest.php`,
  `tests/Integration/RateLimiting/ConcurrentDatabaseAttemptLimiterTest.php`
- `tests/Performance/AttemptLimiterQueryBudgetTest.php`, `tests/Performance/SessionServiceQueryBudgetTest.php`,
  `tests/Performance/JwtGuardAttemptBudgetTest.php`

## Change Triggers

Update this note when any of the following change:

- the keys of an `audience` block, their defaults, or how a guard's keys combine with the package's
- what counts as a principal's type, or whether an untyped principal can be admitted by a guard that lists types
- which sign-ins carry an identifier type, and so which the verified-identifier gate applies to
- which paths consult the policy (sign-in, start, completion, refresh, bearer, pins), in what order, or whether any of
  its refusals revokes a device
- which lifetimes can vary by principal type, or where access-token and session lifetimes are computed
- whether `pty` is written, required, or checked
- what the attempt limits count, in which form, where, or whether they share the session's transaction
