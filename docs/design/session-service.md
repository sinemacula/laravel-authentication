# Session Service

## Purpose

This note records how a JWT guard's session service (`Auth::sessions($guard)`) turns a sign-in into a session: the
checks it runs and their order, how it creates a device or continues one a client proves it holds, and what it
dispatches when. It is the one place a session starts, so every sign-in method, and every external verifier that calls
`start()`, ends in the same checks.

## Invariants

- Failures are results (`SignInResult::failed()` with a `FailureReason`), each reported with Laravel's `Failed` and then
  `AuthenticationFailed` (flow `sign_in`). A concealed reason (`account_rate_limited`, `code_expired`, `code_exhausted`,
  `passkey_counter_regressed`) reaches only the event; the result says `invalid_credentials`, with no wait. Exceptions
  are reserved for misconfiguration (an unknown method, a method that refuses with a reason that is not a sign-in method
  reason, an identity that is not an Eloquent model or does not implement `HasDevices`, an invalid device model, an
  `UnresolvableIdentityException`) and server errors. An identity without `HasDevices` is refused before it is admitted
  (in `signIn()`, after its slot was taken; in `start()` and `complete()`, before anything is written), because a bearer
  token names a device the guard can only find through that relation, so the session's access token would never
  authenticate. A `MachineIdentity` is the exception: it is let through to admission, which refuses it as a result
  (`machine_identity`), since a non-human identity has no session whatever it implements.
- No event ever receives the sign-in input. `Attempting` and `Failed` carry only `[type => identifier]` (or
  `['identifier' => ...]` for a method without a type, or nothing); `AuthenticationFailed` carries the identifier as
  given.
- `signIn()` order: the method is resolved (unknown throws); `Attempting`; the audience policy must allow the method
  (`method_not_allowed`, nothing counted, no timebox); the attempt limiter must grant a slot (`rate_limited`); then, in
  the guard's credential timebox, cut short only for an admitted sign-in: the method verifies the input, the identity
  must not be a `MachineIdentity` (`machine_identity`) and must be active, the audience policy must admit it with the
  identifier type before any principal is resolved (`admitIdentifier()`; the package's finds the identifier verified
  where the guard requires it), the principal (the context's pin, verified like an `attempt()` pin, else the resolver's
  default) and its tenant must be active, and the audience policy must admit them with the method's identifier type; a
  password is rehashed; the proof of a device is checked; the additional-factor policy is asked; the session is written,
  recording the method and its identifier type on the device, or a pending sign-in is issued. Only a success gives the
  slots back, those the method took on the accounts it checked included; a pending sign-in keeps them all, with their
  windows, until `complete()` starts its session. The slots are written on `rate_limits.connection`, outside the
  session's own transaction but not outside a transaction the caller opened on that connection: with the default
  (`null`, the storage connection) a caller that rolls back around a sign-in rolls its counts back too, so its attempts
  go uncounted. Only counters on a connection of their own survive such a rollback. `complete()` therefore gives the
  slots back only once its delete of the pending sign-in commits on that row's connection: a rollback restores the
  pending sign-in, and slots given back before it would be given back again when the token is completed a second time. A
  release that fails then is reported to the exception handler, not thrown, the one limiter error that does not
  propagate: the session already stands, and Laravel runs a commit's callbacks in order without catching, so a throw
  would stop the later ones (another completion's events, the caller's own). The release stops at the failure, and the
  slots not given back stay counted. A handler that throws while reporting is not caught, as with Laravel's `rescue()`:
  an error that cannot be reported surfaces rather than vanishing.
- The steps `signIn()` and the guard's `attempt()` take the same way are `Sessions\CredentialAttempt`'s, which each
  calls in its own order: `checkMethod()` (the audience policy's method check, before anything is counted), `begin()`
  (the slot on the identifier and IP limits, the limiter resolved then), the account attempts the method's checks count
  against, `accountRefusal()` (`account_rate_limited`, with the account's wait), `windows()` for a pending sign-in to
  keep and `release()` for a session. `attempt()` reads the identifier for the limits between the two, only once the
  method is allowed. What runs in the timebox and around it stays with each: `attempt()` fires `Validated` once the
  password is accepted, rehashes and asks the factor policy inside the timebox, cuts it short only for an admitted
  attempt and gives its slots back before the bind; `signIn()` cuts it short for an admitted sign-in or a choice,
  rehashes after it, continues to a session, a pending factor or a choice, and gives its slots back after the bind.
- `start()` reloads the identity through the guard's provider and requires the same class and key (`identity_unknown`),
  then runs the method check, the admission with no identifier type, the device proof, the factor policy and the write.
  It takes no slot and runs in no timebox: nothing is guessed. The principal is given as the argument or on the
  context, never both. A machine credential kind (`SignInMethodManager::CREDENTIAL_METHODS`) as the method is an
  `InvalidArgumentException` before anything else: a session recorded under `client_credentials` would pass for a
  client credentials token to every listener that reads the method.
- One `$now` per call, cut to the second, is used for the deadlines, the last use and every token's `iat`. The
  deadlines come from the audience policy's lifetimes for the principal (`AudiencePolicy::lifetimes()`), which with the
  shipped policy are the guard's `jwt.by_principal_type` entry for the principal's type, or the guard's own; the access
  token is issued with the principal's type in `pty` (see `audience-policy.md`).
- A session is written in one transaction on the device's connection: the device first, then both tokens, so any
  failure while issuing rolls the device back. Only the digest of the rotation id is stored.
- A refresh token proves a device only when it is the device's current rotation id, validly signed for the guard
  (`parseRefreshProof()`: every `parse()` check except expiry), and the device, read from the writer, is owned by the
  identity, records this guard and the same principal, and is not revoked. Anything else is no proof: a new device,
  nothing failed, revoked or reported.
- Continuing a proven device is one compare-and-swap on the row exactly as it was proven (digest, owner, principal, not
  revoked). It restarts both deadlines, sets a new rotation id with no previous one, and records the method, the last
  use and the client's description when given; it keeps the guard, owner, principal and creation details. A swap that
  misses reconsiders the sign-in without the device, factor policy included: it creates a device, or issues a pending
  sign-in when the factor policy now asks for one; it never retries.
- After the session's transaction, `DeviceCreated` (new devices only) and `SignedIn` are scheduled on the commit of the
  device's connection, and a completion's or a choice's slot give-back on the pending row's, and only then is the guard
  bound, with the usual immediate bind events: a bind listener that throws cannot withhold them, and they never fire for
  a rolled-back session. The order holds by construction: `SessionEstablishment` writes the session (or issues the
  pending sign-in), asks the factor policy and schedules those reports, and never binds; the service binds the guard,
  through `login()` on the `Contracts\GuardBinding` it was given, only once establishment has returned a signed-in
  result, and `signIn()` gives its slots back after that bind.
- The service holds no state between calls. It runs on the guard's context (`Runtime\GuardContext`), reading the
  provider, resolver, dispatcher and request, and the sign-in method manager and policies from the container, each time
  it needs them, and reaches the guard's bound state only through its binding; it names no `Guards` class. The guard
  neither builds nor holds one: `AuthManager::sessions()` builds a service on each call, from the guard's context and
  token service, with the guard as the binding, on the container's connections and transactions manager. A service
  handed out earlier therefore follows the guard's rebinds as a new one does.
- The principals an identity may choose from, the choice a sign-in without a default waits on, and finding a live choice
  are `PrincipalChoices`' (see `principal-choice-and-switch.md`); the service routes a sign-in to it and binds a chosen
  session as it binds any other.
- Ending sessions is not the service's own: `signOut()`, `signOutEverywhere()`, `revokeDevice()`, `revokeDevices()`,
  `revokePrincipalDevices()` and the security-change methods delegate to `SessionRevocations` (see
  `device-lifecycle.md`), on the guard's context, with the guard as the `Contracts\GuardBinding` the two sign-out calls
  read and forget. The guard's `logout()` and the password writer use the same revocations without a session service.
- Refreshing is the service's too, beside switching principal: `refresh()` and `refreshFromRequest()` delegate to
  `SessionRefresh`, which runs the refresh exchange the service builds on the guard's context and token service,
  schedules `Refreshed` and `SignedIn` (a refresh) for the rotation's commit, and only then binds the guard as a sign-in
  through the binding's `loginVerified()`, with the tenant and the sign-in method the exchange established. Every
  refusal is a failed `RefreshResult` with the exchange's or the transport's reason, `rate_limited` with its wait, never
  a thrown 429; `refreshFromRequest()` answers `null` only for a request without a token, and says where it read one
  (see `refresh-rotation-and-replay.md` and `refresh-token-transport.md`).

## Success Path

- A new device: `Attempting`, then, once committed (at once with no transaction open on the device's connection),
  `DeviceCreated` and `SignedIn` (`deviceCreated: true`), then `Validated`, `Login`, `Authenticated`,
  `PrincipalAssigned`, `DeviceAuthenticated`. Inside a caller's transaction the bind events come first and the pair
  follows its commit. The device's last use is the sign-in, so the shipped last-use listener writes nothing more.
- A continued device: the same, without `DeviceCreated`, and `SignedIn` with `deviceCreated: false`.
- `start()`: the same without `Attempting`.
- A sign-in held for a further factor: `Attempting` (not from `start()`), then, once the pending sign-in is committed
  on its connection, `AdditionalFactorRequired` (a context of guard, identity, principal, tenant, proven device, method
  and client, and the expiry; never the token), and nothing bound. Its completion follows the new or continued device
  path without `Attempting`; its discard emits `Failed` and `AuthenticationFailed` (`additional_factor_failed`, the
  method, the discarding client, the identity when the provider still returns it), and a token that discards nothing
  emits nothing.

## Failure / Edge Cases

- A required additional factor starts no session: the service stores a pending sign-in (the digest of a single-use,
  guard-bound token's secret, who, as whom, how, from which client, the proven device and the digest it was proven
  against, the windows of the attempt-limit slots the sign-in took, and an expiry from
  `authentication.sign_in.pending_ttl_seconds`) and returns its token. The token is not a JWT, so no guard authenticates
  a request or a refresh with it. The slots stay taken until the pending sign-in completes, the one the method's check
  took on the account (`SignInRequest::reserveAccountAttempt()`) among them, and `discard()` uses one up without a
  session (as when its factor fails), so each guess at a factor costs a sign-in attempt. For the password method the
  guesses are bounded by the account's one count, whatever spelling of the identifier or guard the sign-ins used, held
  to the most permissive `per_identifier` limit among the guards that check the account (see `audience-policy.md`); for
  a method that counts no account, only by its identifier's and the IP address's limits. A pending sign-in from
  `start()` holds no slots (nothing was guessed), so its external verifier bounds it.
- `pending()` finds a live pending sign-in of the guard (identity reloaded through the provider as the recorded owner,
  principal through the hinted path as the recorded one, still owned) without using it up. `complete()` uses it up by a
  `DELETE` on its id, digest and unexpired `expires_at` that only one completion can win, checks it again (method,
  activity, tenant, `admitIdentifier()` and `admit()` with the stored identifier type; not the factor policy), and
  writes the session in the same transaction; a failed check still uses it up. Every lookup failure is
  `pending_invalid`. A completion runs in the completing request's client: its events and the device's last use carry
  that client, while a device it creates records the client the sign-in came from as its creation.
- A sign-in that names no principal, for an identity whose resolver has no default but which has eligible principals,
  waits for a choice instead of failing: a pending sign-in of purpose `principal_choice`, with no principal and the
  sign-in's slots, reported by `PrincipalChoiceRequired`. `pending()` and `complete()` never take a choice token. See
  `principal-choice-and-switch.md`.
- Inside a caller's transaction the service's transaction is a savepoint: the guard is bound at once, the lifecycle
  events wait for the caller's commit, and a rollback withdraws them with the device while the guard stays bound. Do not
  roll back around a sign-in.
- A listener that throws on a bind event propagates after the session committed: the device exists and the pair is lost,
  but `DeviceCreated` and `SignedIn` were already dispatched (or, inside a caller's transaction, wait for its commit)
  and a completion's slots are given back. A listener that throws on `DeviceCreated` or `SignedIn` with no transaction
  open propagates before the bind: the session stands, the guard is not bound, and `SignedIn` is not dispatched after a
  throwing `DeviceCreated`.
- A device continued by a sign-in makes the earlier refresh tokens of the device replays (see
  `refresh-rotation-and-replay.md`).
- A crafted client name or platform is stored cleaned (`SignInContext`), so it cannot fail the insert.

## Implementation Anchors

- `src/Sessions/SessionService.php`: `signIn()`, `start()`, `complete()`, `choose()`, `bound()`;
  `src/Sessions/Concerns/EndsSessions.php`: the methods it delegates to `src/Sessions/SessionRevocations.php` (a trait
  only so the service stays within phpcs's limit of methods a class may declare);
  `src/Sessions/Concerns/RefreshesSessions.php`: `refresh()` and `refreshFromRequest()`, delegated to
  `src/Sessions/SessionRefresh.php` (a trait for the same reason), and `src/Sessions/RefreshResult.php`.
- `src/Sessions/SessionEstablishment.php`: `proceed()`, `establish()`, `complete()`, `write()`, `signedIn()`,
  `giveBack()`: the session, the factor policy and the scheduled reports, never the bind.
- `src/Sessions/PrincipalChoices.php`: `offerChoice()`, `admissible()`, `liveChoice()`.
- `src/Sessions/CredentialAttempt.php`: the method check, the slots and their give-back, shared with `attempt()`
  (`src/Guards/Concerns/SignsInWithCredentials.php`).
- `src/Sessions/SignInRequest.php` (`reserveAccountAttempt()`) and `src/RateLimiting/AccountAttempts.php`: the slots a
  sign-in's method takes on the accounts it checks, held with the sign-in's own.
- `src/Sessions/SessionWriter.php`: `create()`, `continueOn()` and the compare-and-swap.
- `src/Sessions/DeviceProof.php`, `src/Jwt/JwtTokenService.php` (`parseRefreshProof()`), `src/Devices/DeviceLookup.php`.
- `src/Sessions/PendingSignIns.php` and `src/Models/PendingSignIn.php`: issuing, finding and consuming pending sign-ins.
- `src/Sessions/SessionPreconditions.php`: the `HasDevices` refusal, and `start()`'s one-principal rule and
  reloaded-identity check.
- `src/Admission/SignInAdmission.php`, shared with `attempt()`; `src/Admission/PinnedPrincipal.php`.
- `src/Database/AfterCommit.php`, shared with the refresh exchange's revocation report.
- `src/AuthManager.php`: `sessions()`, which builds the service per call; `src/Guards/JwtGuard.php`: `tokens()`.

## Authoritative Tests

- `tests/Feature/Sessions/SessionServiceTest.php`, `tests/Unit/RateLimiting/AccountAttemptsTest.php`
- `tests/Feature/Contracts/CredentialAttemptMatrixTest.php`: every case of `signIn('password')` beside `attempt()`'s,
  with its answer, events, timebox, rehash and slots; `tests/Feature/Sessions/CredentialAttemptTest.php`
- `tests/Feature/Sessions/SessionEstablishmentTest.php`: establishment on its own (what it writes, returns and
  schedules, and that it never binds); `tests/Feature/Sessions/PrincipalChoicesTest.php`
- `tests/Feature/AuthManagerTest.php`: the service built per call on the guard's context, binding and token service
- `tests/Feature/Sessions/SessionRefreshTest.php`, `tests/Unit/Sessions/RefreshResultTest.php`: the refresh, its events
  and bind, and every refusal returned
- `tests/Feature/Sessions/SessionRevocationsTest.php`, `tests/Feature/Sessions/ManagesDevicesTest.php`,
  `tests/Feature/Sessions/RevokesOnSecurityChangesTest.php`: the revocations on their own and through the service
- `tests/Feature/Sessions/SessionRoutesTest.php`: the documented sign-in and further-factor routes over HTTP, through
  `Auth::sessions()`, with tokens checked through `auth:api`
- `tests/Integration/Sessions/SessionServiceTest.php`
- `tests/Feature/Sessions/DeviceProofTest.php`, `tests/Feature/Sessions/SessionWriterTest.php`
- `tests/Feature/Sessions/PendingSignInsTest.php`, `tests/Integration/Sessions/PendingFactorSessionServiceTest.php`
- `tests/Integration/Sessions/ReplicaPendingSignInsTest.php`: pending sign-ins read from the writer
- `tests/Unit/Sessions/SessionPreconditionsTest.php`
- `tests/Integration/Sessions/SignInPolicyEndToEndTest.php`: the shipped audience policy, attempt limiter, normalisers
  and verified-identifier gate, through `signIn()`, `start()` and `attempt()`
- `tests/Integration/Migration/PendingSignInsTableSchemaTest.php`
- `tests/Performance/SessionServiceQueryBudgetTest.php`
- `tests/Feature/Contracts/EventSequenceTest.php`, `tests/Integration/Contracts/EventSequenceTest.php`: the event
  sequence of every sign-in, completion, choice and discard, and around the device connection's transaction

## Change Triggers

Update this note when any of the following change:

- the order of the checks, or which of them count an attempt or run in the timebox
- which steps `Sessions\CredentialAttempt` shares between `signIn()` and `attempt()`
- what proves a device, or what continuing one writes or keeps
- what the session's transaction contains, or when the guard is bound, or what builds the service
- when `DeviceCreated`, `SignedIn` and `AdditionalFactorRequired` are dispatched, or what they carry
- what reaches the events from the sign-in input
- what a pending sign-in stores, how long it lives, what finds it, or what completing it checks
- which of its methods it delegates to `SessionRevocations`, or what of the guard those need
- what a refresh returns, binds or reports, or what it delegates to `SessionRefresh`
