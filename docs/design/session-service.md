# Session Service

## Purpose

This note records how a JWT guard's session service (`Auth::sessions($guard)`) turns a sign-in into a session: the
checks it runs and their order, how it creates a session and revokes the one a client proves it holds, and what it
dispatches when. It is the one place a session starts, so every sign-in method, and every external verifier that calls
`start()`, ends in the same checks.

## Invariants

- Failures are results (`SignInResult::failed()` with a `FailureReason`), each reported with Laravel's `Failed` and then
  `AuthenticationFailed` (flow `sign_in`). A concealed reason (`account_rate_limited`, `code_expired`, `code_exhausted`,
  `passkey_counter_regressed`) reaches only the event; the result says `invalid_credentials`, with no wait. Exceptions
  are reserved for misconfiguration (an unknown method, a method that refuses with a reason that is not a sign-in method
  reason, an identity that is not an Eloquent model or does not implement `HasSessions`, an invalid session model, an
  `UnresolvableIdentityException`) and server errors. An identity without `HasSessions` is refused before it is admitted
  (in `signIn()`, after its slot was taken; in `start()`, before anything is written), because a bearer
  token names a session the guard can only find through that relation, so the session's access token would never
  authenticate. A `MachineIdentity` is the exception: it is let through to admission, which refuses it as a result
  (`machine_identity`), since a non-human identity has no session whatever it implements.
- No event ever receives the sign-in input. `Attempting` and `Failed` carry only `[type => identifier]` (or
  `['identifier' => ...]` for a method without a type, or nothing); `AuthenticationFailed` carries the identifier as
  given.
- `signIn()` order: the method is resolved (unknown throws); `Attempting`; the application policy must allow the method
  (`method_not_allowed`, nothing counted, no timebox); the attempt limiter must grant a slot (`rate_limited`); then, in
  the guard's credential timebox, cut short only for an admitted identity: the method verifies the input, the identity
  must not be a `MachineIdentity` (`machine_identity`) and must be active, and the application policy must admit it with
  the identifier type before any principal is resolved (`admitIdentifier()`; the package's finds the identifier verified
  where the guard requires it); a password is rehashed; then, outside the timebox (`SessionEstablishment::select()` and
  `proceed()`, over `PendingEvaluation`): the principals the identity may use the application as, read from the writer
  and each admitted (`Admission\PrincipalAdmission`), with none left the last one's refusal or `principal_unresolved`;
  the one the context names (`principal_mismatch` when it is not among them), or the only one, or none selected while a
  choice is outstanding; the proof of a session is checked; the identity-level additional-factor policy is asked, with
  no principal or tenant; a selected principal's active tenant is admitted (`Admission\TenantAdmission::select()`); that
  tenant's authentication policy is judged against the sign-in's own evidence in memory (`Tenancy\TenantPolicyCheck`,
  `SessionEvidence`: `sso_required` refuses, writing nothing; a further factor it lacks makes `mfa` outstanding); and
  the session is written active, recording the method, the policy's version, its identifier type and the tenant, or
  pending with its requirements. Only a session that starts active gives the slots back, those the method took on the
  accounts it checked included; a pending session keeps them all, their windows in its hidden `attempt_windows`, until
  it first activates (`SessionActivation`). The slots are written on `rate_limits.connection`, outside the session's own
  transaction but not outside a transaction the caller opened on that connection: with the default (`null`, the storage
  connection) a caller that rolls back around a sign-in rolls its counts back too, so its attempts go uncounted. Only
  counters on a connection of their own survive such a rollback. The slots are therefore given back only once the
  session commits on its connection and the guard is bound to it: a rollback leaves a first activation's session
  pending, and slots given back before it would be given back again when it activates. A release that fails then is
  reported to the exception handler, not thrown, the one limiter error that does not propagate: the session already
  stands, and Laravel runs a commit's callbacks in order without catching, so a throw would stop the later ones (another
  activation's events, the caller's own). The release stops at the failure, and the slots not given back stay counted. A
  handler that throws while reporting is not caught, as with Laravel's `rescue()`: an error that cannot be reported
  surfaces rather than vanishing.
- The steps `signIn()` and the guard's `attempt()` take the same way are `Sessions\CredentialAttempt`'s, which each
  calls in its own order: `checkMethod()` (the application policy's method check, before anything is counted), `begin()`
  (the slot on the identifier and IP limits, from the limiter the caller resolved after the method check), the account
  attempts the method's checks count against, `accountRefusal()` (`account_rate_limited`, with the account's wait),
  `windows()` for a pending session to keep and `release()` for an active one. Between the two, `attempt()` reads the
  identifier type, resolves the limiter and only then reads the identifier for the limits, once the method is allowed;
  `signIn()` resolves the limiter, its subject already built. What runs in the timebox and around it stays with each:
  `attempt()` fires `Validated` once the password is accepted, rehashes and asks the factor policy inside the timebox,
  cuts it short only for an admitted attempt and gives its slots back before the bind; `signIn()` cuts it short for an
  admitted identity, rehashes after it, continues to an active or a pending session, and gives its slots back after the
  bind of an active one.
- `start()` reloads the identity through the guard's provider and requires the same class and key (`identity_unknown`),
  then runs the method check, the identity's admission with no identifier type, and the same order from the principals
  on.
  It takes no slot and runs in no timebox: nothing is guessed. The principal is given as the argument or on the
  context, never both. A machine credential kind (`SignInMethodManager::CREDENTIAL_METHODS`) as the method is an
  `InvalidArgumentException` before anything else: a session recorded under `client_credentials` would pass for a
  client credentials token to every listener that reads the method.
- One `$now` per call, cut to the second, is used for the deadlines, the last use and every token's `iat`. The deadlines
  come from the application policy's lifetimes for the guard (`ApplicationPolicy::lifetimes($guard)`), which with the
  shipped policy are the guard's token service's (see `application-policy.md`), the absolute one capped at the
  context's own deadline (`SignInContext::$notAfter`, into which `signInExternally()` folds the provider's); a context
  whose deadline is `$now` or earlier is refused as `session_expired` before anything is written.
- Every sign-in creates a new session (D15): a new key, a new rotation id, both deadlines from `$now`. An active
  session is written in one transaction on the session's connection: the revocation of a proven session first, then the
  new session, then its proofs and its provenance, then both tokens, so any failure while issuing, or an insert a model
  event cancels (a `LogicException`), rolls all of it and the revocation back. Only the digest of the rotation id is
  stored. A pending session (`SessionWriter::createPending()`) is written the same way with `status = pending`, its
  `requires`, the digest of its pending credential's secret (`pending_key`), the proven session and the digest it was
  proven against (`supersedes_session_id`, `supersedes_refresh_key`), the slots' windows, no refresh digest, and an
  idle deadline that is the credential's expiry (`session.pending_ttl_seconds`, never past the absolute deadline); it
  revokes nothing and issues no token.
- What a sign-in proved travels as an internal `Proofs\SignInProof` from the moment it is verified to the session's
  first proofs: the method, the `FirstFactor` a sign-in method returned (its channel, observations and `amr` values,
  `mfa` refused) timed when it returned, or for `signInExternally()` the provider's (the connection, the private
  `urn:sinemacula:amr:external_provider` value, the provider's time, never after now) with the `Provenance` (the link's
  id included), or for `start()` an unattested one (unknown channel, no value, now). A pending session records it as its
  first proof when it is written, so the session records the time the credentials were verified. A `satisfy()`'s
  `ProofResult` is accepted only as `Proofs\ProofAcceptance::forPendingSession()` decides (an `additional_factor` or
  `recovery_code`, for `sign_in`, or `enrollment` for an `additional_factor`, accepted, timed between when the session
  began waiting and now: `proof_invalid`; bound to the pending session's identity, guard and id:
  `proof_binding_mismatch`); a refusal stores nothing and leaves the session pending.
- A refresh token proves a session only when it is the session's current rotation id, validly signed for the guard
  (`parseRefreshProof()`: every `parse()` check except expiry), and the session, read from the writer, is owned by the
  identity, records this guard and the same principal, and is not revoked. Anything else is no proof: a new session,
  nothing failed, revoked or reported. The IP address, user agent, client name and platform never count. The proof is
  the client's device key in this package's reading of D15: possession of the previous session's credential, the only
  one a client holds; no other key material exists. Passing it in `SignInContext::$refreshToken` is the application's
  opt-in (D21).
- Replacing a proven session (`SessionWriter::replace()`) revokes it with one compare-and-swap on the row exactly as it
  was proven (digest, owner, principal, guard, active, not revoked), writing `revoked_at`, the reason `superseded` and null
  digests as any revocation does, then inserts the new session as `create()` does, except that a client name or platform
  the sign-in does not give is the proven session's. The proven row keeps everything else. A swap that misses
  reconsiders the sign-in without the session, factor policy included: it creates a session and revokes nothing, or
  writes it pending when the factor policy now asks for a factor; it never retries. A pending session supersedes only at
  its first activation, with the same compare-and-swap on the digest it recorded; a miss there writes nothing and
  judges the session again without the proven one, factor policy included: it activates and revokes nothing, or stays
  pending when the factor policy now asks for a factor.
- After the session's transaction, `SessionRevoked` (`superseded`, for a replaced session), `SessionCreated` and
  `SignedIn` are scheduled, in that order and in one callback, on the commit of the session's connection; a second
  callback on the same commit then binds the guard, with the usual bind events, and only after the bind gives back the
  sign-in's slots (the attempt's, or the ones a first activation's pending sign-in held, which `SessionActivation`
  hands up on the `SignedInSession` rather than giving them back itself). A bind listener that throws therefore cannot
  withhold the reports and leaves the slots counted, and nothing of a rolled-back session is reported, bound or given
  back. The order holds by construction: `SessionEstablishment` (and `SessionActivation` for a pending session) writes
  the session, asks the factor policy and schedules those reports, and never binds; the service's `bound()` delivers
  the pair at once and schedules the bind, through `login()` on the `Contracts\GuardBinding` it was given, only once
  establishment has returned a signed-in result. A bind that waited for a commit (`Database\AfterCommit::defers()`)
  binds only while the guard still serves the request that signed in and the session, read again on the write
  connection, is still that one (generation and owner), of this guard, unrevoked, active and not ended; with no
  transaction open it binds at once, with no extra query. The bind is deferred because the factor package satisfies a
  pending session inside its own transaction, re-entrantly inside a passkey registration's too, and a refusal there
  must undo the bind with the writes. A refresh's and a switch's binds wait for the commit in the same way, through the
  same `Sessions\DeferredBind`, after the report each scheduled first (`Refreshed` and `SignedIn`, `PrincipalSwitched`),
  so the guard and the pair a caller attaches follow the commit wherever the call happens.
- The service holds no state between calls. It runs on the guard's context (`Runtime\GuardContext`), reading the
  provider, resolver, dispatcher and request, and the sign-in method manager and policies from the container, each time
  it needs them, and reaches the guard's bound state only through its binding; it names no `Guards` class. The guard
  neither builds nor holds one: `AuthManager::sessions()` builds a service on each call, from the guard's context and
  token service, with the guard as the binding, on the container's connections and transactions manager. A service
  handed out earlier therefore follows the guard's rebinds as a new one does.
- Acting on a pending session is `PendingSessions`' (`pending()`, `satisfy()`, `choose()`, `discard()`): it finds the
  session by its credential under the row's lock, re-runs the gate (`PendingEvaluation`) and activates it
  (`SessionActivation`) or leaves it waiting; the service binds an activated session as it binds any other. See
  `pending-sessions.md`.
- Ending sessions is not the service's own: `signOut()`, `signOutEverywhere()`, `revokeSession()`, `revokeSessions()`,
  `revokePrincipalSessions()` and the security-change methods delegate to `SessionRevocations` (see
  `session-lifecycle.md`), on the guard's context, with the guard as the `Contracts\GuardBinding` the two sign-out calls
  read and forget. The guard's `logout()` and the password writer use the same revocations without a session service.
- Refreshing is the service's too, beside switching principal or tenant: `refresh()` and `refreshFromRequest()` delegate
  to `SessionRefresh`, which runs the refresh exchange the service builds on the guard's context and token service,
  schedules `Refreshed` and `SignedIn` (a refresh) for the rotation's commit, and only then, at the same commit, binds
  the guard as a sign-in through the binding's `loginVerified()`, with the tenant and the sign-in method the exchange
  established. Every
  refusal is a failed `RefreshResult` with the exchange's or the transport's reason, `rate_limited` with its wait, never
  a thrown 429; `refreshFromRequest()` answers `null` only for a request without a token, and says where it read one
  (see `refresh-rotation-and-replay.md` and `refresh-token-transport.md`).

## Success Path

- A sign-in: `Attempting`, then, once committed (at once with no transaction open on the session's connection),
  `SessionCreated` and `SignedIn`, then `Validated`, `Login`, `Authenticated`, `PrincipalAssigned`,
  `SessionAuthenticated`. Inside a caller's transaction all of them follow its commit, in that order, while the result
  answers at once with the pair. The session's last use is the sign-in, so the shipped last-use listener writes nothing
  more.
- A sign-in that replaces a proven session: the same, with `SessionRevoked` (`superseded`) for the proven session just
  before `SessionCreated`. Its context has the guard, the sign-in's client, the identity, principal and tenant the
  sign-in admitted, the proven session and the method it records.
- `start()`: the same without `Attempting`.
- A sign-in whose session is written pending: `Attempting` (not from `start()`), then, once committed on its
  connection, `SessionPending` (a context of guard, identity, the principal and tenant once selected, proven session,
  method and client, what it requires and its expiry; never the credential), nothing bound and nothing revoked. Its
  first activation follows the sign-in path without `Attempting`, replacing the proven session only if it is still
  unchanged then; its discard is a revocation (`signed_out`, `SessionRevoked`), and a credential that discards nothing
  emits nothing.

## Failure / Edge Cases

- The slots a pending session keeps stay taken until it first activates, the one the method's check took on the
  account (`SignInRequest::reserveAccountAttempt()`) among them, and a discard or expiry leaves them counted, so each
  guess at a factor costs a sign-in attempt. For the password method the
  guesses are bounded by the account's one count, whatever spelling of the identifier or guard the sign-ins used, held
  to the most permissive `per_identifier` limit among the guards that check the account (see `application-policy.md`);
  for a method that counts no account, only by its identifier's and the IP address's limits. A pending session from
  `start()` or `signInExternally()` holds no slots (nothing was guessed), so its external verifier bounds it.
- An activation runs in the acting request's client: its events and the session's last use carry that client, while
  the session keeps the client the sign-in came from as its creation.
- Inside a caller's transaction the service's transaction is a savepoint: the lifecycle events, the bind and the
  give-back of the slots wait for the caller's commit, and a rollback withdraws all three with the session, leaving the
  guard unbound (and, unless the counters are on a connection of their own, the sign-in's attempts uncounted). A
  session the caller's transaction revokes or returns to pending after signing it in is not bound at the commit.
- A listener that throws on a bind event propagates after the session committed (inside a caller's transaction, from its
  commit): the session exists and the pair is lost, but `SessionCreated` and `SignedIn` were already dispatched, and the
  sign-in's slots stay counted. A listener that throws on `SessionCreated` or `SignedIn` with no transaction open
  propagates before the bind: the session stands, the guard is not bound, and `SignedIn` is not dispatched after a
  throwing `SessionCreated`.
- A session replaced by a sign-in is revoked: its access tokens stop at once and its refresh tokens are refused as
  `session_revoked`, so they cannot touch the new session (see `refresh-rotation-and-replay.md`). A listener on its
  `SessionRevoked` that throws stops `SessionCreated` and `SignedIn` and reaches the caller, while both rows stand.
- Two sign-ins presenting the same proof: the compare-and-swap lets one revoke the session; the other is reconsidered
  without the proof and creates a session revoking nothing. A refresh that rotates the session first makes the sign-in's
  swap miss; a sign-in that commits first makes the refresh fail as `session_revoked`. A bulk revocation racing a
  sign-in is not synchronised (see `session-lifecycle.md`).
- A crafted client name or platform is stored cleaned (`SignInContext`), so it cannot fail the insert.

## Implementation Anchors

- `src/Sessions/SessionService.php`: `signIn()`, `start()`, `pending()`, `satisfy()`, `choose()`, `discard()`,
  `bound()`;
  `src/Sessions/Concerns/EndsSessions.php`: the methods it delegates to `src/Sessions/SessionRevocations.php` (a trait
  only so the service stays within phpcs's limit of methods a class may declare);
  `src/Sessions/Concerns/RefreshesSessions.php`: `refresh()` and `refreshFromRequest()`, delegated to
  `src/Sessions/SessionRefresh.php` (a trait for the same reason), and `src/Sessions/RefreshResult.php`.
  `src/Sessions/Concerns/ProvesSessions.php`: `stepUp()` and `reauthenticate()`, delegated to
  `src/Sessions/SessionStepUp.php` and `src/Sessions/SessionReauthentication.php` over `src/Sessions/ProofIssuance.php`
  (see `proofs-and-freshness.md`).
- `src/Sessions/SessionEstablishment.php`: `select()`, `proceed()`, `establish()`, `wait()`, `write()`, `signedIn()`:
  the session, the factor policy and the scheduled reports, never the bind.
- `src/Sessions/DeferredBind.php`: the bind of a sign-in, a refresh and a switch once the session commits, and the
  re-read of a bind that waited.
- `src/Sessions/PendingEvaluation.php` (the gate), `src/Sessions/PendingSessions.php`,
  `src/Sessions/SessionActivation.php`, `src/Sessions/PendingTransitions.php`, `src/Sessions/PendingState.php`,
  `src/Sessions/PendingSession.php` and `src/Sessions/Enums/{PendingRequirement,PendingAction,SessionStatus}.php`.
- `src/Sessions/CredentialAttempt.php`: the method check, the slots and their give-back, shared with `attempt()`
  (`src/Guards/Concerns/SignsInWithCredentials.php`).
- `src/Sessions/SignInRequest.php` (`reserveAccountAttempt()`) and `src/RateLimiting/AccountAttempts.php`: the slots a
  sign-in's method takes on the accounts it checks, held with the sign-in's own.
- `src/Sessions/SessionWriter.php`: `create()`, `replace()`, `createPending()`, `record()` and the compare-and-swap.
- `src/Proofs/SignInProof.php`, `src/Proofs/ProofWriter.php`, `src/Proofs/ProofAcceptance.php`,
  `src/Proofs/FirstFactor.php` and the drivers' `authenticate()`: what a sign-in proves and how its session records it.
- `src/Sessions/ProvenSessions.php`, `src/Jwt/JwtTokenService.php` (`parseRefreshProof()`),
  `src/SessionRecords/SessionLookup.php`.
- `src/Sessions/SessionPreconditions.php`: the `HasSessions` refusal, and `start()`'s one-principal rule and
  reloaded-identity check.
- `src/Admission/SignInAdmission.php`, shared with `attempt()`; `src/Admission/PinnedPrincipal.php`.
- `src/Database/AfterCommit.php`, shared with the refresh exchange's revocation report.
- `src/AuthManager.php`: `sessions()`, which builds the service per call; `src/Guards/JwtGuard.php`: `tokens()`.

## Authoritative Tests

- `tests/Feature/Sessions/SessionServiceTest.php`, `tests/Unit/RateLimiting/AccountAttemptsTest.php`
- `tests/Feature/Contracts/CredentialAttemptMatrixTest.php`: every case of `signIn('password')` beside `attempt()`'s,
  with its answer, events, timebox, rehash and slots; `tests/Feature/Sessions/CredentialAttemptTest.php`
- `tests/Feature/Sessions/SessionEstablishmentTest.php`: establishment on its own (what it writes, returns and
  schedules, and that it never binds)
- `tests/Feature/Sessions/DeferredBindTest.php`: the bind on its own, at once with no query, at the commit, and never
  for another request, a rollback or a session changed before the commit
- `tests/Feature/AuthManagerTest.php`: the service built per call on the guard's context, binding and token service
- `tests/Feature/Sessions/SessionRefreshTest.php`, `tests/Unit/Sessions/RefreshResultTest.php`: the refresh, its events
  and bind, and every refusal returned
- `tests/Feature/Sessions/SessionRevocationsTest.php`, `tests/Feature/Sessions/ManagesSessionsTest.php`,
  `tests/Feature/Sessions/RevokesOnSecurityChangesTest.php`: the revocations on their own and through the service
- `tests/Feature/Sessions/SessionRoutesTest.php`: the documented sign-in and further-factor routes over HTTP, through
  `Auth::sessions()`, with tokens checked through `auth:api`
- `tests/Integration/Sessions/SessionServiceTest.php`
- `tests/Feature/Sessions/ProvenSessionsTest.php`, `tests/Feature/Sessions/SessionWriterTest.php`
- `tests/Feature/Sessions/PendingSessionsTest.php`, `tests/Integration/Sessions/ConcurrentPendingSatisfactionTest.php`
- `tests/Unit/Sessions/SessionPreconditionsTest.php`
- `tests/Integration/Sessions/SignInPolicyEndToEndTest.php`: the shipped application policy, attempt limiter,
  normalisers and verified-identifier gate, through `signIn()`, `start()` and `attempt()`
- `tests/Integration/Migration/SessionsTableSchemaTest.php`
- `tests/Feature/Proofs/SignInProofsTest.php`, `tests/Feature/Proofs/SignInProofTest.php`: the proofs and provenance
  each sign-in records, a satisfied further factor and every refusal of one, the choice carrying them across
- `tests/Performance/SessionServiceQueryBudgetTest.php`
- `tests/Feature/Contracts/EventSequenceTest.php`, `tests/Integration/Contracts/EventSequenceTest.php`: the event
  sequence of every sign-in, satisfaction, choice and discard, and around the session connection's transaction

## Change Triggers

Update this note when any of the following change:

- the order of the checks, or which of them count an attempt or run in the timebox
- which steps `Sessions\CredentialAttempt` shares between `signIn()` and `attempt()`
- what proves a session, or what replacing one writes, keeps or revokes
- what the session's transaction contains, or when the guard is bound, or what builds the service
- when `SessionRevoked` (`superseded`), `SessionCreated`, `SignedIn`, `SessionPending`, `SessionReturnedToPending` and
  `SessionActivated` are dispatched, or what they carry
- what reaches the events from the sign-in input
- what a pending session stores, how long its credential lives, what finds it, what it allows, or what activating it
  checks
- what a sign-in records as its proofs or provenance, or which proofs `satisfy()` accepts
- which of its methods it delegates to `SessionRevocations`, or what of the guard those need
- what a refresh returns, binds or reports, or what it delegates to `SessionRefresh`
