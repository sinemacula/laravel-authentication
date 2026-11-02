# Session Lifecycle

## Purpose

This note records what happens to a session after it starts: which sessions count as active and how an
identity's sessions are listed, how sessions are signed out (by the access token or the refresh credential) and
revoked, and when a session that ended is deleted. Starting a session is in
`session-service.md`; refresh rotation and replay are in `refresh-rotation-and-replay.md`.

## Invariants

- A session is active while `revoked_at` is null, `idle_expires_at` is after now, and `absolute_expires_at` is after now
  or `null` (no absolute deadline): a deadline has passed from the second it names, as on the bearer, refresh and
  sign-in pin paths (`SessionDeadlines::hasEnded()`). The `active()` scope `ActsAsSession` brings and the listing apply
  the same rule through `ActiveSessions::constrain()`, with the columns of the model's name accessors, so a model
  without the trait is listed the same way.
- The listing (`SessionService::sessions()`, from `EndsSessions`) reads the identity's `sessions()` relation on the
  write connection (the query itself through `WriteConnection::query()`, and anything the relation reads while it is
  built inside `WriteConnection::during()` for the identity), so a revocation the primary holds is never listed as live.
  It covers every guard: a session list shows every session the identity has.
- The order is total on every database: last use, most recent first, with never-used sessions last (an explicit
  `CASE ... IS NULL` term, because PostgreSQL sorts nulls first in a descending order and MySQL and SQLite last), then
  the key, newest first. Pages are therefore stable.
- A `SessionSummary` never holds a digest, the rotation time, a revocation column, the owner or the principal; `current`
  compares the listed session with the guard's bound session by class and identifier.
- `session($identity, $id)` (`LooksUpSessions`, `ActiveSessions::find()`) gets one session as the list shows it, or
  `null`: one query under the list's rule on the writer, none for an id that cannot be a key (`callers.md`).
- Revoking marks the session (`revoked_at`, `revoked_reason`, both digests cleared) with one conditional `UPDATE ...
  WHERE pk AND revoked_at IS NULL` on the session's own connection (`RefreshRotationStore::revoke()`), mirrored in
  memory only when it changed the row. It is idempotent, the first revocation's time and reason are kept, and only the
  call that changed the row reports `SessionRevoked`, through `AfterCommit` on the session's connection.
- Sign-out, revocation and the security changes are `Sessions\SessionRevocations`, on the guard's context; the session
  service's methods delegate to it, and `JwtGuard::logout()` and the password writer use it without a session service.
  Only `signOut()` and `signOutEverywhere()` read or change the guard's bound state, through the
  `Contracts\GuardBinding` they are given, whose readers resolve the request's credential on first access.
- `signOut()` (and `JwtGuard::logout()`) revokes the guard's bound persisted session as `signed_out`, then dispatches
  `Logout` when an identity was bound, then `forgetUser()`. A session that is not an Eloquent `EloquentSession` is only
  forgotten.
- `signOutFromRequest()` (`Sessions\SessionSignOut`) signs out by whichever credential the request carries, so a client
  whose access token has expired, or that holds none, can still sign out. A guard bound to a stored session through its
  access token is `signOut()`, and the refresh credential is not read. Otherwise any binding is forgotten first (an
  access-only token's, with `Logout`), and the refresh credential is read through the application's transport and proven
  by `RefreshProof::prove()`: the exchange's checks with its reasons (`token_invalid`, `session_unknown`,
  `session_guard_mismatch`, `session_revoked`, `session_pending`, `session_expired`, `refresh_key_missing`,
  `session_principal_mismatch`), short of rotating, counting attempts, admitting the owner or asking the tenant policy.
  The token names its principal by identifier alone, and only the owner's admission resolves its type, so the proof
  compares the identifier with the recorded one: a token from before a switch to a principal of another class with the
  same identifier still signs its session out inside the grace window (the same token revokes it as a replay once the
  window closes), while a refresh, a switch and the caller of a refresh credential refuse it, since they admit the
  owner and compare the type too. A replay revokes its session as `rotation_reuse`, as the exchange does, so reuse
  detection covers every path that accepts a refresh token. The proven session is revoked as `signed_out`
  (`SessionRevoked` once committed), `Logout` fires for its owner when the guard's provider still returns it and none
  fired already, and a binding to it is forgotten. A refusal is reported by `AuthenticationFailed` with the flow
  `sign_out`, never by `Failed`; no attempt limit applies (nothing is issued, a token cannot be guessed, revoking is the
  safe direction). A cookie application's `SignOutResult` carries the expired cookie when the access token signed its
  session out, and otherwise only for a request that passes the cookie's same-site checks and was not refused as
  `refresh_token_conflict`: a cross-site page that auto-submits a form to the logout route (sending no `SameSite=Strict`
  cookie, but able to have the response's cookie kept) clears nothing, and a refused request leaves the cookie with the
  session it still proves. `signOutWith($token)` proves and revokes the same way for a token a body application's code
  read, but forgets no other binding: a guard bound to another session stays bound to it, whether the token is refused
  or proves another session. A cookie application throws a `LogicException`.
- A sign-out by refresh credential races a rotation without a lock, as the exchange does: a token rotated in between is
  the previous one inside the grace window and still proves the session, and the conditional revocation means two
  sign-outs, or a sign-out and a replay, revoke and report once.
- `revokeSession()` reads the session through the owner's `sessions()` relation on the writer
  (`IdentitySessions::find()`), with the key-shape check first, so another identity's session is "not found" (`false`)
  and never revealed.
- A bulk revocation (`revokeSessions()`, `revokePrincipalSessions()`, `signOutEverywhere()`, and the security-change
  methods) is a list of `RevocationScope`s: (1) each scope's `HasTokensValidAfter` cutoff moved to `$now` on its own
  connection; (2) one transaction on the storage connection, which the session model must live on, that reads each
  scope's unrevoked sessions on the writer in key order (`lazyById`, chunks of 500), revokes each conditionally (pending
  sessions among them) and, for an identity's scope whose identity implements
  `HasChangeableIdentifiers`, its pending identifier changes (by key, every type with a registered normaliser: a change
  link needs no session, so one requested from a session that ends must end with it); (3) once committed,
  `SessionRevoked` per revoked session, then `SignedOutEverywhere` per scope, also when it revoked none. A failure in
  (2) leaves (1) in place: fail-safe, and a retry is idempotent.
- An identity's scope is every session its `sessions()` relation returns, of every guard; a principal's is every session
  of the configured model whose principal columns record it. An identity without `HasSessions` can hold no
  session, pending or active (no session starts for it), so its scope, and that of a principal whose owner (read
  afresh on the writer through `WriteConnection::stored()`, whatever relation is loaded and in strict mode too) is such
  an identity, reads and deletes nothing and only moves the cutoff: access-only mode needs none of the package's tables
  to revoke. A principal whose owner cannot be read has its sessions looked for anyway; an unsaved principal has no
  sessions. A principal scope's events carry that owner as their identity.
- `signOutEverywhere(keepCurrentSession: true)` keeps the request's session; a request without one (a session-less
  token) is kept by leaving the identity's cutoff unmoved, so the identity's other session-less tokens survive too,
  until they expire.
- The security-change methods (`passwordChanged()`, `passwordReset()`, `credentialRemoved()`, `factorReset()`,
  `identityDeactivated()`, `principalDeactivated()`, `tenantDeactivated()`) are bulk revocations with their own reason;
  `factorRemoved()` is one too, before it judges the current session again (`Sessions\FactorRevocations`).
  `tenantDeactivated()` checks every listed principal acts within the tenant (`getTenant()` on the writer, through
  `WriteConnection::stored()`, so a `tenant` relation whoever loaded the principal set does not decide and Eloquent's
  strict mode does not stop the read; same class and identifier; for a `CanBeActive` tenant that can no longer be
  loaded, the class and key the `TenantUnavailableException` carries, so a deleted or soft-deleted one still ends its
  principals' sessions; a tenant without `CanBeActive` reads as no tenant once it cannot be loaded, so the application
  calls it before deleting one) before anything is written, de-duplicates by recorded type and id, and ends all of them
  in one transaction on the session connection, with one `SignedOutEverywhere` each. `factorRemoved()` and
  `factorReset()` are mandatory: no setting turns them off, and the factor package calls them synchronously inside the
  transaction that makes its change (a savepoint here, reported after the outermost commit), never through a listener;
  each forgets the request's binding once it commits, before anything is reported, when the binding is to a session it
  ended or took back to pending (`factorRemoved()` with a current session) or to the identity (`factorReset()`, and
  `factorRemoved()` with none, since both end every session of it, through `GuardBinding::forgetIdentity()`).
  `credentialRemoved()` stays per event, the optional listener's or the application's.
- `connectionDisabled()`, `connectionDeleted()` and `linkRemoved()` (`Sessions\ConnectionRevocations`, through
  `Concerns\EndsConnectionSessions`) revoke the live sessions, pending ones included, of every guard that a connection
  established (a link's: only that identity's), found 500 at a time (a connection's through the provenance connection
  index, a link's through the identity's own sessions), each chunk locked in key order and revoked in one transaction.
  A connection's chunks follow the session keys' own order (an integer key's numeric one, though the provenance holds
  it as a string), so its locks are taken in one key order across chunks. After the commit the request's binding to any
  session ended is forgotten (`GuardBinding::forgetSession()`), then one `SessionRevoked` reports each, so a listener
  that throws cannot leave the binding. They move no cutoff, since the scope is the provenance rather than the
  identity, and each can be turned off under `authentication.revocation.*` (`Sessions\RevocationSettings`), which
  `authentication:check` validates.
- The optional listeners (`RevokeSessionsOnPasswordReset`, `RevokeSessionsOnPasswordChange`,
  `RevokeSessionsOnDeactivation`) run their revocation through `AfterCommit` on the changed model's connection, so a
  rolled-back change revokes nothing. They act through a jwt guard's session service: the guard bound to the
  listener's `$guard`, else the current default guard when it is a jwt guard, else the first jwt guard configured, so a
  route guarded by another driver (`shouldUse()`) still revokes; no jwt guard at all is an `InvalidArgumentException`.
- The password-change observer ignores a save of the user the container's scoped `Sessions\Methods\Rehashing` marks, and
  a save is a rehash only when it re-encodes the password signed in with: both the previous hash (the model's original,
  which Eloquent has not yet synced in `updated`) and the saved hash verify it (the hasher's `check()`; a hash it
  refuses to check is a change). Two rehashes are marked: the one `PasswordSignIn::rehash()` runs through the provider,
  for its identity and password (cleared in `finally`) until a change of that identity's password runs inside it, and
  the one `SessionGuard::attempt()`, `attemptWhen()` and `once()` run through an Eloquent user provider on the instance
  a guard validated during a credential attempt, from Laravel's `Validated` until that guard's `Login`, `Authenticated`
  or `Failed` carrying that instance (`Listeners\TrackCredentialAttempts`, registered by the provider). No event
  separates `attemptWhen()`'s callbacks from that rehash, so a save inside the bracket counts as the rehash only when it
  saves that instance (compared by its weak reference) for the user validated, with the attempt's `password` credential,
  and no change of the user's password has run since: a callback that saves another password revokes, and from then on
  so does every save of the user, a change back to the attempt's password through any instance included. A save taken
  for a rehash is held, not dropped, one per user (the latest), for `OtherDeviceLogout`, which
  `SessionGuard::logoutOtherDevices()` dispatches after its forced rehash, to run (a change like any other). A listener
  of the save may end or make attempts, or change the password in a transaction it rolls back, before that event, so
  nothing else lets go of a save held for an attempt: it is kept until the request or job ends, and a sign-out later in
  the same request or job runs it too, revoking twice. The package's own rehash holds its save only while it runs, so a
  forced rehash inside it (a listener of its save calling `logoutOtherDevices()`) still revokes, and then holds again
  the save held before it, which a forced rehash around it may be waiting for. The forced rehash is so answered as a
  change even inside an attempt's callback or after an attempt that threw after `Validated` and never ended. A
  `Validated` outside an attempt (`validate()`), or a second one within it, marks nothing. Each guard keeps its open
  attempts innermost last, since an `attemptWhen()` callback may attempt again on the same guard: an attempt's end
  closes the innermost attempt that validated the event's instance (or no one), so a nested attempt's `Login` and
  `Authenticated`, or a session or remember-me user resolved inside the callback, leave the outer attempt open for its
  own rehash. Two cases end the outer attempt early, and its rehash then revokes: an `Auth::login()` of its own instance
  inside its callback, and a refused inner attempt that validated that same instance (a provider that caches its users).
  An attempt that threw never ends, so a new attempt of the guard first lets go of every attempt that cannot be running
  around it (its instance is gone or its user's password changed, or it validated no one or was made without a
  password), and a validation lets go of the guard's earlier attempts for the same instance, so a long-running command
  keeps at most one attempt per guard and instance still held; an instance stays held while a save of it is held, so
  what a command keeps grows with the accounts it rehashes. Users are keyed as `AccountAttempts::account()` keys
  accounts (connection, database, prefixed table and key for a model), so the same key in another tenant's database is
  another user. The deactivation observer throws a `LogicException` for a deactivated model that is neither identity nor
  principal: a tenant's deactivation is `tenantDeactivated()`. With both password listeners registered, a broker reset
  is recorded as `password_changed` (the observer sees the save before the application fires `PasswordReset`).
- The provider registers `Listeners\TrackCredentialAttempts` for every application, observer or not, because the
  observer cannot switch it on: `observe()` and `#[ObservedBy]` pass through no package code, and the attribute
  registers the observer only when the model first boots, inside the guard's `retrieveByCredentials()`, after
  `Attempting` carried the password. Tracking that starts with the observer, or an opt-in beside it that can be left
  out, would leave that attempt's rehash revoking. Without the observer the tracking costs no query and no hash check:
  it keeps each open attempt's password, wrapped in a `SensitiveParameterValue`, until the attempt ends (or the request
  or job, for one that threw), and only the observer's `unlessRehash()` checks a hash.
- Pruning (`PrunesSessions`, with Laravel's `model:prune`) deletes a session revoked, or past either deadline, at or
  before now less `authentication.session.prune_after_days`: counted from the end of the session, never from creation.
  Each chunk is one conditional `DELETE`; nothing is read first.
- A pruned session is indistinguishable from an unknown one: its tokens already failed once it was revoked or ended, so
  retention never changes who authenticates.

- `tenantPolicyChanged($tenant)` (`Sessions\TenantPolicyChanges`) is the synchronous revocation for a tenant
  authentication policy that changed: in one transaction on the session model's connection (a savepoint inside the
  caller's), it reads the live sessions (unrevoked, before both deadlines) whose `tenant_id` is the tenant's, every
  guard, pending ones included, in key order 500 at a time with a locking read; skips one recorded at the very version
  answered (neither `null`); revokes an active one that falls short, and a pending one only when it needs another
  connection, as `tenant_policy_changed` with a conditional update on `tenant_id` and `revoked_at IS NULL`; and records
  the version on an active one that meets it. `SessionRevoked` follows each revocation's commit. A session that enters
  the tenant after the scan is bounded by its first refresh, which always asks the policy.

## Success Path

- `Auth::sessions('api')->sessions($identity, 20)` costs a count and a select and returns a `LengthAwarePaginator` of
  `SessionSummary`, whose JSON uses snake_case keys and ISO-8601 times.
- `model:prune --model=...Session` deletes ceil(N / chunk) chunks and ends with one `DELETE` that finds nothing.

## Failure / Edge Cases

- A sign-in already past its credential check when a bulk revocation reads the sessions can still create its session
  afterwards: closing that window would need a lock every sign-in and revocation take on the identity row, which is not
  added. A sign-in that replaces a proven session races a bulk revocation the same way, with no synchronisation added:
  when the revocation reads the proven session first, it is revoked with the bulk reason, the replacement's swap misses
  and the sign-in still creates its session; when the sign-in commits first, the proven session is already `superseded`
  (skipped as revoked) and the new session is revoked if the bulk read finds it. A pending session the bulk call revoked
  cannot activate (`pending_invalid`). Holding sign-ins back during a security change belongs to mandatory, synchronous
  revocation on security changes, which the package does not do yet. Revocation races with refresh, switch and
  re-sign-in are safe: each of their compare-and-swaps requires `revoked_at IS NULL`, so one revocation of a row,
  sign-out or `superseded`, wins and the other changes nothing.
- An exception between `logoutOtherDevices()`'s forced save and its `OtherDeviceLogout` (Laravel saves, queues the
  remember cookie, then dispatches), or an earlier listener of that event stopping it, leaves a save held for a rehash
  unrun, so that forced rehash revokes nothing; the observer relies on Laravel's event to tell it apart.
- A page size outside 1 to 100 is an `InvalidArgumentException` before any read. An identity without `HasSessions`, or a
  `sessions()` relation over a model that is not an `EloquentSession`, is a `LogicException`.
- A retention that is not an integer (or canonical digit string) from 0 to 3650 is an `InvalidArgumentException` when
  pruning runs. With 0, a session is pruned from the second it ends.
- `PrunesSessions` composes `MassPrunable` and replaces its `prunable()`; using `MassPrunable` beside it is a PHP trait
  collision, so a custom model uses `PrunesSessions` alone. A global scope on the model still narrows pruning: the three
  conditions are grouped.
- A pending session can remember a session that is pruned before it first activates; its activation then supersedes
  nothing.
- Queued listeners of an event about a pruned session cannot re-fetch it.

## Implementation Anchors

- `src/Sessions/ActiveSessions.php`, `src/Sessions/SessionSummary.php`, `src/Sessions/Concerns/EndsSessions.php`
  (`sessions()`)
- `src/Concerns/ScopesActiveSessions.php` (`scopeActive()`, composed by `ActsAsSession`),
  `src/Concerns/PrunesSessions.php`, `src/Database/SessionRetention.php`, `src/Models/Session.php`
- `src/Sessions/SessionRevocations.php` (the security changes), `src/Listeners/RevokeSessionsOn*.php`,
  `src/Listeners/Concerns/RevokesOnceCommitted.php`, `src/Sessions/Methods/Rehashing.php`,
  `src/Listeners/TrackCredentialAttempts.php`
- `src/Sessions/SessionSignOut.php`, `src/Sessions/RefreshProof.php`, `src/Sessions/SignOutResult.php`,
  `src/Sessions/Concerns/LooksUpSessions.php`
- `src/Sessions/SessionRevocations.php`, `src/Sessions/RevocationWriter.php`, `src/Sessions/RevocationScope.php`,
  `src/SessionRecords/IdentitySessions.php`, `src/Jwt/RefreshRotationStore.php` (`revoke()`), `src/Guards/JwtGuard.php`
  (`logout()`), `src/Contracts/GuardBinding.php`, `src/Guards/AbstractGuard.php` (`forgetUser()`)

## Authoritative Tests

- `tests/Feature/Sessions/ActiveSessionsTest.php`: the session list over HTTP behind `auth:api`;
  `tests/Feature/Sessions/ScopesActiveSessionsTest.php`: the `active()` scope
- `tests/Integration/Sessions/SessionListingIntegrationTest.php`,
  `tests/Integration/Sessions/ReplicaSessionListingTest.php`
- `tests/Unit/Sessions/SessionSummaryTest.php`
- `tests/Feature/Sessions/ManagesSessionsTest.php`: logout, sign out everywhere and a session list's revoke over HTTP
- `tests/Feature/Sessions/SessionRevocationsTest.php`: the revocations without a session service, the binding they are
  given, the dispatcher a deferred report reaches, and `logout()` through them alone
- `tests/Integration/Http/RefreshCookieSessionLifecycleTest.php`: logout from outside the refresh cookie's path revokes
  the session and clears the cookie
- `tests/Feature/Sessions/SessionSignOutTest.php`, `tests/Feature/Sessions/RefreshProofTest.php`,
  `tests/Unit/Sessions/SignOutResultTest.php`, `tests/Integration/Sessions/SessionSignOutTest.php`,
  `tests/Performance/SessionSignOutQueryBudgetTest.php`: sign-out by refresh credential
- `tests/Feature/Sessions/LooksUpSessionsTest.php`: one session, as the list shows it
- `tests/Integration/Sessions/ConcurrentSwitchAndRevocationTest.php`: two revocations in two processes on PostgreSQL
  and MySQL report each session once, after a commit and after a rollback
- `tests/Integration/Sessions/SecurityChangeEndToEndTest.php`: each security-change listener's revocation refused at
  the `auth` middleware and at refresh, and a session guard's rehash, under an observer `#[ObservedBy]` registers
  inside the attempt, leaving the session working
- `tests/Feature/Sessions/RevocationWriterTest.php`, `tests/Integration/Sessions/RevocationWriterTest.php`,
  `tests/Integration/Sessions/SeparateConnectionRevocationWriterTest.php`,
  `tests/Integration/Sessions/RevocationScopeTest.php`, `tests/Feature/Sessions/RevocationScopeTest.php`,
  `tests/Integration/Sessions/ManagesSessionsTest.php`
- `tests/Performance/SessionRevocationQueryBudgetTest.php`
- `tests/Feature/Sessions/RevokesOnSecurityChangesTest.php`,
  `tests/Integration/Sessions/ReplicaRevokesOnSecurityChangesTest.php`,
  `tests/Feature/Listeners/RevokeSessionsOn*Test.php`, `tests/Unit/Sessions/Methods/RehashingTest.php`,
  `tests/Feature/Listeners/TrackCredentialAttemptsTest.php`, `tests/Feature/Sessions/Methods/RehashingAccountsTest.php`,
  `tests/Integration/Process/QueueWorkerRehashingTest.php`, `tests/Performance/RehashingBudgetTest.php`
- `tests/Feature/Models/PrunesSessionsTest.php`, `tests/Feature/Database/SessionRetentionTest.php`,
  `tests/Integration/Models/SessionPruningIntegrationTest.php`
- `tests/Performance/SessionListingQueryBudgetTest.php`, `tests/Performance/SessionPruneQueryBudgetTest.php`

## Change Triggers

Update this note when any of the following change:

- what makes a session active, or which columns decide it
- which security change ends which sessions, or what the optional listeners react to
- what a revocation writes, which sessions a scope covers, what a bulk revocation ends besides sessions, or when and in
  which order it reports
- what a session summary holds, the listing's order, page bounds or connection
- what a sign-out by refresh credential checks, revokes or reports
- what pruning selects, how retention is counted or configured, or how a custom model opts in
