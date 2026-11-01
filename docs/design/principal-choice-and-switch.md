# Principal Choice and Switch

## Purpose

This note records how a session comes to act as one principal of an identity that may act as several: a sign-in that
names none, for an identity with several, waits pending for the identity to choose (`pending()`, `choose()`), and a
live session moves to another principal
(`switchPrincipal()`). Starting a session is in `session-service.md`; the refresh judgement both paths share is in
`refresh-rotation-and-replay.md`; the bearer checks that end the old principal's tokens are in `fail-closed-pid-did.md`.

## Invariants

- A choice is offered only by `signIn()` and `start()`, only when no principal is named and the identity has more than
  one admitted principal: with one, that one is selected; with none, the sign-in fails with the last one's refusal or
  `principal_unresolved`, after the credential was verified. `attempt()` never offers one.
- Admitted principals (`PendingEvaluation::principals()`, and `SessionService::principals()` for a switch screen) are
  the identity's `principals()` read on the write connection (the resolver's default for an identity that is its own
  principal or has no `principals()`), each admitted by `Admission\PrincipalAdmission` (active, in an active tenant,
  allowed to use the application) with the sign-in's identifier type, so a principal the policy refuses is neither
  offered nor listed. `principals($identity, $identifierType)` lists the same way given the type the session records,
  so it lists only targets the application policy lets that session switch to.
- Each principal read with the others is checked on a stored copy (`WriteConnection::stored()`): Eloquent strict mode
  prevents lazy loading on models read together, and the activity check (and any application policy that reads it) reads
  its tenant. The list holds the principals as read.
- Every sign-in asks the application policy's `admitIdentifier()` before any principal is resolved or listed
  (`SignInAdmission`), so with the package's policy a guard requiring a verified identifier refuses an unverified one
  as `identifier_unverified` whether the identity has principals or not, and the answer never tells someone holding an
  unverified identity's password whether it has been invited anywhere. A policy that wraps the package's keeps this by
  asking the wrapped `admitIdentifier()`. Which principals may use the application is `ApplicationAccess`'s answer,
  asked only once a principal resolves, so for an identity with none the sign-in answers `principal_unresolved`.
- A choice is a pending session (see `session-service.md`) whose `requires` holds `principal` and which records no
  principal. The identity-level factor policy is asked before any choice, so a required factor comes first (`mfa`, then
  `principal`), and no principal is listed or chosen while it is outstanding (`pending_action_not_allowed`).
- `choose()` runs under the session's row lock in one transaction rolled back on any refusal, so a refused choice
  leaves the session pending for another. It admits the identity and the method again, resolves the chosen principal
  through the hinted path as the very one named and owned (`principal_mismatch`), admits it, and admits the tenant the
  call names or the principal's own (`Admission\TenantAdmission::select()`); then asks the factor policy again: a
  factor it now asks for records the principal and tenant and leaves the session waiting on `mfa`, with the same
  credential; otherwise the session activates as the principal. The proven session is replaced (revoked as
  `superseded`) at the first activation only when it is still the one proven and records the chosen principal;
  otherwise it is left as it is. Offering or discarding the choice revokes nothing else.
- The attempt slots a sign-in took stay counted while it waits for a choice and are given back only once the session
  first activates.
- A switch is proven by the session's refresh token, never an access token, and judged by `RefreshJudgment::classify()`
  as a refresh is: the refresh limits (counted against the token's session and the client's IP address), the guard, a
  live session, and the rotation id. A replayed id revokes the session as `rotation_reuse`.
- Every path of a switch, the retry included, runs every live check: the owner reloaded through the guard's provider
  and active (`RefreshAdmission`), the target resolved through the hinted path, of the target's class and owned by the
  owner as read from the principal's own key (`principal_mismatch`), active, its tenant active, admitted by the
  application policy, the session's method allowed, the identity and then the target admitted again with the type of
  identifier the session's sign-in used (the session's `sign_in_identifier_type`, written with `sign_in_method` at every
  sign-in; a session whose sign-in used none is not held to one, and a session loaded without the column throws a
  `LogicException` rather than reading as one that used none) so a principal a policy refuses to that identifier cannot
  be reached by switching, and no further factor asked (`additional_factor_required`).
- With the current rotation id, the token's `principal` must be the principal the session records
  (`session_principal_mismatch`). The absolute deadline stays the session's, held to `signed_in_at` plus the guard's
  absolute lifetime (`session_expired` when that has passed), so a lifetime shortened or set since the sign-in applies
  and a switch never extends the session or lifts its deadline; a session with no absolute deadline under a guard with
  no absolute limit keeps none. The idle deadline restarts under the guard's lifetimes. Both tokens are issued for
  the target before the write, and end at the restarted idle deadline.
- The switch is one compare-and-swap (`RefreshRotationStore::switchPrincipal()`) on the presented digest, an unrevoked
  row, both loaded deadlines and the loaded principal columns. It writes the rotation, both deadlines and, when the
  principal changes, the target and `switched_at` (`SessionRecords\SwitchFloor`). A switch to the recorded principal
  writes no switch.
- With the previous rotation id inside the grace window, the current credential is reissued for the target, writing
  nothing, only when the session records the target and either its last rotation was a switch
  (`switched_at = refresh_rotated_at`) or the token's own `principal` is the target; anything else is
  `rotation_conflict`, without revoking.
- A missed swap re-reads the row with a lock and judges it once: a still-current id is `rotation_conflict`, a previous
  id is answered by the retry rule against the row as it now is (after the owner is checked again), and anything else
  fails for its reason, a replay (`rotation_reuse`) revoking the session as a first judgement does. There is never a
  second swap.
- `SessionPending` and `PrincipalSwitched` are dispatched through `AfterCommit` on the session model's connection.
  `PrincipalSwitched` carries the session's recorded previous morph class and identifier and the previous principal only
  when the hinted path still returns that very principal (same type and identifier).

## Success Path

1. `signIn()` verifies the identity, finds several principals and none named, and writes the session pending on
   `principal`: `SessionPending` follows the commit, and the result `isPending()`, listing the principals.
2. `pending($credential, PendingAction::LIST_PRINCIPALS)` lists them again; `choose($credential, $principal)` activates
   the session as it, scheduling `SessionCreated` and `SignedIn` for the session's commit before it binds the guard
   (`Validated`, `Login` and the bind events), and the slots are given back after the commit. With no transaction open
   on the session's connection that is `SessionCreated`, `SignedIn`, then `Login`; inside a caller's transaction the
   bind events come first, and the pair follows its commit or is dropped on a rollback.
3. Later, `switchPrincipalFromRequest($other)` (or `switchPrincipal($refreshToken, $other)` with a token read by the
   caller) rotates the session to the other principal and schedules `PrincipalSwitched` for the commit on the session's
   connection before it binds the guard to it (`Authenticated`, `PrincipalAssigned`, `SessionAuthenticated`), so a bind
   listener that throws cannot withhold the report. With no transaction open there `PrincipalSwitched` is dispatched at
   once, before the bind events; inside a caller's transaction the bind events come first, and it follows the commit or
   is dropped on a rollback. The previous principal's access tokens fail on the bearer path as
   `session_principal_mismatch` from then on.

## Failure / Edge Cases

- A lost switch response: the client retries with the old token inside the grace window and receives the current
  credential for the target, with no second `PrincipalSwitched`. Presented to the session service's `refresh()`, the
  same token fails as `session_principal_mismatch` without revoking.
- A switch racing a refresh of the same token loses the swap and fails as `rotation_conflict`; two identical switches
  both answer with the target's credential; two switches to different principals leave the first; a switch racing a
  revocation fails as `session_revoked`.
- A previous principal that no longer resolves (deleted, or recorded under a type the morph map no longer uses) is
  reported by its snapshot only.
- A choice whose identity no longer resolves through the guard's provider is no choice (`pending()` returns `null`,
  `choose()` fails as `pending_invalid`).
- The comparison of the expiry against `$now` reads the absolute deadline; the idle deadline is never later, so the
  two readings agree.

## Implementation Anchors

- `src/Sessions/SessionService.php`: `principals()`, `pending()`, `choose()`, `switchPrincipal()`,
  `switchPrincipalFromRequest()`, `switched()`, `previousPrincipal()`; a chosen session is activated by
  `src/Sessions/PendingSessions.php` (`choose()`) over `src/Sessions/SessionActivation.php` and then bound by the
  service.
- `src/Sessions/PendingEvaluation.php`: `principals()`, `selection()`, `named()`, `destination()`, `owesFactor()`.
- `src/Sessions/PrincipalSwitch.php`: one switch, built per call; `switch()` (the limiter), `switchOn()`, `admit()`,
  `isTarget()`, `switchCurrent()`, `rotateTo()`, `retry()`, `afterLostSwitch()`, `deadlines()`.
- `src/Jwt/RefreshRotationStore.php`: `switchPrincipal()` and `reload()`.
- `src/Jwt/RefreshJudgment.php`: `classify()`, shared with the refresh exchange.
- `src/Sessions/ProvenSessions.php`: `provenSessionOf()`, which proves a session without a principal for a choice.
- `src/Events/SessionPending.php`, `src/Events/PrincipalSwitched.php`, `src/Sessions/PendingSession.php`,
  `src/Sessions/SwitchResult.php`, `src/SessionRecords/SwitchFloor.php`.

## Authoritative Tests

- `tests/Feature/Sessions/PendingSessionsTest.php` (a choice offered and listed, the factor before it, a choice
  refused and made again, a factor asked after it, the proven session, the slots, discard)
- `tests/Feature/Sessions/PrincipalSwitchTest.php` (the switch over HTTP, the old access token refused at once,
  A -> B -> A, the old refresh token inside and after the grace window, the lost response retried, every refusal, a
  switch read from the request and the transport's refusals, and a switch screen's listing)
- `tests/Integration/Sessions/PrincipalSwitchTest.php` (the switch racing a refresh, a revocation, an identical switch,
  a different switch, a deadline change, a deletion and an owner change, and a swap lost to a refresh with no grace
  window or to two refreshes, which revokes the session)
- `tests/Integration/Sessions/ConcurrentSwitchAndRevocationTest.php` (on PostgreSQL and MySQL, two processes: a switch
  waiting on a revocation, on a refresh of its token and on an identical switch, after a commit and after a rollback)
- `tests/Integration/Applications/ReplicaChoicesAcrossConnectionsTest.php` (the principals read on the write
  connection)
- `tests/Feature/Jwt/RefreshRotationStoreTest.php` `testSwitchPrincipalRecordsTheTargetAndMirrorsIt`,
  `testSwitchPrincipalMissesAfterAChangeSinceTheSessionWasLoaded`
- `tests/Integration/Http/RefreshCookieSessionLifecycleTest.php` (a switch proven by the refresh cookie, its
  cross-site checks, and the rotated cookie)
- `tests/Performance/PrincipalSwitchQueryBudgetTest.php` (seven reads and one write per switch, from the request
  too; six reads and no write per grace retry; the counters' writes alone for a refusal, and their read alone when
  rate-limited; the reads, the counters' writes and the insert of a sign-in left pending on a choice, the reads of a
  choice listed, and the reads and writes of a choice made; and a time ceiling for switches, retries and refusals)

## Change Triggers

Update this note when any of the following change:

- when a choice is offered, which principals are admitted, or what a pending choice records
- the checks a switch runs, the order it runs them in, or the retry rule for the previous rotation id
- the switch's compare-and-swap predicate or the columns it writes
- how the deadlines of a switched session are derived
- what `SessionPending` or `PrincipalSwitched` carry, or when they are dispatched
