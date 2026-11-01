# Principal Choice and Switch

## Purpose

This note records how a session comes to act as one principal of an identity that may act as several: a sign-in that
names none, for an identity with several, waits pending for the identity to choose (`pending()`, `choose()`), and a live
session moves to another principal, another active tenant, or both (`switchTo()`). Starting a session is in
`session-service.md`; the refresh judgement both paths share is in `refresh-rotation-and-replay.md`; the bearer checks
that end the tokens issued before a switch are in `fail-closed-pid-did.md`; the access contracts that decide the
destination tenant are in `application-policy.md`; the pending session a choice waits as, and a switch's return to
pending, are in `pending-sessions.md`; the active tenant and the tenant authentication policy are in
`active-tenant-and-switching.md`.

## Invariants

- A choice is offered only by `signIn()` and `start()`, only when no principal is named and the identity has more than
  one admitted principal: with one, that one is selected; with none, the sign-in fails with the last one's refusal or
  `principal_unresolved`, after the credential was verified. `attempt()` never offers one.
- Admitted principals (`PendingEvaluation::principals()`, and `SessionService::principals()` for a switch screen) are
  the identity's `principals()` read on the write connection (the resolver's default for an identity that is its own
  principal or has no `principals()`), each admitted by `Admission\PrincipalAdmission` (active, in an active tenant,
  allowed to use the application by `ApplicationAccess`), so a principal it refuses is neither offered nor listed. The
  identifier type gates the identity, not each principal: given one, `admitIdentifier()` is asked first and, when it
  refuses, nothing is listed (not even which principals there are) and its reason is returned. `principals()` given the
  identifier type the session records lists the same way, so it lists nothing for a session the application policy would
  no longer let switch. `TenantAccess` is not asked when listing: the tenant a listed principal acts in is known only
  once a selection names it, at the sign-in or the choice.
- Each principal read with the others is checked on a stored copy (`WriteConnection::stored()`): Eloquent strict mode
  prevents lazy loading on models read together, and the activity check (and any application policy that reads it) reads
  its tenant. The list holds the principals as read.
- Every sign-in asks the application policy's `admitIdentifier()` before any principal is resolved or listed
  (`SignInAdmission`), so with the package's policy a guard requiring a verified identifier refuses an unverified one
  as `identifier_unverified` whether the identity has principals or not, and the answer never tells someone holding an
  unverified identity's password whether it has been invited anywhere. A policy that wraps the package's keeps this by
  asking the wrapped `admitIdentifier()`. Which principals may use the application is `ApplicationAccess`'s answer,
  asked only once a principal resolves, so for an identity with none the sign-in answers `principal_unresolved`.
- A choice is a pending session (see `pending-sessions.md`) whose `requires` holds `principal` and which records no
  principal. The identity-level factor policy is asked before any choice, so a required factor comes first (`mfa`, then
  `principal`), and no principal is listed or chosen while it is outstanding (`pending_action_not_allowed`).
- `choose()` runs under the session's row lock in one transaction rolled back on any refusal, so a refused choice leaves
  the session pending for another. It admits the identity and the method again, resolves the chosen principal through
  the hinted path as the very one named and owned (`principal_mismatch`), admits it, and admits the tenant the call
  names or the principal's own (`Admission\TenantAdmission::select()`); then judges that tenant's authentication policy,
  whose connection requirement refuses this principal alone (`sso_required`, nothing recorded), and asks the factor
  policy again: a factor either asks for records the principal and tenant and leaves the session waiting on `mfa`, with
  the same credential; otherwise the session activates as the principal. The proven session is replaced (revoked as
  `superseded`) at the first activation only when it is still the one proven and records the chosen principal; otherwise
  it is left as it is. Offering or discarding the choice revokes nothing else.
- The attempt slots a sign-in took stay counted while it waits for a choice and are given back only once the session
  first activates.
- A switch is proven by the session's refresh token, never an access token, and judged by `RefreshJudgment::classify()`
  as a refresh is: the refresh limits (counted against the token's session and the client's IP address), the guard, a
  live session, and the rotation id. A replayed id revokes the session as `rotation_reuse`.
- A switch names its destination with a `SwitchTarget`: another principal of the identity, in the tenant selected for it
  or its default (its own), or another tenant for the principal the session records (`SwitchTarget::tenant()`).
- Every path of a switch, the retry included, runs every live check: the owner reloaded through the guard's provider and
  active (`RefreshAdmission::admitPrincipal()`), the destination principal (the target, or the recorded one for a
  tenant-only switch) resolved through the hinted path, of the target's class (or the recorded principal) and owned by
  the owner as read from the principal's own key (`principal_mismatch`), active, its own tenant active, allowed the
  application by `ApplicationAccess` (`principal_ineligible`), the session's method allowed, the identity and then the
  destination admitted again with the type of identifier the session's sign-in used (the session's
  `sign_in_identifier_type`, written with `sign_in_method` at every sign-in; a session whose sign-in used none is not
  held to one, and a session loaded without the column throws a `LogicException` rather than reading as one that used
  none) so a principal a policy refuses to that identifier cannot be reached by switching, and the destination tenant
  admitted by `TenantAdmission::select()` (`TenantAccess` and, for a tenant other than the principal's own,
  `TenantResolver`: `tenant_ineligible`; inactive: `tenant_inactive`). The identity-level additional-factor policy is
  not asked.
- With the current rotation id, the token's `principal` must be the principal the session records
  (`session_principal_mismatch`). Then the destination tenant's authentication policy judges the session against its own
  proofs and provenance (`TenantPolicyCheck::check()`, outside any transaction): connections the session was not
  established through refuse the switch (`sso_required`, nothing written); a further factor the session lacks returns it
  to pending with the destination recorded (`PendingTransitions::returnToPending()`, flow `switch`), a missed
  compare-and-swap there judged as a missed switch swap is. A return forgets a binding of the guard to the session
  (`GuardBinding::forgetSession()`, no event), as a refresh's return does, so nothing later in the request acts in the
  context it left.
- The absolute deadline stays the session's, held to `signed_in_at` plus the guard's absolute lifetime
  (`session_expired` when that has passed), so a lifetime shortened or set since the sign-in applies and a switch never
  extends the session or lifts its deadline; a session with no absolute deadline under a guard with no absolute limit
  keeps none. The idle deadline restarts under the guard's lifetimes. Both tokens are issued for the destination before
  the write, name the destination tenant, and end at the restarted idle deadline.
- The switch is one compare-and-swap (`RefreshRotationStore::switchSession()`) on the presented digest, an active
  (`status = active`) unrevoked row, both loaded deadlines, the loaded principal columns, `tenant_id` and
  `tenant_policy_version`. It writes the rotation, both deadlines and the policy version answered and, when the
  principal or the tenant changes (`RefreshRotationStore::contextChanges()`, read from the row as loaded), the
  destination principal, `tenant_id` and `switched_at` by `SwitchFloor::after()` (the switch's second, or one second
  after a `switched_at` already at it), so every access token issued before it is refused (`session_tenant_mismatch`,
  `session_principal_mismatch`, `session_switched`). A switch to the recorded principal and tenant writes no switch. The
  session's key does not change, so its proofs and provenance carry over unchanged.
- With the previous rotation id inside the grace window, the current credential is reissued for the destination, writing
  nothing, only when the session records the destination principal and tenant and either its last rotation was a switch
  that changed them (`switched_at` not before `refresh_rotated_at`: a switch in a second the floor already reached
  writes the floor past the rotation, see `SessionRecords\SwitchFloor`) or the token's own `principal` is the
  destination; anything else is `rotation_conflict`, without revoking. The destination tenant's policy is asked again
  on a retry, as a refresh with the same token asks it (the rotation that opened the window may have been a refresh, or
  the policy may have changed since): `sso_required` refuses the retry and leaves the session alone, and a further
  factor the session lacks returns it to pending, a return that loses its swap answered `rotation_conflict`.
- A missed swap re-reads the row with a lock and judges it once: a still-current id is `rotation_conflict`, a previous
  id is answered by the retry rule against the row as it now is (after the owner is checked again), and anything else
  fails for its reason, a replay (`rotation_reuse`) revoking the session as a first judgement does. There is never a
  second swap.
- `SessionPending` and `PrincipalSwitched` are dispatched through `AfterCommit` on the session model's
  connection. `PrincipalSwitched` is dispatched only when the principal or the tenant changed; it carries the session's
  recorded previous morph class and identifier, the previous tenant's identifier, which of the two changed, and the
  previous principal only when the hinted path still returns that very principal (same type and identifier), or the
  principal itself on a tenant-only switch.

## Success Path

1. `signIn()` verifies the identity, finds several principals and none named, and writes the session pending on
   `principal`: `SessionPending` follows the commit, and the result `isPending()`, listing the principals.
2. `pending($credential, PendingAction::LIST_PRINCIPALS)` lists them again; `choose($credential, $principal)` activates
   the session as it, scheduling `SessionCreated` and `SignedIn` for the session's commit before it binds the guard
   (`Validated`, `Login` and the bind events), and the slots are given back after the commit. With no transaction open
   on the session's connection that is `SessionCreated`, `SignedIn`, then `Login`; inside a caller's transaction the
   bind events come first, and the pair follows its commit or is dropped on a rollback.
3. Later, `switchFromRequest(SwitchTarget::principal($other))` (or `switchTo($refreshToken, $target)` with a token read
   by the caller) rotates the session to the other principal, in its own tenant unless one is named, or with
   `SwitchTarget::tenant()` to another tenant, and schedules `PrincipalSwitched` for the commit on the session's
   connection before it binds the guard to the destination in the destination tenant (`Authenticated`,
   `PrincipalAssigned`, `SessionAuthenticated`), so a bind listener that throws cannot withhold the report. With no
   transaction open there `PrincipalSwitched` is dispatched at once, before the bind events; inside a caller's
   transaction the bind events come first, and it follows the commit or is dropped on a rollback. Every access token
   issued before the switch fails on the bearer path from then on.

## Failure / Edge Cases

- A lost switch response: the client retries with the old token inside the grace window and receives the current
  credential for the destination, with no second `PrincipalSwitched`. Presented to the session service's `refresh()`,
  the same token fails as `session_principal_mismatch` without revoking.
- A switch racing a refresh of the same token loses the swap and fails as `rotation_conflict`; two identical switches
  both answer with the destination's credential; two switches to different principals leave the first; a switch racing a
  revocation fails as `session_revoked`; a switch whose session changed tenant or policy version under it fails as
  `rotation_conflict`.
- Two context changes in one second: the second records `switched_at` one second after the first, so the tokens it
  issues are refused until the client refreshes after that second; no token issued before it is ever revived.
- A previous principal that no longer resolves (deleted, or recorded under a type the morph map no longer uses) is
  reported by its snapshot only.
- A choice whose identity no longer resolves through the guard's provider is no choice (`pending()` returns `null`,
  `choose()` fails as `pending_invalid`).
- The comparison of the expiry against `$now` reads the absolute deadline; the idle deadline is never later, so the
  two readings agree.

## Implementation Anchors

- `src/Sessions/SessionService.php`: `principals()`, `pending()`, `choose()`, `switchTo()`, `switchFromRequest()`,
  `switched()`, `previousPrincipal()`; a chosen session is activated by `src/Sessions/PendingSessions.php`
  (`choose()`) over `src/Sessions/SessionActivation.php` and then bound by the service.
- `src/Sessions/PendingEvaluation.php`: `principals()`, `selection()`, `named()`, `destination()`, `owesFactor()`.
- `src/Sessions/SessionSwitch.php`: one switch, built per call; `switch()` (the limiter), `switchOn()`, `admit()`,
  `admitAsDestination()`, `isDestination()`, `switchCurrent()`, `underPolicy()`, `toPending()`, `rotateTo()`, `retry()`,
  `afterLostSwitch()`, `deadlines()`; `src/Sessions/SwitchTarget.php` and `src/Sessions/SwitchedPrincipal.php`.
- `src/Jwt/RefreshRotationStore.php`: `switchSession()`, `contextChanges()` and `reload()`;
  `src/SessionRecords/SwitchFloor.php`: `after()`.
- `src/Jwt/RefreshJudgment.php`: `classify()`, shared with the refresh exchange.
- `src/Sessions/ProvenSessions.php`: `provenSessionOf()`, which proves a session without a principal for a choice.
- `src/Events/SessionPending.php`, `src/Events/PrincipalSwitched.php`, `src/Sessions/PendingSession.php`,
  `src/Sessions/SwitchResult.php`, `src/SessionRecords/SwitchFloor.php`.

## Authoritative Tests

- `tests/Feature/Sessions/PendingSessionsTest.php` (a choice offered and listed, the factor before it, a choice
  refused and made again, a factor asked after it, the proven session, the slots, discard)
- `tests/Feature/Sessions/SessionSwitchTest.php` (the switch over HTTP, the old access token refused at once, A -> B ->
  A, the old refresh token inside and after the grace window, the lost response retried, every refusal, a switch read
  from the request and the transport's refusals, a switch screen's listing, a tenant-only switch and one of both,
  switching back to a tenant, two switches in one second, the destination tenant's refusals, the proofs kept, and the
  identity-level factor policy not asked)
- `tests/Integration/Sessions/SessionSwitchTest.php` (the switch racing a refresh, a revocation, an identical switch, a
  different switch, a deadline change, a tenant or policy version change, a deletion and an owner change, and a swap
  lost to a refresh with no grace window or to two refreshes, which revokes the session)
- `tests/Integration/Sessions/ConcurrentSwitchAndRevocationTest.php` (on PostgreSQL and MySQL, two processes: a switch
  waiting on a revocation, on a refresh of its token and on an identical switch, after a commit and after a rollback)
- `tests/Integration/Applications/ReplicaChoicesAcrossConnectionsTest.php` (the principals read on the write
  connection)
- `tests/Feature/Jwt/RefreshRotationStoreTest.php` `testSwitchSessionRecordsTheDestinationAndMirrorsIt`,
  `testSwitchSessionRecordsAChangeOfEitherAlone`, `testSwitchSessionToTheRecordedDestinationOnlyRotates`,
  `testSwitchSessionMovesTheFloorPastASwitchInTheSameSecond`,
  `testSwitchSessionMissesAfterAChangeSinceTheSessionWasLoaded`,
  `testContextChangesCompareTheDestinationWithTheLoadedSession`
- `tests/Integration/Http/RefreshCookieSessionLifecycleTest.php` (a switch proven by the refresh cookie, its
  cross-site checks, and the rotated cookie)
- `tests/Performance/SessionSwitchQueryBudgetTest.php` (eight reads and one write per switch, from the request
  too; seven reads and no write per grace retry; the counters' writes alone for a refusal, and their read alone when
  rate-limited; the reads, the counters' writes and the insert of a sign-in left pending on a choice, the reads of a
  choice listed, and the reads and writes of a choice made; and a time ceiling for switches, retries and refusals)

## Change Triggers

Update this note when any of the following change:

- when a choice is offered, which principals are admitted, or what a pending choice records
- the checks a switch runs, the order it runs them in, or the retry rule for the previous rotation id
- what a destination's tenant policy does to a switch or a choice
- the switch's compare-and-swap predicate or the columns it writes
- how the deadlines of a switched session are derived
- what `SessionPending` or `PrincipalSwitched` carry, or when they are dispatched
