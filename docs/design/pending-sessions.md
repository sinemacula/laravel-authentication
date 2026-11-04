# Pending Sessions

## Purpose

This note records how a session waits for what its sign-in still owes: a further factor, a choice of principal, or
both. A pending session is a session row like any other, with a status, what it requires and a pending credential in
place of a token pair. It covers the record, the order a sign-in reaches it in, the actions its credential allows, how
`satisfy()` and `choose()` move it on and activate it, and how an active session returns to pending. How a sign-in is
checked before it gets here is in `session-service.md`; the choice of principal and the switch are in
`principal-choice-and-switch.md`; the tenant authentication policy that can hold a session back is in
`active-tenant-and-switching.md`.

## Invariants

- A session is `active` or `pending` (`status`, `Sessions\Enums\SessionStatus`); revocation stays `revoked_at` on
  either. A pending session lists what it waits on in order (`requires`: `mfa`, then `principal`), holds the digest of
  its pending credential's secret (`pending_key`) and, until it first activates, no refresh digest. Every row the
  package writes names its status; the column's default (`active`) only keeps a row written outside the package from
  reading as pending. A stored status or requirement outside its enum is a `LogicException`, never read as either.
- A pending session's idle deadline is its credential's expiry: `session.pending_ttl_seconds` from when it was issued
  (30 to 3600, default 300), never past the absolute deadline. An expired pending session has therefore ended by the
  same deadline rule as any session, so listing, pruning and every ended check need no condition of their own, and no
  separate expiry column exists. Activation restores the guard's idle lifetime.
- Nothing is pending by default: a session waits only when the identity-level factor policy asks for a factor, when an
  identity with several principals names none, or when the destination tenant's authentication policy asks for a
  factor the sign-in did not prove.
- The order, one pipeline for every sign-in: the credential is verified and the identity admitted
  (`session-service.md`); its principals are listed and each admitted (`PendingEvaluation::principals()`); one is
  selected (named, the only one, or none while a choice is outstanding); the identity-level factor policy is asked with
  no principal or tenant; for a selected principal, its tenant is admitted (`TenantAdmission::select()`) and that
  tenant's policy judged against the sign-in's own evidence in memory (`sso_required` refuses, writing nothing).
  `requires` is then `mfa` when the factor is owed, followed by `principal` when none is selected. With nothing required
  the session is written active; otherwise `SessionWriter::createPending()` writes it pending, with its first proof and
  provenance, in one transaction.
- The credential is `<session key>.<secret>`: the secret from `RefreshTokenHasher::generate()`, only its digest stored
  and compared in constant time. It is split at its last `.`, since the secret is base64url and has none, so a session
  model whose key holds a `.` is found by it. It is handed out once, in the result's body (`SignInResult::$credential`),
  never in a URL or a cookie, and it is not a JWT: no guard authenticates a request or a refresh with it, and only
  `pending()`, `satisfy()`, `choose()` and `discard()` read it. While a session is pending its access tokens are refused
  as `session_pending` (`OwnedSession::refusal()`), and its refresh token too, before any key comparison
  (`RefreshJudgment::classify()`), so a token presented while pending is never taken for a replay.
- A credential names a live pending session only while the session is this guard's, pending, unrevoked and before its
  idle deadline, the digest matches, the owner reloads through the guard's provider as the recorded one, and the
  principal it records, if any, resolves through the hinted path as that principal and is still owned
  (`PendingSessions::find()`). Anything else is "not found": `null` from `pending()`, `pending_invalid` from the rest,
  without saying why.
- The credential allows only the actions of the first outstanding requirement (`PendingRequirement::actions()`): the
  five `mfa.*` actions while the factor is owed, `list_principals` and `choose_principal` once only the choice is left.
  `pending($credential, $action)` answers `null` for any other, and `satisfy()` or `choose()` out of turn is
  `pending_action_not_allowed`. The `mfa.*` values follow the further-factor package's action names, spelt with this
  package's identifiers (`enrollment`), so the integration between the two maps them by case, not by value; whether a
  bootstrap enrolment applies is that package's to judge. `pending()` also answers `null` when the gate would refuse the
  identity, the method, or the principal and active tenant the session records (below, `PendingEvaluation::recorded()`),
  so nothing is sent or enrolled for a session that can never activate.
- `satisfy()` and `choose()` run in one transaction on the session's connection that locks the row, finds the credential
  again under the lock, and rolls back on any refusal, so a refused proof is never stored, a refused choice records
  nothing, and no refusal revokes the session: it waits until its credential expires, and only `discard()` ends it
  early (`signed_out`).
- Each runs the gate again under the lock: the identity (not a machine identity, active, `admitIdentifier()` with the
  recorded identifier type), the recorded method still allowed, the recorded or chosen principal admitted
  (`PrincipalAdmission::refusal()`) and its tenant (`TenantAdmission::recorded()` with the access check, or `select()`
  at the choice), the identity-level factor policy's requirement against the stored proofs (`RequirementJudge`, through
  the bound `RequirementCheck`), and the tenant's policy against the session's own proofs and provenance, read current
  (`SessionProofs`: on MySQL and MariaDB a shared lock, so a proof committed or voided before the action is judged as
  it now stands, whatever the caller's transaction read first). Nothing that changed while the session waited is
  skipped. Once the action is admitted, the session the sign-in's client proved it holds, when there is one an
  activation may supersede, is read locked for update, before `satisfy()`'s issuance guard and proof and before any
  read of the pending session's proofs, so the supersede takes no session row after a proof row; `pending()` reads it,
  and the proofs, plainly.
- `satisfy()` accepts a proof only as `ProofAcceptance::forPendingSession()` decides: an `additional_factor` or a
  `recovery_code`, for `sign_in` (or `enrollment` for an `additional_factor`, a bootstrap enrolment's confirming proof),
  accepted, timed no earlier than when the session began waiting (the later of its start and `switched_at`) and no
  later than now (`proof_invalid`), and bound to the session's owner, the guard and the session's key
  (`proof_binding_mismatch`). Each accepted call stores one proof, also when the session stays pending: a verification
  is single use on the further-factor package's side.
- `choose()` takes the principal (`principal_mismatch` when it is not the identity's own, resolved through the hinted
  path) and the tenant the call names or the principal's own. Its tenant's policy asking for connections refuses that
  principal alone (`sso_required`, nothing recorded, the session left pending for another choice); asking for a factor
  records the principal and tenant and leaves the session waiting on `mfa` with the same credential.
- `SessionActivation::activate()` writes the active state with one compare-and-swap under the lock on `status =
  pending` and the digest: `status = active`, `requires` and `pending_key` cleared, the principal and `tenant_id`, a new
  rotation id, a fresh idle deadline, the last use and the policy version answered, and only then issues the pair, for
  the tenant the row now records. The first activation (no refresh digest yet) supersedes the proven session with a
  compare-and-swap on the digest it recorded and `status = active` (a miss writes nothing, and `settle()` judges the
  session again without the proven session, since the factor policy may have waived the factor for it), clears the kept
  slots' windows, hands the slots up with the activated session for the service to give back once it has bound the
  guard after the commit, and schedules `SessionRevoked` (`superseded`), `SessionCreated` and `SignedIn`; a later one,
  of a session that returned to pending, moves `switched_at` (`SwitchFloor::after()`) and schedules `SessionActivated`.
  The session keeps its key throughout, so the proofs and provenance written while it waited carry over unchanged.
- `PendingTransitions::returnToPending()` takes an active session back to pending, recording the destination its caller
  admitted, when a refresh or a switch finds the tenant's policy asking for a factor the session lacks, or the factor
  package's removal of a factor, or an addition to its factors (`factorChanged()`), leaves the session short of the
  identity's requirement or its tenant's (`Sessions\FactorRevocations`, flow `factor_change`, with the outstanding
  requirement): one compare-and-swap on the row as the caller loaded it (`status = active`, unrevoked, refresh digest,
  principal, `tenant_id`, policy version and both deadlines) that writes a new pending credential, `requires = ["mfa"]`,
  the destination's principal and tenant, `switched_at` by `SwitchFloor::after()` and the credential's expiry as the
  idle deadline. It keeps the refresh digests, which stay refused as `session_pending` until the session activates with
  a new rotation id; from its commit every access token of the session is refused. `SessionReturnedToPending` follows
  the commit. A connection requirement never returns a session to pending: no action could meet it. The session's first
  factor is read once: the tenant's verdict carries the one it was judged on, and `PendingTransitions::firstFactorOf()`
  hands that to the identity-level judgement (`outstanding()`) and to the pending session, reading the session's own
  only when the verdict asked for no further factor.

## Success Path

1. `signIn()` for an identity whose factor policy asks for a factor writes the session pending on `mfa` and dispatches
   `SessionPending` once committed; the result `isPending()`, with its `PendingSession` and the credential.
2. The further-factor package checks `pending($credential, PendingAction::VERIFY)` before it verifies, then calls
   `satisfy($credential, $proof)`: the proof is stored, the gate finds nothing left, and the session activates, the
   guard is bound and the result is signed in, under the session's original key.
3. For an identity with several principals, the same sign-in waits on `mfa` and then `principal`: `satisfy()` moves it
   on to the choice, listing the principals, and `choose()` activates it as the principal chosen.
4. Later, a refresh whose tenant now asks for a factor returns the session to pending (`RefreshResult::pending()`), and
   `satisfy()` activates it again, dispatching `SessionActivated`; every access token from before the return stays
   refused.

## Failure / Edge Cases

- Two `satisfy()` calls on one credential serialise on the row's lock: one activates, and the other finds the session
  active and is `pending_invalid`. A `discard()` racing either wins or loses the same way.
- A `satisfy()` or `choose()` that locks the pending session and then the older one it proved, and a
  `tenantPolicyChanged()` that locks the tenant's sessions in key order, can deadlock; the database fails one, for its
  caller to roll back and retry whole.
- A return to pending that loses its compare-and-swap is judged again from the reloaded row, as a lost rotation is, so a
  concurrent rotation, switch, revocation or return applies and the other is refused or retried, never both.
- A pending idle deadline can equal the active one near the absolute cap, so only `status` tells the two apart in a
  compare-and-swap; every swap that changes an active session's refresh or context state carries `status = active`.
- An activation and a return to pending in one second: the floor moves one second past the recorded one, so every token
  from before the return is refused, at the cost of a refresh for the activation's own tokens once that second is over.
- A principal or tenant deactivated, a method withdrawn, an identifier left unverified, or a factor newly required while
  the session waits: the next `satisfy()` or `choose()` is refused with its reason and the session stays pending.
- A further-factor requirement from a tenant with no `RequirementCheck` bound fails closed: the default check meets
  nothing, so the session never activates in that tenant until a further-factor package binds its check.

## Implementation Anchors

- `src/Sessions/PendingSessions.php`: `pending()`, `satisfy()`, `choose()`, `discard()`, `find()`, `admitted()`,
  `chosen()`, `settle()`.
- `src/Sessions/PendingEvaluation.php`: the gate's building blocks (`identityRefusal()`, `allowsMethod()`,
  `principals()`, `selection()`, `named()`, `destination()`, `recorded()`, `owedFactor()`, `tenantPolicy()`,
  `requirements()`).
- `src/Sessions/SessionEstablishment.php` and `src/Sessions/SessionWriter.php` (`createPending()`, over
  `src/Sessions/PendingSessionDraft.php`); `src/Sessions/PendingState.php` (the TTL, the expiry, the raw writes).
- `src/Sessions/SessionActivation.php`: `activate()`; `src/Sessions/PendingTransitions.php`: `returnToPending()`;
  `src/SessionRecords/SwitchFloor.php`: `after()`.
- `src/Sessions/PendingSession.php`, `src/Sessions/ReturnedToPending.php`, `src/Sessions/Enums/SessionStatus.php`,
  `src/Sessions/Enums/PendingRequirement.php`, `src/Sessions/Enums/PendingAction.php`.
- `src/Proofs/ProofAcceptance.php`: `forPendingSession()`; `src/SessionRecords/OwnedSession.php`: `refusal()`;
  `src/Jwt/RefreshJudgment.php`: `classify()`.
- `src/Concerns/RecordsSessionStanding.php` and `src/Contracts/EloquentSessionStanding.php`: the record's columns.
- `src/Events/SessionPending.php`, `src/Events/SessionReturnedToPending.php`, `src/Events/SessionActivated.php`.

## Authoritative Tests

- `tests/Feature/Sessions/PendingSessionsTest.php` (the actions per requirement, an unknown, expired, revoked,
  other-guard or tampered credential, every acceptance refusal, activation, moving on to the choice, a bootstrap
  enrolment proof, a recovery code, the gate's refusals, the proven session and its lock, the current reads, the slots,
  discard)
- `tests/Feature/Sessions/PendingTransitionsTest.php` (a return to pending, its compare-and-swap, the version it
  records, its event)
- `tests/Feature/Sessions/PendingEvaluationTest.php` (the gate's checks on their own) and
  `tests/Feature/Sessions/SessionActivationTest.php` (an activation's compare-and-swap and what it writes)
- `tests/Feature/Sessions/TenantAuthenticationPolicyTest.php` (a tenant's factor or connections at sign-in, at the
  choice, at activation and at refresh)
- `tests/Feature/Sessions/SessionSwitchTest.php` `testADestinationAskingForAFactorReturnsTheSessionToPendingUntilItIsMet`
- `tests/Feature/Proofs/ProofAcceptanceTest.php`, `tests/Unit/Sessions/PendingSessionTest.php`,
  `tests/Unit/Sessions/PendingStateTest.php`, `tests/Unit/Sessions/Enums/PendingRequirementTest.php`,
  `tests/Unit/Traits/RecordsSessionStandingTest.php`, `tests/Unit/SessionRecords/SwitchFloorTest.php`
- `tests/Integration/Sessions/ConcurrentPendingSatisfactionTest.php` (two calls on one credential) and
  `tests/Integration/Sessions/ConcurrentPendingLocksTest.php` (satisfy, discard and the policy-change helper waiting on
  one another's row lock, on PostgreSQL and MySQL)
- `tests/Integration/Sessions/ReplicaPendingSessionsTest.php` (pending, satisfy and the choice on a lagging replica)
- `tests/Integration/Sessions/IntegerKeyPendingSessionTest.php` and
  `tests/Integration/Sessions/DottedKeyPendingSessionTest.php` (a credential naming an integer key, and a key that
  holds a `.`)
- `tests/Integration/Sessions/SeparateCounterConnectionActivationTest.php` (the slots an activation gives back with
  the counters on a connection of their own: on commit, not on rollback, a failed release reported)
- `tests/Integration/Jwt/RefreshTokenExchangeTest.php` (a refresh's return to pending and its revocation racing a
  rotation, a revocation and a switch of tenant)
- `tests/Integration/Sessions/CurrentProofReadsTest.php` (`satisfy()` and `choose()` never counting a proof another
  connection voided after the caller's first read)
- `tests/Integration/Migration/SessionsTableSchemaTest.php` (the columns and their lengths)

## Change Triggers

Update this note when any of the following change:

- the columns a pending session records, or how its credential is built, stored or found
- the sign-in order that decides whether a session starts pending, or what `requires` holds
- the actions each requirement allows
- the gate `satisfy()` and `choose()` run, or what a refusal leaves behind
- what activation or a return to pending writes, or their compare-and-swap predicates
- what `SessionPending`, `SessionReturnedToPending` or `SessionActivated` carry, or when they are dispatched
