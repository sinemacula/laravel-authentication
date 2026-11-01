# Proofs and Freshness

## Purpose

This note records how a session keeps the proofs it was established and kept with, how an access token's `auth_time`
and `amr` are derived from them, how a session steps up and reauthenticates without becoming a new session, and how the
freshness of a session's authentication is judged for a sensitive operation. The proofs are evidence a session holds;
the token's claims and every freshness answer are worked out from them, never stored in their place.

## Invariants

- A proof is a row in `proofs.table`, on the storage connection, belonging to a session's key: its kind
  (`first_factor`, `first_factor_reauthentication`, `external_reauthentication`, `additional_factor`,
  `recovery_code`), method, channel, factor reference, observed properties (each `null` when not observed, which never
  counts as true), evaluation, `amr` values, time and binding (identity, application, session, purpose). A proof is
  never changed once recorded; a voided one never counts, and a further factor or recovery code counts only when its
  adapter accepted it.
- Every session the package writes records a counting first factor in the transaction that writes the session; an
  external provider's session also records its provenance, once. Proofs and provenance carry unchanged from a pending
  sign-in to its session and across every refresh and switch of principal; a sign-in that replaces a session starts a
  new session with its own.
- Every read of proofs is of the session's own: those recorded under its key and bound to its guard and its owner (the
  morph type and key the session records), so another identity's or application's proof under the same key never
  counts for it. The key, guard, owner and `amr` columns compare byte for byte (a binary collation on MySQL and
  MariaDB, whose default ones ignore case and accents), so a key, owner or value that differs only in those is another.
  A sign-in deletes every proof and provenance recorded under its new session's key before it records its own
  (`ProofWriter::clear()`), so a key the database issues again (an integer key whose counter a truncation reset, after
  the sessions were deleted without their proofs) inherits nothing, the same identity's proofs included. It finds them
  with a plain read on the write connection and deletes by their own keys only what it found: a delete that matches
  nothing would lock the last gap of the proofs' and the provenance's indexes on MySQL, where every new time-ordered key
  falls, and two sign-ins holding that lock while inserting their own proofs would deadlock. The plain read sees the
  transaction's snapshot, so on MySQL at REPEATABLE READ a sign-in inside an application's transaction whose first
  plain read predates the orphans' commit misses them; deleting a session's rows with it is the guarantee, this the
  second line.
- Every read of proofs is on the write connection and bounded: the claims read one aggregate query grouped by kind,
  `amr` set and multifactor report (`SessionProofs::history()`), and freshness reads the newest proof a requirement
  takes with `LIMIT 1` on the session, kind and time index (`SessionProofs::newestMeeting()`), so a session with many
  step-ups costs what one with few does.
- `auth_time` is the newest time of any counting proof. `amr` is the values of the first factor, the further factors and
  the recovery codes, once each, in the order of their newest times and then of their values; `mfa` is added only when
  a further factor's or recovery code's evaluation reported multifactor authentication, never worked out from the
  values, and a proof may not record it itself. A reauthentication of either kind renews `auth_time` and adds no value.
  A session with no counting first factor issues no token (a `LogicException`).
- A step-up (`SessionService::stepUp()`) and a reauthentication (`reauthenticate()`) share `Sessions\ProofIssuance`:
  in one transaction on the session's connection, the session's row is locked; the session must exist, be this guard's,
  live and a person's; the operation's own check runs on the locked row; the session is admitted again as a refresh
  admits it; the proof is recorded and one access token issued, its claims derived with the new proof included. The
  refresh token, the deadlines and the session row are untouched, so a concurrent refresh's compare-and-swap is
  unaffected, and nothing is bound to the request.
- A step-up takes only an `additional_factor` or a `recovery_code`, accepted, made for `step_up`, no later than now and
  no earlier than the session started (`proof_invalid`), bound to the session's owner, this guard and the session's key
  (`proof_binding_mismatch`). A reauthentication runs an allowed, non-machine sign-in method under the `sign_in` limits
  and the credential timebox, and the identity it verifies must be the session's owner (`invalid_credentials`
  otherwise); its proof is `first_factor_reauthentication`, made now.
- Freshness is `Contracts\FreshnessPolicy`'s: a requirement per operation and application (proof kinds, maximum age of
  1 to 86400 seconds, multifactor, phishing resistance), the stricter of the configured one and the caller's, and the
  newest proof meeting it. The default, `Freshness\ConfiguredFreshness`, reads `authentication.freshness` and a guard's
  `freshness` block (an entry wins whole; `null` removes it) on every call, keeps no state, and reads the session again
  by key on the write connection, requiring it live for its guard, before reading its proofs; it reads nothing when the
  operation has no requirement. An operation with no requirement, or two requirements with no kind in common, is never
  fresh. The latest `auth_time` never stands in for the proof that meets a requirement.
- An identifier change proves a recent authentication with the `identifier_change` operation: a session proof must be
  one of the identity's live sessions of the guard, as stored, and the policy must find a proof for it; inside the
  change's transaction both are checked again on the session's locked row, which the change judges itself, since the
  policy's own read takes no lock; a password proof is a first-factor
  reauthentication made now and is taken only when the requirement takes `first_factor_reauthentication` and asks for
  neither multifactor authentication nor phishing resistance.

## Success Path

1. A sign-in records the first factor its method returned (`FirstFactor`), or `start()` records the external
   provider's with its provenance; a completion records the further factor it was given.
2. Every access token issued for the session (`signIn()`, a refresh, a switch, a step-up, a reauthentication) asks
   `Proofs\AuthenticationClaims::forSession()` for its `auth_time` and `amr`.
3. A further-factor adapter verifies a factor on a signed-in session and hands its `ProofResult` to `stepUp()`: the
   proof is recorded, a new access token issued, `SteppedUp` dispatched once committed.
4. A client proves its first factor again through `reauthenticate()`: the attempt is counted and verified, the proof
   recorded, a new access token issued with `auth_time` renewed, `Reauthenticated` dispatched once committed.
5. Before a sensitive operation, the caller asks `FreshnessPolicy::freshProof($session, $operation)` and acts only on a
   proof; a caller that acts atomically locks the session first, checks the locked row is still live itself (the
   policy's own read takes no lock, so a transaction may serve it from an earlier snapshot), and asks inside its
   transaction.

## Failure / Edge Cases

- A step-up or a reauthentication refused for any reason is an `AccessTokenResult` with the reason and an
  `AuthenticationFailed` (flow `step_up` or `reauthentication`), never an exception; a concealed reason is answered as
  `invalid_credentials`, with no wait.
- A revocation that commits before a step-up's lock refuses it; one that commits after ends the new token at its next
  request, as it ends every token of the session.
- A reauthentication with another identity's correct credential is `invalid_credentials` and never says whose it was;
  its limits are counted before any transaction opens and given back once it succeeds.
- A malformed freshness block fails closed with an `InvalidArgumentException` naming the key when it is read, and
  `authentication:check` reports it under `[freshness]` or the guard. An identifier change reads its requirement before
  anything is counted or written.
- A token issued on a lagging replica's request still sees a proof just written: every proof read is on the write
  connection.
- An `external_reauthentication` has no entry point yet: the kind is reserved for the provider's reauthentication
  handoff, and a step-up refuses it.

## Seams Left

These parts are columns, kinds or values with nothing yet behind them; the guides say so where they describe them.

- Voiding: `voided_at` is respected by every read and written by nothing. Removing a factor does not stop its proofs
  counting, so `factorRemoved()` ends the identity's other sessions and leaves the session it excepts with its proofs
  of that factor: its tokens keep `mfa` in `amr`, and it still meets a multifactor requirement.
- Evidence: `accepted_evidence` has no writer and is always `null`. Nothing decides whether a provider's evidence is
  accepted, so an external reauthentication would never count for MFA or `amr`.
- `external_reauthentication`: a reserved kind that nothing records; there is no reauthentication handoff from the
  provider, and step-up and `complete()` refuse it.
- Provenance by connection or tenant: only the indexes exist. There is no lookup, listing or revocation of the
  sessions of a connection or of a tenant's connections.
- `complete($token)` with no proof stays a transitional trusted assertion: the session records only its first factor,
  so its `amr` and freshness under-claim, never over-claim, the further factor the caller verified.
- The freshness requirement (proof kinds, maximum age, multifactor, phishing resistance) is what the stored proofs can
  show. It is not a requirement value for additional verification or a minimum assurance level, and there is no
  contract saying whether a session's proofs meet such a requirement. The package gates no factor change itself:
  `factor_change` and `password_establishment` name requirements for whatever gates those operations. A sibling that
  needs more rebinds `FreshnessPolicy` until the value is extended.
- A pending sign-in carries its first factor and provenance in `pending_sign_ins` until it completes; it is not yet a
  session row of its own.

## Implementation Anchors

- `src/Proofs/*` (`ProofResult`, `ProofBinding`, `Evaluation`, `ObservedProperties`, `Channel`, `FirstFactor`,
  `Provenance`, `RecordedProof`, `ProofWriter`, `ProofAcceptance`, `SignInProof`, `SessionProofs`, `ProofHistory`,
  `AuthenticationClaims`, `AuthenticationSummary`, `AuthenticationMethods`, `Enums/*`).
- `src/Models/SessionProof.php`, `src/Models/SessionProvenance.php`,
  `database/migrations/2026_04_06_000008_create_authentication_proofs_table.php`,
  `database/migrations/2026_04_06_000009_create_authentication_provenance_table.php`.
- `src/Sessions/ProofIssuance.php`, `SessionStepUp.php`, `SessionReauthentication.php`, `AccessTokenResult.php`,
  `Concerns/ProvesSessions.php`, `SessionWriter.php` (`record()`).
- `src/Contracts/FreshnessPolicy.php`, `src/Freshness/*` (`FreshnessRequirement`, `Operations`, `FreshnessSettings`,
  `ConfiguredFreshness`).
- `src/Sessions/RecentAuthentication.php`, `src/Sessions/Reauthentication.php`.
- `src/Events/SteppedUp.php`, `src/Events/Reauthenticated.php`; `src/Console/CheckConfigurationCommand.php`
  (`[freshness]`).

## Authoritative Tests

- `tests/Feature/Proofs/SignInProofsTest.php`, `SignInProofTest.php`: the first factor and provenance of every sign-in
  path, kept across a pending sign-in and a choice of principal, a superseding sign-in's own, a refused or cancelled
  write rolled back.
- `tests/Feature/Proofs/SessionProofsTest.php`, `tests/Unit/Proofs/ProofHistoryTest.php`: what counts, the aggregate
  read, `auth_time` and `amr` (order, `mfa`, reauthentications).
- `tests/Feature/Sessions/StepUpTest.php`, `SessionReauthenticationTest.php`: every refusal, the token, what is kept,
  the events.
- `tests/Unit/Freshness/*`, `tests/Feature/Freshness/ConfiguredFreshnessTest.php`: requirements, the stricter rule,
  configuration and its failures, the newest meeting proof.
- `tests/Feature/IdentifierChanges/RecentAuthenticationTest.php`: the identifier change's freshness.
- `tests/Feature/IdentifierChanges/ReboundFreshnessPolicyTest.php`: a policy the application binds is the one asked,
  and the locked row is judged live whatever it answers.
- `tests/Integration/Sessions/ConcurrentSwitchAndRevocationTest.php`: a step-up and a revocation racing on the session's
  row lock.
- `tests/Integration/Sessions/ReusedSessionKeyTest.php`: a key the database issues again inherits no proofs.
- `tests/Integration/Sessions/ConcurrentFreshSignInsTest.php`: sign-ins of different identities neither wait on each
  other nor deadlock while clearing their keys.
- `tests/Integration/Proofs/CaseDistinctBindingTest.php`: session keys and `amr` values that differ only in case stay
  apart.
- `tests/Integration/Proofs/ReplicaProofsTest.php`, `tests/Integration/Migration/ProofTablesSchemaTest.php`,
  `tests/Performance/ProofQueryBudgetTest.php`, `benchmarks/Proofs/ProofHistoryBench.php`.

## Change Triggers

- Storing `auth_time` or `amr` instead of deriving them, or reading proofs from a replica.
- Letting a reauthentication add `amr` values, or working `mfa` out from the values.
- Judging freshness on the latest authentication time rather than the proof that meets the requirement.
- Letting a step-up or a reauthentication issue a refresh token, move a deadline, or write the session row.
- Taking a password as an identifier change's proof where the requirement asks for more than a first-factor
  reauthentication.
- Reading a proof history unbounded by the session's distinct combinations.
