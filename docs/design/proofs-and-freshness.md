# Proofs and Freshness

## Purpose

This note records how a session keeps the proofs it was established and kept with, how an access token's `auth_time`
and `amr` are derived from them, how a session steps up and reauthenticates without becoming a new session (at the
external provider it began with included), when an external provider's evidence is accepted and what it then counts
for, and how the freshness of a session's authentication is judged for a sensitive operation. The proofs are evidence a
session holds; the token's claims and every freshness answer are worked out from them, never stored in their place.

## Invariants

- A proof is a row in `proofs.table`, on the storage connection, belonging to a session's key: its kind
  (`first_factor`, `first_factor_reauthentication`, `external_reauthentication`, `additional_factor`,
  `recovery_code`), method, channel, factor reference, observed properties (each `null` when not observed, which never
  counts as true), evaluation, `amr` values, time, binding (identity, application, session, purpose) and, for an
  external provider's proof, the evidence the provider asserted once it was accepted. A proof is never changed once
  recorded; a voided one never counts, and a further factor or recovery code counts only when its adapter accepted it.
- Every session the package writes records a generation, a random UUID written when the row is inserted and never
  changed (`EloquentSession::getGenerationName()`, `SessionRecords\SessionGeneration`): it tells a session apart from
  any other a model that reissues keys puts under its key, of the same owner and in the same second included, which
  neither the key, the owner nor the whole-second start can. A row that records none is never the session a caller
  holds.
- Every session the package writes records a counting first factor in the transaction that writes the session; an
  external provider's session also records its provenance, once. Proofs and provenance carry unchanged from a pending
  sign-in to its session and across every refresh and switch; a sign-in that replaces a session starts a
  new session with its own.
- Every read of proofs is of the session's own: those recorded under its key and bound to its guard and its owner (the
  morph type and key the session records), so another identity's or application's proof under the same key never
  counts for it. The key, guard, owner and `amr` columns compare byte for byte (binary columns on MySQL and MariaDB,
  whose default collations ignore case and accents and whose `utf8mb4_bin` ignores trailing spaces; there the key, guard
  and owner take 1020 bytes, the 255 four-byte characters they hold elsewhere), so a key, owner or value that differs
  only in those is another.
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
- `auth_time` is the newest time of any counting proof. `amr` is the values of the first factor, the further factors,
  the recovery codes and the reauthentications with an accepted evaluation, once each, in the order of their newest
  times and then of their values; `mfa` is added only when an accepted evaluation reported multifactor authentication
  (a further factor's, a recovery code's, or an external provider's proof whose evidence was accepted as multifactor),
  never worked out from the values, and a proof may not record it itself. A first-factor reauthentication, and an
  external one whose evidence was not accepted, renews `auth_time` and adds no value (`ProofHistory`, which
  `SessionProofs::history()` groups by acceptance too). A session with no counting first factor issues no token (a
  `LogicException`).
- An external provider's evidence (`External\ExternalEvidence`: its `amr` values, its `acr` value or SAML authentication
  context class reference, the time it is for) is accepted only when the bound `Contracts\ExternalEvidencePolicy` says
  it meets multifactor authentication or, failing that, an additional verification or then phishing resistance, each of
  any age and for no tenant, asked inside `WriteConnection::during()` for the identity
  (`External\EvidenceAcceptance::evaluate()`). The default, `InsufficientEvidence`, meets nothing, so by default no
  evidence is accepted. Accepted evidence is recorded with its proof (`proofs.evidence`, the first factor's at sign-in
  and an `external_reauthentication`'s) and, at sign-in, the provenance's `accepted_evidence`, dated no later than the
  time it was judged at (`EvidenceAcceptance::asOf()`), and the proof carries the acceptance as its evaluation
  (multifactor when it met multifactor authentication). Evidence that is not accepted is recorded nowhere and counts for
  nothing; there is no partial acceptance. A result's evidence is never dated after the provider's time the result gives
  (`ExternalResult` refuses it): the provider's time times the proof, the evidence's own time is what its acceptance and
  any requirement judged on it age. Evidence that is not valid UTF-8, or whose stored JSON (every character outside
  ASCII escaped, up to twelve bytes for one) would exceed `ExternalEvidence::STORED_MAX_BYTES` (65,535, a MySQL `TEXT`
  column), is refused when it is built, so evidence once accepted is always written.
- Freshness takes no provider's evidence: a proof that carries accepted evidence never meets a freshness requirement
  that asks for multifactor authentication (`SessionProofs::newestMeeting()`), since the evidence was accepted as of any
  age and the proof is timed at the provider's time, not the evidence's. It still meets one that does not, on its time.
- The identity-level requirement and a tenant's further factor have one judge (`Requirements\RequirementJudge`). For a
  session an external provider established (its first factor's channel is `external_provider`) that holds accepted
  evidence, it asks the evidence policy first whether the newest accepted evidence, by the evidence's own time, meets
  the whole requirement: at sign-in the sign-in's own, in memory (`SessionEvidence::$externalEvidence`); otherwise one
  read of at most `SessionProofs::EVIDENCE_LIMIT` of the session's counting proofs that carry evidence
  (`SessionProofs::acceptedEvidence()`), on the write connection. The policy is told the connection and the tenant whose
  requirement it judges (`EvidenceSubject::$tenant`, `null` for the identity level and for acceptance), so it can refuse
  evidence from a connection that tenant does not trust. Met, `RequirementCheck` is not asked; otherwise it
  judges the session's proofs as it does any session's. Evidence never meets part of a requirement and leaves the rest
  to the factor package's proofs, and a session no provider established reads nothing more.
- An `external_reauthentication` is recorded only by `reauthenticateExternally()` (`Sessions\ExternalReauthentication`),
  through `ProofIssuance` like the others, and only through the very link that established the session: the link
  contract is asked first (before any lock of the package's, so after the adapter's own), then under the session's
  locked row the session must still be of the same generation, owned by the link's identity, with a provenance that
  records exactly the result's connection and the link's id, byte for byte (`link_mismatch`; a session recorded with no
  link never matches), and not begun after the provider's time (`proof_invalid`). With the proof recorded, the session
  must still meet its tenant's authentication policy, as at every redemption (`sso_required`,
  `additional_factor_required`; the proof rolls back). The proof is timed at the provider's time, never after now, so
  the new token's `auth_time` is the later of the session's and the provider's, decided under that lock.
  `externalStanding()` takes the same lock and answers the same checks without writing.
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
  otherwise); its proof is `first_factor_reauthentication`, made now. Before the check, the session as stored must still
  record the generation of the session given (`session_unknown` otherwise, reported with no session); its check on the
  locked row is that the row is still the session verified, the same owner's and of the same generation, since a
  session model that reissues a key could have put another session under it meanwhile (`session_unknown`, reported for
  the session verified). The generation tells apart even a session of the same owner started in that same second,
  whose token would otherwise carry its own further factors, `mfa` included, to a caller who proved only a password;
  both comparisons read columns already loaded, with no query.
- Freshness is `Contracts\FreshnessPolicy`'s: a requirement per operation and application (proof kinds, maximum age of 1
  to 86400 seconds, multifactor, phishing resistance), the stricter of the configured one and the caller's, and the
  newest proof meeting it. The default, `Freshness\ConfiguredFreshness`, reads `authentication.freshness` and a guard's
  `freshness` block (an entry wins whole; `null` removes it) on every call, keeps no state, and reads the session again
  by key on the write connection, requiring it to record the caller's generation and owner (a session model that
  reissues keys may have put another session under it, another identity's or a later one of the same identity, which a
  retained instance of the earlier session would otherwise be answered with) and be live for its guard, before reading
  its proofs; it reads nothing when the operation has no requirement. An operation with no requirement, or two
  requirements with no kind in common, is never fresh. The latest `auth_time` never stands in for the proof that meets a
  requirement.
- An identifier change proves a recent authentication with the `identifier_change` operation: a session proof must still
  be the session given (of its generation) and one of the identity's live sessions of the guard, as stored, and the
  policy must find a proof for it; inside the change's transaction both are checked again on the session's locked row,
  which the change judges itself, since the policy's own read takes no lock; a password proof is a first-factor
  reauthentication made now and is taken only when the requirement takes `first_factor_reauthentication` and asks for
  neither multifactor authentication nor phishing resistance.

## Success Path

1. A sign-in records the first factor its method returned (`FirstFactor`), `signInExternally()` records the external
   provider's with its provenance (and its evidence, once accepted), and `start()` an unattested one; a completion
   records the further factor it was given.
2. Every access token issued for the session (`signIn()`, a refresh, a switch, a step-up, a reauthentication) asks
   `Proofs\AuthenticationClaims::forSession()` for its `auth_time` and `amr`.
3. A further-factor adapter verifies a factor on a signed-in session and hands its `ProofResult` to `stepUp()`: the
   proof is recorded, a new access token issued, `SteppedUp` dispatched once committed.
4. A client proves its first factor again through `reauthenticate()`: the attempt is counted and verified, the proof
   recorded, a new access token issued with `auth_time` renewed, `Reauthenticated` dispatched once committed. A trusted
   adapter hands a result the session's external provider verified to `reauthenticateExternally()` inside its own
   transaction: the link is found, the evidence judged, the session's row locked last and checked again, the proof
   recorded and one access token issued, `Reauthenticated` (method `external_provider`) dispatched once committed.
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
- An `external_reauthentication` is recorded only by `reauthenticateExternally()`; a step-up and `satisfy()` refuse it.
  A result linked to no identity is `external_result_unlinked`, after `ExternalResultUnlinked`; one without the
  provider's time, or with one before the session began, is `proof_invalid`. A revocation of the session (a link's
  removal or widened scope, say) that commits before the reauthentication's lock refuses it as `session_revoked`; one
  that commits after ends the new token at its next request.
- Two reauthentications at the provider racing on one session both record their proofs; `auth_time` is the later
  provider time whichever commits last, since it is derived from the proofs, never written.
- An exception from the evidence policy or the link contract, and a database error (a serialization failure included),
  propagates and rolls back the caller's transaction, for the adapter to retry whole.
- Only the newest accepted evidence is judged against a requirement: a later reauthentication whose evidence was
  accepted only as an additional verification is what a multifactor requirement is judged on, though `amr` keeps the
  `mfa` an earlier acceptance added.

## Seams Left

These parts are columns, kinds or values with nothing yet behind them; the guides say so where they describe them.

- Voiding: `voided_at` is respected by every read and written only by `factorRemoved()`, for the current session's
  proofs made with the removed factor (`ProofWriter::void()`), whether that session is active or pending, so a pending
  session's next action is never judged on them; the identity's other sessions end instead, so their proofs are never
  voided. A removed first-factor credential (`credentialRemoved()`) voids nothing.
- Provenance by connection or tenant: the connection index finds the sessions a connection established for
  `connectionDisabled()` and `connectionDeleted()` (`Sessions\ConnectionRevocations`); there is no lookup or listing of
  the sessions of a connection or of a tenant's connections, and the tenant index has no reader yet.
- The freshness requirement (proof kinds, maximum age, multifactor, phishing resistance) is what the stored proofs can
  show. A tenant's further factor is a `Requirements\Requirement` instead (additional verification, multifactor, a
  minimum assurance level, phishing resistance, each with an optional maximum age), and whether a session meets it is
  the accepted evidence's (`Contracts\ExternalEvidencePolicy`) or its proofs' (`Contracts\RequirementCheck`) answer,
  each meeting nothing by default; the identity-level factor policy answers a `Requirement` too, judged the same way
  (`RequirementJudge`). Freshness uses neither, and so no provider's evidence: a proof carrying accepted evidence never
  meets a multifactor freshness requirement. The factor-change gate
  (`SessionService::factorChange()`) asks freshness for `factor_change`, or `first_additional_factor` for an identity's
  first additional factor, excluding the factor a replacement or removal names. A sibling that needs more rebinds
  `FreshnessPolicy` until the value is extended.
- A pending session records its first factor and provenance as any session does, when it is written; the further
  factor `satisfy()` accepts is stored with them (the requirement check reads it when the policy is asked again), and
  none counts for a token until the session activates.

## Implementation Anchors

- `src/Proofs/*` (`ProofResult`, `ProofBinding`, `Evaluation`, `ObservedProperties`, `Channel`, `FirstFactor`,
  `Provenance`, `RecordedProof`, `ProofWriter`, `ProofAcceptance`, `SignInProof`, `SessionProofs`, `ProofHistory`,
  `AuthenticationClaims`, `AuthenticationSummary`, `AuthenticationMethods`, `Enums/*`).
- `src/Models/SessionProof.php`, `src/Models/SessionProvenance.php`,
  `database/migrations/2026_04_06_000008_create_authentication_proofs_table.php`,
  `database/migrations/2026_04_06_000009_create_authentication_provenance_table.php`.
- `src/Sessions/ProofIssuance.php`, `SessionStepUp.php`, `SessionReauthentication.php`, `ExternalReauthentication.php`,
  `ExternalResults.php`, `AccessTokenResult.php`, `Concerns/ProvesSessions.php`, `Concerns/SignsInExternally.php`,
  `SessionWriter.php` (`record()`).
- `src/Contracts/ExternalEvidencePolicy.php`, `src/External/*` (`ExternalEvidence`, `EvidenceSubject`,
  `EvidenceAcceptance`, `InsufficientEvidence`), `src/Requirements/RequirementJudge.php`,
  `src/Tenancy/SessionEvidence.php`.
- `src/Contracts/FreshnessPolicy.php`, `src/Freshness/*` (`FreshnessRequirement`, `Operations`, `FreshnessSettings`,
  `ConfiguredFreshness`).
- `src/Sessions/RecentAuthentication.php`, `src/Sessions/Reauthentication.php`.
- `src/Events/SteppedUp.php`, `src/Events/Reauthenticated.php`; `src/Console/CheckConfigurationCommand.php`
  (`[freshness]`).

## Authoritative Tests

- `tests/Feature/Proofs/SignInProofsTest.php`, `SignInProofTest.php`: the first factor and provenance of every sign-in
  path, kept across a pending session and a choice of principal, a superseding sign-in's own, a refused or cancelled
  write rolled back.
- `tests/Feature/Proofs/SessionProofsTest.php`, `tests/Unit/Proofs/ProofHistoryTest.php`: what counts, the aggregate
  read, `auth_time` and `amr` (order, `mfa`, reauthentications).
- `tests/Feature/Sessions/SessionStepUpTest.php`, `SessionReauthenticationTest.php`, `ExternalReauthenticationTest.php`:
  every refusal, the token, what is kept, the events; the external one's link checks, the later-time rule, accepted and
  unaccepted evidence, changes under the lock and the standing.
- `tests/Feature/External/EvidenceAcceptanceTest.php`, `tests/Unit/External/ExternalEvidenceTest.php`,
  `tests/Feature/Requirements/RequirementJudgeTest.php`: acceptance and its order, the stored form, the evidence path of
  the judge in memory and stored, and no read for a session no provider established.
- `tests/Integration/Sessions/ExternalReauthenticationTest.php`, `ConcurrentExternalReauthenticationsTest.php`,
  `ConcurrentExternalReauthenticationAndWideningTest.php`: the byte-exact link, the adapter's transaction, and the
  races on the session's row lock.
- `tests/Unit/Freshness/*`, `tests/Feature/Freshness/ConfiguredFreshnessTest.php`: requirements, the stricter rule,
  configuration and its failures, the newest meeting proof, and no provider's evidence meeting multifactor freshness.
- `tests/Feature/IdentifierChanges/RecentAuthenticationTest.php`: the identifier change's freshness.
- `tests/Feature/IdentifierChanges/ReboundFreshnessPolicyTest.php`: a policy the application binds is the one asked,
  and the locked row is judged live whatever it answers.
- `tests/Integration/Sessions/ConcurrentSwitchAndRevocationTest.php`: a step-up and a revocation racing on the session's
  row lock.
- `tests/Integration/Sessions/ReusedSessionKeyTest.php`: a key the database issues again inherits no proofs.
- `tests/Integration/Sessions/ConcurrentFreshSignInsTest.php`: sign-ins of different identities neither wait on each
  other nor deadlock while clearing their keys.
- `tests/Integration/Proofs/ByteDistinctBindingTest.php`: session keys that differ only in case or by a trailing space,
  and `amr` values that differ only in case, stay apart.
- `tests/Integration/Proofs/ReplicaProofsTest.php`, `tests/Integration/Migration/ProofTablesSchemaTest.php`,
  `tests/Performance/ProofQueryBudgetTest.php`, `benchmarks/Proofs/ProofHistoryBench.php`.

## Change Triggers

- Storing `auth_time` or `amr` instead of deriving them, or reading proofs from a replica.
- Letting a reauthentication add `amr` values without an accepted evaluation, or working `mfa` out from the values.
- Recording or counting a provider's evidence the evidence policy did not accept, letting it meet part of a
  requirement, storing an evidence time after the time it was judged at, or letting freshness count it as multifactor
  authentication.
- Letting an external reauthentication through any link but the one the session's provenance records, or locking the
  session before the link contract is asked.
- Judging freshness on the latest authentication time rather than the proof that meets the requirement.
- Letting a step-up or a reauthentication issue a refresh token, move a deadline, or write the session row.
- Taking a password as an identifier change's proof where the requirement asks for more than a first-factor
  reauthentication.
- Reading a proof history unbounded by the session's distinct combinations.
