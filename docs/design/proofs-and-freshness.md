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
  counts as true), evaluation (accepted, multifactor, and whether it is an additional verification, in the
  `additional_verification` column: always for a further factor, never for a recovery code, and
  `Evaluation::$additionalVerification` for an external proof), `amr` values,
  time, binding (identity, application, session, purpose) and, for an external provider's proof, the evidence the
  provider asserted once it was accepted. A proof is never changed once recorded; a voided one never counts, and a
  further factor or recovery code counts only when its adapter accepted it.
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
- Every read of proofs is on the write connection and bounded: the claims and the authentication context read one
  aggregate query grouped by kind, `amr` set, multifactor report and additional verification
  (`SessionProofs::history()`), and freshness reads the newest proof a requirement takes with `LIMIT 1` on the session,
  kind and time index (`SessionProofs::newestMeeting()`), so a session with many step-ups costs what one with few does.
- Another package reads an active session's proofs only through the session service,
  `Auth::sessions($guard)->proofs($session, $since, $kinds, $limit)` and `firstFactor($session)`
  (`Sessions\ActiveSessionProofs`), and a context contributor through its `ContributionSubject` (see
  `authentication-context.md`). `SessionProofs` stays internal, since its current mode is a precondition (the session's
  row held locked) only the package can honour, and so does `RequirementSubject`'s constructor. The reads answer
  `PendingSession::proofs()`'s filter, order and bound (1 to `RequirementSubject::MAX_LIMIT`, checked before anything is
  read) and the oldest counting first factor, only for one of the guard's live, active sessions of a person: an id that
  cannot be a key of the session model (no query), one that names no row, and a session of another guard, revoked,
  pending, past a deadline at this second or without deadlines, or a machine's, answer `[]` and `null` alike, with no
  exception and no event (`OwnedSession::refusal()` and `SessionOwnership::isMachineOwned()`, as `externalStanding()`).
  The proofs are bound to the row as stored, so an id names whichever session holds the key now; a `Session` given to
  the service, and a subject's, answers only while the stored row is still that session
  (`SessionOwnership::isSameSession()`: its generation and owner, with no query), and one that is not an Eloquent
  session is not looked up. `$since` is any `CarbonInterface`, as the package's other times from a caller are (so
  `now()`'s mutable `Carbon` serves), and an immutable copy of it is converted to the application's time zone, the one
  proofs are written in, before it is compared, so it is the same instant in whichever zone it is given and the caller's
  time is never changed (as `PendingSession::proofs()` and `RequirementSubject::proofs()` read it too;
  `RequirementSubject` hands its reader the immutable copy). No identity is checked: which sessions a caller may ask
  about is the application's to decide.
- `auth_time` is the newest time of any counting proof. `amr` is the values of the first factor, the further factors,
  the recovery codes and the reauthentications with an accepted evaluation, once each, in the order of their newest
  times and then of their values; `mfa` is added only when an accepted evaluation reported multifactor authentication
  (a further factor's, a recovery code's, or an external provider's proof whose evidence was accepted as multifactor),
  never worked out from the values, and a proof may not record it itself. A first-factor reauthentication, and an
  external one whose evidence was not accepted, renews `auth_time` and adds no value (`ProofHistory`, which
  `SessionProofs::history()` groups by acceptance too). A session with no counting first factor issues no token (a
  `LogicException`). The claims describe how the session authenticated, not what any tenant accepts: `mfa` from
  accepted evidence follows the application-wide acceptance, of any age, so it stays in every token of the session,
  one issued as a principal of a tenant whose evidence policy refuses that connection included. A tenant's requirement
  is judged by the evidence policy for that tenant, never on `amr`.
- An external provider's evidence (`External\ExternalEvidence`: its `amr` values, its `acr` value or SAML authentication
  context class reference, the time it is for) is accepted only when the bound `Contracts\ExternalEvidencePolicy`'s
  `accepts()` accepts it for multifactor authentication or, failing that, an additional verification, then phishing
  resistance, then the lowest assurance level (AAL1: evidence credible for any level is accepted, and the level a
  requirement asks for is `meets()`'s), each of any age and for no tenant, asked inside `WriteConnection::during()` for
  the identity (`External\EvidenceAcceptance::evaluate()`). Acceptance is its own question, not the identity-level
  requirement's: the policy accepts evidence credible to anyone it may later be judged for (the identity level, or any
  tenant that trusts the connection), and `meets()` scopes each requirement, so a connection only one tenant trusts
  still has its evidence accepted and meets only that tenant's requirement. The default, `InsufficientEvidence`, accepts
  nothing, so by default no evidence is accepted. Accepted evidence is recorded with its proof (`proofs.evidence`, the
  first factor's at sign-in and an `external_reauthentication`'s) and, at sign-in, the provenance's `accepted_evidence`,
  dated no later than the time it was judged at (`EvidenceAcceptance::asOf()`), and the proof carries the acceptance as
  its evaluation (multifactor when it was accepted for multifactor authentication, an additional verification when it
  was accepted for one or for multifactor authentication, neither for phishing resistance or a level alone), which
  `amr` and the authentication context's `mfa` read (see `authentication-context.md`). The proof reads
  back with no evaluation (`SessionProofs`, `SignInProof::recorded()`), so a `RequirementCheck` never takes the
  application's acceptance of evidence of any age for a tenant's multifactor proof; only the evidence beside it, which
  the evidence policy judges, says what it is worth. Evidence that is not accepted is recorded nowhere and counts for
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
  evidence, it asks the evidence policy's `meets()` first whether any accepted evidence meets the whole requirement, the
  newest by the evidence's own time first and no further once one does: at sign-in the sign-in's own, in memory
  (`SessionEvidence::$externalEvidence`); otherwise one read of at most `SessionProofs::EVIDENCE_LIMIT` of the session's
  counting proofs that carry evidence (`SessionProofs::acceptedEvidence()`), on the write connection, keeping of
  evidence that asserts the same methods and context only the newest, which an older copy can never better. Newer
  evidence accepted for less (an additional verification, say) never hides older evidence that still meets the
  requirement on its own time, among those proofs: evidence only on proofs older than the newest `EVIDENCE_LIMIT` that
  carry evidence is not read, which fails closed (the session needs a further factor or a new reauthentication). The
  policy is told the connection and the tenant whose requirement it judges (`EvidenceSubject::$tenant`, `null` for the
  identity level and for acceptance), so it can refuse evidence from a connection that tenant does not trust. Met,
  `RequirementCheck` is not asked; otherwise it judges the session's proofs as it does any session's. Evidence never
  meets part of a requirement and leaves the rest to the factor package's proofs, and a session no provider established
  reads nothing more.
- An `external_reauthentication` is recorded only by `reauthenticateExternally()` (`Sessions\ExternalReauthentication`),
  through `ProofIssuance` like the others, and only through the very link that established the session: the link
  contract is asked first (before any lock of the package's, so after the adapter's own), then under the session's
  locked row the session must still be of the same generation, owned by the link's identity, with a provenance that
  records exactly the result's connection and the link's id, byte for byte (`link_mismatch`; a session recorded with no
  link never matches), and not begun after the provider's time (`proof_invalid`). With the proof recorded, the session
  must still meet its tenant's authentication policy, as at every redemption (`sso_required`,
  `additional_factor_required`; the proof rolls back). The proof is timed at the provider's time, never after now, so
  the new token's `auth_time` is the later of the session's and the provider's, decided under that lock.
  `externalStanding()` answers the same checks without writing, under the same lock inside a transaction, reading the
  provenance current there, and with none outside one (when no link id is given, through any link of the connection).
- A step-up (`SessionService::stepUp()`) and a reauthentication (`reauthenticate()`) share `Sessions\ProofIssuance`:
  in one transaction on the session's connection, the session's row is locked; the session must exist, be this guard's,
  live and a person's; the operation's own check runs on the locked row; the session is admitted again as a refresh
  admits it; the session's issuance guard is written, the proof is recorded and one access token issued, its claims
  derived with the new proof included. The refresh token and the deadlines are untouched, and the session row takes only
  its issuance guard, which no compare-and-swap reads, so a concurrent refresh's compare-and-swap is unaffected, and
  nothing is bound to the request. A proof refused before it is recorded writes nothing.
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
  its proofs; it reads nothing when the operation has no requirement, or when the session is not an Eloquent session
  (which can never be the stored one). An operation with no requirement, or two requirements with no kind in common, is
  never fresh. The latest `auth_time` never stands in for the proof that meets a requirement.
- `freshProof()` and `freshUntil()` carry a read mode (`$current`, last, `false` by default). Asked plainly, both read
  and lock nothing. Asked current, they answer on the session as committed, for a caller that acts on the answer
  atomically (`freshUntil()` for a grant's expiry): they are asked only inside a transaction on the session model's
  connection (the default throws a `LogicException` outside one, before anything is read: outside one the row's read
  and the proofs' read are two statements whose locks end with each, no atomic judgement), and the default reads the
  session's row with `SessionLookup::lock()`, judges it as a plain answer does (the same generation and owner, live for
  its guard), and reads its proofs current (`SessionProofs::newestMeeting(..., true)`), still two queries. So the
  caller need take no lock first; one that judges the row for more of its own locks it before (one more statement and
  no new lock), as every caller in the package does, since a rebound policy is never trusted to judge the row for it.
  The read mode is on the contract, so a rebound policy is asked it too and honours it (a decorator of the default
  passes it on; one of its own locks the session's row, judges it and reads its proofs as committed), and the package
  asks it only where the call site holds the session's row, never whenever a transaction happens to be open (see the
  freshness judgements under the lock, below). No judgement of the package under a lock asks `freshUntil()`: the gate
  takes its grant's expiry from the current proof and the requirement; the mode serves a caller of its own that grants
  on the answer.
- An identifier change proves a recent authentication with the `identifier_change` operation: a session proof must still
  be the session given (of its generation) and one of the identity's live sessions of the guard, as stored, and the
  policy must find a proof for it; inside the change's transaction both are checked again on the session's locked row,
  which the change judges itself (the policy is never trusted to), the policy asked under that lock on the session's
  proofs as committed; a password proof is a first-factor reauthentication made now and is taken only when the
  requirement takes `first_factor_reauthentication` and asks for neither multifactor authentication nor phishing
  resistance.

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
   proof; a caller that acts atomically asks current inside its transaction (`freshProof(..., current: true)`), which
   locks the session's row until the transaction ends and judges it before the proofs are read, never acting on a plain
   answer there (the plain read takes no lock, so a transaction may serve it from an earlier snapshot). The package's
   own freshness judgements under a session's lock (the factor-change gate, an identifier change request's check under
   the identity's lock, a password establishment) ask so, each having locked and judged the row itself first.

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
  provider time whichever commits last, since it is derived from the proofs, never written. Each writes the session's
  issuance guard (`SessionRecords\IssuanceGuard`) before its proof and reads the proofs for its token current
  (`SessionProofs::history($session, true)`: a shared lock on MySQL and MariaDB, whose plain reads inside a REPEATABLE
  READ transaction return its first snapshot), so the token issued second counts the other's proof. Inside a caller's
  transaction at PostgreSQL's REPEATABLE READ or SERIALIZABLE whose snapshot predates the other's commit, no read could
  see it, and the second fails to serialise on the guard (or on its own lock of the row the first's guard wrote)
  instead, for the caller to retry whole; a retry can fail the same way once more when the other writes the row again
  after it commits (a refresh's `Listeners\RecordSessionUsage` records the last use then). The same holds for every
  issuer of a session's tokens: in commit order no token carries an older `auth_time` or fewer `amr` values than one
  before it, except where a factor's removal voided proofs on purpose (`FactorRevocations` writes the guard before it
  voids).
- Every requirement judgement made while the transaction holds the session's row locked reads the session's proofs and
  provenance current, as the issuance does: the tenant policy's judgement in a refresh (`RefreshTokenExchange`), a
  switch and its grace retry (`SessionSwitch`) and a reauthentication at the provider (`ExternalReauthentication`,
  inside `ProofIssuance`'s lock), the judgement of the current session again after a factor's removal or an addition
  (`FactorRevocations`, after its issuance guard), `satisfy()` and `choose()` (`PendingSessions`), and
  `tenantPolicyChanged()` (`TenantPolicyChanges`). Each passes a current read down to every read of the session it
  makes: its first factor (`SessionProofs::firstFactor()`), the evidence its proofs hold accepted
  (`acceptedEvidence()`), every query the bound requirement check makes of the subject (`query()`, through
  `RequirementSubject::proofs()`), and the connection its provenance records (`connectionId()`);
  `Requirements\ProofSource` carries the choice into `RequirementJudge` and `TenantPolicyCheck`, a `bool $current` into
  `PendingEvaluation` and `PendingTransitions`. So on MySQL and MariaDB at REPEATABLE READ, inside a caller's
  transaction whose first plain read came before another transaction committed a proof (a step-up), voided some (a
  removal of another factor) or reused the session's key, the judgement counts the step-up, never the voided proof, and
  reads the reused key's own proofs and provenance: a plain read there would return that snapshot, returning a session
  to pending although it met the requirement or revoking it for a policy change it meets (failing closed), or counting a
  voided proof or a provenance the key no longer has (failing open). At PostgreSQL's REPEATABLE READ the session's lock
  or guard fails to serialise instead (every writer of a session's proofs writes its row first), for the caller to retry
  whole; at READ COMMITTED each statement reads what is committed. Judgements made with no lock on the session read
  plainly and take no lock: a refresh credential's preview (`SessionRefresh`), the lookup of a pending session
  (`PendingSessions::pending()`), and a sign-in, whose evidence is in memory. Only the package's reads are current: what
  the bound `RequirementCheck`, `ExternalEvidencePolicy` or `TenantAuthenticationPolicy` reads of its own tables is its
  own.
- Every freshness judgement made while the transaction holds the session's row locked is made on the session's proofs as
  committed: the factor-change gate (`FactorChangeGate::judge()`, inside its own transaction on the session model's
  connection), an identifier change request's check under the identity's lock (`RecentAuthentication::stands()`) and a
  password establishment (`PasswordChanges::establish()`, under the identity's and then the session's lock). Each asks
  the bound policy's `freshProof()` current (`current: true`) on the locked row, and the default's budget stays two
  queries. So on MySQL and MariaDB at REPEATABLE READ, inside a caller's transaction whose first plain read came before
  another transaction voided a step-up (a factor's removal, which writes the session's issuance guard before it voids),
  a factor change, an identifier change request or an establishment is refused, where the snapshot read allowed it
  (failing open), and a step-up committed meanwhile is counted, where the snapshot read missed it (failing closed). A
  rebound policy is asked the same way and reads as committed when asked, as the contract requires. At PostgreSQL's
  REPEATABLE READ the session's lock fails to serialise when the session was written after the snapshot, as for every
  judgement under the lock. The identifier change request's first check, before its transaction
  (`RecentAuthentication::refusal()`), reads plainly and locks nothing: run inside a caller's transaction at REPEATABLE
  READ (on MySQL and on PostgreSQL alike, since nothing is locked yet), it misses a step-up committed after the caller's
  snapshot and refuses (failing closed), and a voided step-up it still counts is refused by the check under the lock.
  Locking there would take the session's row and proofs before the identity's row, inverting the identity-then-session
  order an identifier change and a password change from one session both take.
- The current reads keep the lock order of session rows before proof rows. `satisfy()` and `choose()` lock the session
  the sign-in's client proved it holds, whenever the sign-in recorded one, once the action is admitted, before they
  check it and before the pending session's guard and proofs, so the supersede its first activation makes takes no row
  after them; `tenantPolicyChanged()` reads the keys of the tenant's live sessions with locking reads first and judges
  them only once all are locked, reading each chunk again by key with a locking read of rows it already holds; and the
  factor package ends the identity's other sessions before it calls `factorChanged()`, as `factorRemoved()` revokes
  them before it locks the current one. Session rows have no one order across operations: `tenantPolicyChanged()` and
  every bulk revocation (`RevocationWriter::revokeScopes()`, and `ConnectionRevocations` for a connection or a link)
  lock the sessions they cover in key order, the older first, while a pending action locks the pending session before
  the older one it proved, whether it then activates, stays pending, moves on to the choice or is refused. So such an
  operation over both can deadlock with the pending action, as it could at a first activation's supersede before; the
  database fails one, and its caller rolls its whole transaction back and retries it. The freshness judgements under
  the lock keep the order too (the identity's row, then the session's, then its proofs), but two flows take session
  rows after them: the factor package's removal calls `factorRemoved()` after the gate in its transaction, which
  revokes the identity's other sessions, and an
  establishment's `PasswordWriter` ends the identity's other sessions after its judgement. On MySQL and MariaDB at
  REPEATABLE READ the judgement's read holds the gap at the edge of the judged session's proofs (below); a request on a
  neighbouring session of the same identity that holds that session's row while recording a proof falling in that gap
  (a step-up, a reauthentication, or a new session's first proof when the judged session is the newest) waits for it,
  and the revocation then waits for that row: a deadlock, which the database breaks by failing one side, with nothing
  half-written. A test reproduces it for the establishment (with the plain read it once made, the establishment
  completes); the gate's case is the same mechanism. Neither is reordered: the removal follows the gate in the factor
  package's transaction by design, and the establishment could avoid it only by a locking read of every live session of
  the identity before each judgement, which at REPEATABLE READ also gap-locks the identity's range in the owner index
  and holds up its every new sign-in on every establishment, refused ones included, a heavier and always-paid cost for a
  cycle that needs a concurrent proof on a neighbouring session. Two removals from two sessions of one identity could
  already deadlock on their rows the same way. At READ COMMITTED the establishment waits for the neighbour's row and
  completes; at PostgreSQL's REPEATABLE READ it fails to serialise, and a retry of the whole transaction completes.
- A public read of an active session's proofs (`ActiveSessionProofs`) locks only inside a transaction on the session
  model's connection, whether or not the caller already holds the row, which cannot be observed portably and is taken
  again at no cost: it locks the session's row (`SessionLookup::lock()`, the lock every path takes on it, so a step-up
  or a factor change after the read in the same transaction is no lock upgrade that could deadlock two such
  transactions) and reads the proofs current. So on MySQL and MariaDB at REPEATABLE READ a step-up committed before the
  read is returned and a proof voided before it never is, whatever the transaction read first, and at PostgreSQL's
  REPEATABLE READ the row's lock fails to serialise when the session was written after the snapshot. It keeps the lock
  order, the session row and then its proofs, takes no connection guard or other session's row, and on MySQL and
  MariaDB at REPEATABLE READ its proofs' read holds the next-key and gap locks a judgement's does, until the caller
  commits. The row is locked before it is known to exist, as `externalStanding()` locks it: for an id that names no row,
  MySQL and MariaDB at REPEATABLE READ lock the gap in the sessions' primary key where it would fall, and since keys are
  time-ordered, an id above every key holds up every new sign-in until the caller commits; the guide says to check an
  id is the caller's first. A `stepUp()` or `factorChanged()` of the same session after the read locks only the row it
  holds; `factorRemoved()` moves the identity's token cutoff and revokes the identity's other sessions before it
  judges the current one again, so a read before it in the same transaction would put those rows after a session row
  and its proofs' locks, and two removals from two of an identity's sessions could deadlock: the guide says not to.
  Outside a transaction it is two plain reads on the write connection and locks nothing: between them a key passes to
  another session only if the row is deleted (the package deletes one only when pruning it, `session.prune_after_days`
  after it ended) and the database issues the key again, a residual the guide states rather than close with a
  transaction of the read's own, which would lock a session's row on every contributor's read. The binding does not
  include the generation, so proofs an earlier session left under a reused key are kept out by pruning and
  `ProofWriter::clear()`, within the limit stated above.
- On MySQL at REPEATABLE READ, the shared lock of an issuance's or a judgement's current read is a set of next-key locks
  on the proofs' session index (`session_id`, `kind`, `authenticated_at`), so it also locks the gaps on either side of
  the session's proofs, up to the neighbouring entries. Keys are time-ordered, so a proof another transaction inserts
  there waits until the reading transaction commits (inside a caller's transaction, until the caller commits), and then
  commits: after the newest session's proofs falls every new session's, so a sign-in waits for an issuance or a
  judgement of the newest session (a refresh, a switch, a step-up, a reauthentication, an activation, a factor change, a
  pending action, a policy change, and the freshness judgements under the lock: a factor-change gate verdict, an
  identifier change request, a password establishment); just before the next session's `first_factor`
  entry falls its `additional_factor` or `external_reauthentication` proof, so a step-up, a `satisfy()` or a
  reauthentication at the provider of the next session waits; and just after the previous session's last entry falls its
  `first_factor_reauthentication` or `recovery_code` proof, so a reauthentication with the first factor or a recovery
  code of the previous session waits. The wait alone never deadlocks, but a caller's transaction that goes on to take a
  lock the waiting side holds does, and MySQL fails one of them for the caller to retry: the guard row of the link a
  waiting external sign-in goes through, or the row of a waiting neighbour, which `ProofIssuance` and `satisfy()` lock
  before they insert (revoking, refreshing or switching that session, or signing its identity out everywhere). A
  sign-in's own issuance reads plain for this reason: its session is not committed, so no other transaction can record a
  proof under it. At READ COMMITTED MySQL locks no gap, and PostgreSQL takes no shared lock. No narrower lock gives a
  current read there: InnoDB's REPEATABLE READ reads past its snapshot only with a locking read, which locks the range
  it scans.
- Measured on MySQL 8.4 at REPEATABLE READ (`performance_schema.data_locks`: the judging transaction's record locks on
  the proofs and provenance), for `factorChanged()` of a members-guard session among three, the newest and the middle
  one, under a tenant policy asking a further factor (a check reading the further-factor kinds, or every kind), a
  multifactor requirement met by accepted evidence, or a named connection:

  | Shape                                                       | Newest session                          | Middle session                                    |
  |-------------------------------------------------------------|-----------------------------------------|---------------------------------------------------|
  | First factor only                                           | 1 next-key, and the gap to the supremum | 1 next-key, and the gap before the next session's |
  | First factor, further factor, recovery code (kinds or none) | 3 next-key, and the gap to the supremum | 3 next-key, and the gap before the next session's |
  | The same and a voided further factor                        | 4 next-key, and the gap to the supremum | 4 next-key, and the gap before the next session's |
  | External first factor, evidence accepted                    | 1 next-key, and the gap to the supremum | 1 next-key, and the gap before the next session's |
  | Connection named, provenance present                        | 1 next-key; the provenance row          | 1 next-key; the provenance row                    |
  | Connection named, no provenance                             | the provenance gap to the supremum      | the gap before the next provenance key            |

  Each next-key lock comes with a record lock on the proof's row. In the last row no session had provenance, so the gap
  before the next provenance key ran to the supremum for the middle session too; when a later session was established
  externally, that gap ends at its key, and a new external sign-in, whose key comes after it, does not wait. Before, the
  judgement took none of these. A refresh's issuance (`history(true)`) of the same session takes the same records and
  the same edge gap, so a judgement before a refresh's, a switch's, a step-up's, a reauthentication's or an activation's
  issuance takes early what the issuance holds later, and adds only the provenance lock where the policy names
  connections; `factorChanged()`, `factorRemoved()`, a pending action that leaves the session pending, a refresh or a
  switch that returns it to pending, and a reauthentication at the provider its tenant refuses hold them without an
  issuance. `tenantPolicyChanged()` over three sessions holds every judged session's records, the gap after the newest
  and the gaps between them (and with a named connection the provenance gap) until it commits; it also holds every key
  of the tenant's live sessions in memory for the call (for a thousand and one sessions its peak memory rose by about 70
  KB, to 21.6 MB, measured on SQLite). The trade is right: the reads judge security state (whether a session keeps
  acting or returns to pending, whether a voided factor still counts, whether a reused key still establishes through the
  tenant's connection), and a stale read fails open in the void and reuse cases; the added waits fall where an
  issuance's already do (the edges of each judged session's range, and the provenance only when connections are named),
  happen only on MySQL and MariaDB at REPEATABLE READ, last as long as the judging transaction, and are of the class the
  sessions guide already documents for an issuance inside a caller's transaction; and InnoDB gives no narrower current
  read at REPEATABLE READ.
- Measured the same way for a freshness judgement under the lock (a gate verdict, `freshProof()` asked current), the
  session's row held `X,REC_NOT_GAP`: for `factor_change` (its two kinds, `additional_factor` and `recovery_code`) on
  the middle of three sessions with a first factor and one step-up, a next-key lock on the session's own
  `additional_factor` and `first_factor` entries, a next-key lock on the next session's first entry in the index (its
  `additional_factor`), and a record lock on the answered proof's row; on the newest session the same, with the supremum
  in place of the next session's entry. With the caller's requirement taking `additional_factor` alone, the session's
  own entry and the gap before its `first_factor` entry, and no neighbour's entry or supremum. For the five kinds
  `identifier_change` and `password_establishment` take by default, with about sixty sessions, the gate's shape and a
  record lock on each row read; on a near-empty table (three sessions, six proofs) the optimiser scanned the primary key
  and next-key-locked every proof row and the supremum until the transaction ended, as any locking read of a tiny table
  does (the requirement judgements' included). Before, the judgements took none of these; the trade is the requirement
  judgements': a stale read fails open on a voided step-up, and the waits fall at the edges of the judged session's
  range, only on MySQL and MariaDB at REPEATABLE READ, for as long as the judging transaction (the gate's, as long as
  the factor package's).
- An exception from the evidence policy or the link contract, and a database error (a serialization failure, a lock
  wait timeout or a deadlock included), propagates, and the package never retries. Laravel rethrows a concurrency error
  raised inside a savepoint without rolling the caller's transaction back, and MySQL rolls back only the statement on a
  lock wait timeout by default, so the caller rolls its whole transaction back and retries it whole.
- All the accepted evidence the session holds (within `EVIDENCE_LIMIT` proofs) is judged against a requirement, newest
  first: a later reauthentication whose evidence was accepted only as an additional verification or phishing resistance
  leaves an earlier multifactor acceptance to meet a multifactor requirement while its own time allows, so such a
  reauthentication is issued exactly as one without evidence would be.

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
  meets a multifactor freshness requirement. The factor-change gate (`SessionService::factorChange()`) asks freshness
  for `factor_change`, or `first_additional_factor` for an identity's first additional factor, excluding the factor a
  replacement or removal names, before the change, under the session's lock and on its proofs as committed; once it is
  made, a removal or replacement judges the current session
  again with `factorRemoved()` and an addition with `factorChanged()`, which writes the session's issuance guard, then
  reads the proofs current, whatever the caller's transaction read first, and voids none. A sibling that needs more
  rebinds `FreshnessPolicy` until the value is extended.
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
- `src/Sessions/ActiveSessionProofs.php`, `src/Sessions/Concerns/LooksUpSessions.php` (`proofs()`, `firstFactor()`),
  `src/Context/ContributionSubject.php` (`proofs()`, `firstFactor()`): the public reads of an active session's proofs.
- `src/Contracts/ExternalEvidencePolicy.php`, `src/External/*` (`ExternalEvidence`, `EvidenceSubject`,
  `EvidenceAcceptance`, `InsufficientEvidence`), `src/Requirements/RequirementJudge.php`,
  `src/Tenancy/SessionEvidence.php`.
- `src/Contracts/FreshnessPolicy.php`, `src/Freshness/*` (`FreshnessRequirement`, `Operations`, `FreshnessSettings`,
  `ConfiguredFreshness`).
- `src/Sessions/RecentAuthentication.php`, `src/Sessions/Reauthentication.php`, `src/Sessions/FactorChangeGate.php`,
  `src/Passwords/PasswordChanges.php` (`establish()`): the freshness judgements under a session's lock.
- `src/Events/SteppedUp.php`, `src/Events/Reauthenticated.php`; `src/Console/CheckConfigurationCommand.php`
  (`[freshness]`).

## Authoritative Tests

- `tests/Feature/Proofs/SignInProofsTest.php`, `SignInProofTest.php`: the first factor and provenance of every sign-in
  path, kept across a pending session and a choice of principal, a superseding sign-in's own, a refused or cancelled
  write rolled back.
- `tests/Feature/Proofs/SessionProofsTest.php`, `tests/Unit/Proofs/ProofHistoryTest.php`: what counts, the aggregate
  read, `auth_time` and `amr` (order, `mfa`, reauthentications), the additional verification, recovery code,
  multifactor report and step-up time the authentication context reads, the current reads' shared lock, on MySQL
  and MariaDB only, reading what the plain read does, and a page's time given in any zone read as its instant.
- `tests/Feature/Requirements/RequirementJudgeTest.php`, `tests/Feature/Tenancy/TenantPolicyCheckTest.php`,
  `tests/Feature/Sessions/PendingEvaluationTest.php`, `PendingTransitionsTest.php`, `FactorRevocationsTest.php`,
  `PendingSessionsTest.php`, `ExternalReauthenticationTest.php`, `TenantPolicyChangesTest.php`,
  `RefreshCredentialTest.php`, `tests/Integration/Jwt/RefreshTokenExchangeTest.php`,
  `tests/Integration/Sessions/SessionSwitchTest.php`, `tests/Unit/Requirements/ProofSourceTest.php`: every read of a
  judgement made under the session's lock is current (on SQLite through `Tests\Concerns\MarksSharedLocks`, which names
  MySQL as the driver and marks the lock in the SQL), the unlocked ones plain, the proven session locked before the
  proofs, and every session row before any proof in a policy change.
- `tests/Integration/Sessions/CurrentProofReadsTest.php`: every judging path (a factor change and removal, a refresh, a
  switch and its grace retry, `satisfy()` and `choose()`, a reauthentication at the provider and a policy change) and
  the external standing, inside a caller's transaction that read before another connection committed a step-up, voided
  a proof, accepted evidence or reused the key, judges what was committed at READ COMMITTED and on MySQL at REPEATABLE
  READ, and fails to serialise at PostgreSQL's REPEATABLE READ; so do the public proof reads, after a step-up, a void, a
  revocation and a reused key (by key the new session's first factor, by a subject's earlier instance nothing), a read
  followed by a step-up and a factor change of the session in the same transaction commits with no wait and no failure
  to serialise, and outside a transaction they read what is committed and lock nothing.
- `tests/Feature/Sessions/ActiveSessionProofsTest.php`, `tests/Feature/Sessions/LooksUpSessionsTest.php`,
  `tests/Feature/Context/ContributionSubjectTest.php`: the public reads by key and by instance (the service's too), the
  filter, order and bound, a time given in any zone, the limit refused before any statement, every session they may not
  answer for answering nothing with at most the row's read, a session that is not an Eloquent model never looked up, a
  reused key, proofs bound elsewhere under the key, the row's lock and the current read only inside a transaction on
  the session model's connection, and a read then a step-up and a factor change of the session in one transaction
  locking only its row; over HTTP through `Auth::sessions()`, and for the subject's given session, never the
  request's.
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
  configuration and its failures, the newest meeting proof, and no provider's evidence meeting multifactor freshness;
  every answer, a proof's and until when, asked plainly and, inside a transaction, current, alike; asked current,
  locking the session's row and reading its proofs with the shared lock, throwing outside a transaction before any
  statement, and a session that is not an Eloquent session answered with no statement either way.
  `tests/Feature/Proofs/SessionProofsTest.php` covers `newestMeeting()` current, and
  `tests/Unit/Contracts/ContractDeclarationTest.php` the read mode's place on the contract.
- `tests/Feature/Sessions/FactorChangeGateTest.php`, `tests/Feature/Passwords/PasswordChangesTest.php`: the gate's and
  an establishment's freshness judged on the proofs as committed, a bound policy asked current (for an establishment,
  its current answer deciding).
- `tests/Feature/IdentifierChanges/RecentAuthenticationTest.php`: the identifier change's freshness, only the check
  under the lock reading the session's proofs current.
- `tests/Feature/IdentifierChanges/ReboundFreshnessPolicyTest.php`: a policy the application binds is the one asked,
  plainly before the transaction and current under the lock, whose current answer decides; the locked row is judged
  live whatever it answers.
- `tests/Integration/Sessions/CurrentProofReadsTest.php` (the gate, and a caller's own `freshProof()` and
  `freshUntil()` asked current) and `CurrentFreshnessReadsTest.php` (an identifier change request and an
  establishment): inside a caller's transaction that read first, a step-up voided meanwhile never counts and one
  committed meanwhile does, at READ COMMITTED and on MySQL at REPEATABLE READ, PostgreSQL's REPEATABLE READ failing to
  serialise until the retry; the gate also with a bound decorator of the default that passes the read mode on; the
  identifier change's plain first check refusing a step-up committed after the snapshot at REPEATABLE READ on both
  engines.
- `tests/Integration/Sessions/ConcurrentFactorChangeTest.php`: in two processes, a gate asked inside a caller's
  transaction that read first waits on the session's row while a factor's removal voids the step-up, then refuses the
  change (`step_up_required`), at READ COMMITTED and REPEATABLE READ on MySQL and PostgreSQL, PostgreSQL's REPEATABLE
  READ failing to serialise until the retry; and the gate racing a revocation either way.
- `tests/Integration/Passwords/ConcurrentProofSpendingTest.php`: an establishment crossing a neighbouring session's
  proof deadlocks on MySQL at REPEATABLE READ (thrown on as `DeadlockException`, nothing kept, a retry establishing),
  waits and completes at READ COMMITTED, and fails to serialise at PostgreSQL's REPEATABLE READ until the retry.
- `tests/Integration/Sessions/ConcurrentSwitchAndRevocationTest.php`: a step-up and a revocation racing on the session's
  row lock.
- `tests/Integration/Sessions/ReusedSessionKeyTest.php`: a key the database issues again inherits no proofs.
- `tests/Integration/Sessions/ConcurrentFreshSignInsTest.php`: sign-ins of different identities neither wait on each
  other nor deadlock while clearing their keys.
- `tests/Integration/Sessions/ConcurrentIssuanceAndSignInTest.php`: a sign-in waits for a caller's transaction holding
  an issuance, a factor change's judgement or a gate verdict of the newest session, and a step-up of the session next
  to it on either side for one holding a refresh, a factor change's judgement or a gate verdict of that session, only
  on MySQL at REPEATABLE READ, and neither deadlocks.
- `tests/Integration/Proofs/ByteDistinctBindingTest.php`: session keys that differ only in case or by a trailing space,
  and `amr` values that differ only in case, stay apart.
- `tests/Integration/Sessions/ReplicaExternalSessionsTest.php`: the provenance and the accepted evidence read on the
  primary.
- `tests/Integration/Proofs/ReplicaProofsTest.php`, `tests/Integration/Migration/ProofTablesSchemaTest.php`,
  `tests/Performance/ProofQueryBudgetTest.php`, `benchmarks/Proofs/ProofHistoryBench.php`;
  `tests/Integration/Database/StorageConnectionSessionsTest.php`: the public reads on the primary and on the storage
  connection, locking only for a transaction there, and their query budgets.

## Change Triggers

- Storing `auth_time` or `amr` instead of deriving them, or reading proofs from a replica.
- Letting a reauthentication add `amr` values without an accepted evaluation, or working `mfa` out from the values.
- Recording or counting a provider's evidence the evidence policy did not accept, letting it meet part of a
  requirement, storing an evidence time after the time it was judged at, or letting freshness count it as multifactor
  authentication.
- Letting an external reauthentication through any link but the one the session's provenance records, or locking the
  session before the link contract is asked.
- Judging freshness on the latest authentication time rather than the proof that meets the requirement.
- Letting a step-up or a reauthentication issue a refresh token, move a deadline, or write the session row beyond its
  issuance guard.
- Taking a password as an identifier change's proof where the requirement asks for more than a first-factor
  reauthentication.
- Reading a proof history unbounded by the session's distinct combinations.
- Reading a session's proofs or provenance plainly in a requirement judgement made under the session's lock, taking a
  shared lock in one made without it, or taking a session row after a judgement has read proofs, beyond the two flows
  the lock order above accepts (the factor package's removal after the gate, and an establishment's ending of the
  identity's other sessions).
- Asking freshness plainly in a judgement made under the session's lock, locking in the identifier change's first
  check, or answering a current `freshProof()` or `freshUntil()` outside a transaction.
- Answering a public read of a session's proofs for a session that is not one of the guard's live, active sessions of a
  person (or, by instance, no longer that session), reading them plainly inside a transaction, or making `SessionProofs`
  public.
