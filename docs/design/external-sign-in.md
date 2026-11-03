# External Sign-in

## Purpose

This note records how a result an external identity provider verified signs an identity in and reauthenticates its
session, how the package finds the identity (only through a link contract the application binds), what it records of
how the session began, and how the sessions established through one link end. The package verifies no provider
response, issues and redeems no handoff, and stores no link: a trusted server-side adapter verifies and redeems, the
link contract answers, and the package starts, reauthenticates and ends sessions.

## Invariants

- Off by default (D21), twice over: an application allows external sign-in only by listing `external_provider` in its
  `methods` (`method_not_allowed` otherwise, checked before the link contract is asked), and the default link contract,
  `External\NoExternalLinks`, links nothing, so no result signs anyone in until an application binds its own.
- A result (`External\ExternalResult`: the connection, issuer and subject, and optionally the connection's tenant, the
  provider's authentication time and session deadline, the policy version checked, and the provider's evidence) comes
  only from a trusted adapter, never from a client: `external_provider` is reserved, so `SignInMethodManager::extend()`
  refuses it, `method()` never resolves it, `signIn()` cannot reach it, and `start()` and `reauthenticate()` refuse it
  as their method (`SessionPreconditions::assertSessionMethod()`). Only `signInExternally()` records a session under it.
- The identity is the one `Contracts\ExternalIdentityLinks::find($connectionId, $issuer, $subject)` answers, through a
  link made through exactly that connection for exactly that issuer and subject, never by email or any other attribute
  the provider asserted. Its answer (`External\ExternalLink`) is the identity and the link's own opaque id. The link id
  is taken from that answer, not from the result, though the verified result an adapter redeems carries one: the
  contract reads, inside the adapter's transaction, the very link it maps the identity through, so the id recorded is
  always that link's and can never name a link other than the one that chose the identity.
- The link contract, and the evidence policy's acceptance of a result's evidence, are asked before the package takes any
  lock, so the adapter's own locks, taken inside its transaction, always come first and the package's session rows (the
  session reauthenticated, or the one a sign-in supersedes) last. In a reauthentication the tenant's authentication
  policy and the evidence policy's `meets()` are then asked under the session's row lock, with the new proof recorded;
  both contracts' docblocks say they must only read, or take no lock the adapter does not already hold. No identity row
  is locked on these paths.
- Every session an external provider established records its provenance once, with the session, pending or active,
  and never rewrites it: the connection and its tenant, the provider's authentication time and deadline, the policy
  version, the id of the link (`link_id`, compared byte for byte: a binary column on MySQL and MariaDB) and the
  accepted evidence. The first proof is the provider's: the connection as an `external_provider` channel, the private
  `amr` value `urn:sinemacula:amr:external_provider`, and the provider's time (now, when it gave none or one after now).
  The provider's deadline is folded into the sign-in's own (`SignInContext::withNotAfter()`).
- A session reauthenticates at the provider only through the very link that established it: the link's identity must
  own it and its provenance must record exactly the result's connection and the link's id (`link_mismatch`); a session
  recorded with no link never matches. Only an access token is issued; the refresh token, the session row, its
  deadlines and its provenance are untouched.
- A link's sessions end only through that link: `linkRemoved()` and `linkScopeWidened()` revoke the identity's live
  sessions, pending ones included, whose provenance records exactly the connection and the link id, leaving its
  sessions through any other link. `linkRemoved()` honours `authentication.revocation.link_removed`;
  `linkScopeWidened()` is mandatory and idempotent. An empty connection or link id is an `InvalidArgumentException`
  before any setting is read.
- Nothing catches or retries a database exception: a serialization failure or deadlock, and an exception from the
  link contract or the evidence policy, propagates and rolls back the caller's transaction, for the adapter to retry
  whole.

## Success Path

1. Inside the transaction in which it redeems a handoff, after its own locks, the adapter calls
   `Auth::sessions($guard)->signInExternally($result, $context)`.
2. The provider's deadline joins the context's; the application must allow `external_provider`; the link contract is
   asked; the result's evidence is judged for the link's identity (`ExternalResults::acceptance()`, see
   `proofs-and-freshness.md`).
3. From the linked identity on, the sign-in is `start()`'s (`SessionService::startFor()`): the identity reloaded
   through the guard's provider (the same class and key, `identity_unknown`), admitted, a passed deadline refused, the
   principals, the identity-level requirement, the tenant and its authentication policy (another connection required:
   `sso_required`), judged against the provider's proof and any accepted evidence in memory. No attempt limit,
   timebox or `Attempting`: nothing is guessed.
4. The session, its first proof and its provenance are written in one transaction, a savepoint in the adapter's; the
   reports and the guard's bind wait for its commit. The result is an active pair or a pending session.
5. To reauthenticate, the adapter hands a later result to `reauthenticateExternally($sessionId, $result)`, with the
   identifier of the session its handoff names (an adapter holds no session object, and the session the request is
   authenticated with is not necessarily that one): the method, the session as stored and its standing, the provider's
   time and the link are checked before any lock; then `ProofIssuance` locks the session's row and checks it again,
   records an `external_reauthentication`, asks the tenant's authentication policy with that proof recorded (as at every
   redemption), and issues one access token whose `auth_time` is the later of the session's and the provider's. An
   adapter asks `externalStanding($sessionId, $identity, $connectionId, $linkId)` for a session's standing, writing
   nothing: with no link id (any link of the connection) and outside a transaction when a reauthentication flow starts,
   locking nothing; with the link id inside the redemption's transaction, before it renews, locking the row until it
   ends.
6. When a link is removed or its scope widened, the adapter calls `linkRemoved()` or `linkScopeWidened()` in that
   transaction (`Sessions\ConnectionRevocations::link()`): the identity's live session keys 500 at a time, then their
   provenance by key filtered on the connection and link and compared byte for byte in PHP, then each chunk locked in
   key order and revoked; the binding is forgotten and `SessionRevoked` reported once it commits.

## Failure / Edge Cases

- A result linked to no identity dispatches `ExternalResultUnlinked` (the guard, the client, the connection and the
  issuer; never the subject) and fails as `external_result_unlinked`, writing nothing. The event is informational: the
  package that links results provisions on its own event, before any handoff, never on this one.
- A refused sign-in reports Laravel's `Failed` and `AuthenticationFailed` (flow `sign_in`); a refused reauthentication
  reports `AuthenticationFailed` (flow `reauthentication`) and is answered, never thrown.
- A reauthentication without the provider's time, or with one before the session began, is `proof_invalid`; through
  another link, another connection, another identity, or on a session no link established, `link_mismatch`.
- A change committed while the reauthentication waits for the session's lock (a revocation, a reissued key, a
  rewritten owner) is judged under the lock: `session_revoked`, `session_unknown` or `link_mismatch`.
- A reauthentication whose session, with its proof recorded, no longer meets its tenant's authentication policy is
  `sso_required` (a connection the tenant no longer admits) or `additional_factor_required` (a further factor the
  session, this proof's accepted evidence included, does not meet): the proof rolls back in a savepoint
  (`Sessions\IssuanceRefused`, caught by `ProofIssuance`) and the row is not written, so no version is recorded and the
  next refresh revokes the session or returns it to pending. A first-factor reauthentication asks no tenant policy.
- A sign-in through a link racing that link's revocation is serialised by the adapter's own lock on the link, taken
  before the session's row; the package documents the order and does not enforce it. The revocation finds the link's
  sessions and their provenance (and a connection's, its provenance) with locking reads, which see what is committed
  now on MySQL: a plain read at REPEATABLE READ would use the snapshot the adapter's transaction opened at its first
  read, before it took the lock on the link or connection, and miss a session the sign-in committed meanwhile. The
  identity's live sessions under `external_provider` are locked in key order, as the revocation then locks them, until
  the transaction ends; only those are looked up in the provenance, so every key asked for exists and MySQL takes
  record locks only, never the gap another identity's next provenance would be inserted into.
- On PostgreSQL even a locking read at REPEATABLE READ or SERIALIZABLE sees only the snapshot the transaction's first
  statement took, and no serialization failure follows (the sign-in changed nothing the revocation locks), so no lock
  order on the adapter's side lets the revocation see that session. A connection's or link's revocation inside a
  caller's transaction at either level is therefore refused with a `LogicException` before anything is read
  (`Database\CommittedReads`): fail closed, for the adapter to run that transaction at READ COMMITTED.
- `externalStanding()` locks the row only inside a transaction on the session model's connection; outside one it reads
  the row on the write connection, so its answer may change before the redemption, which judges it again under the
  lock. Without a link id, a session recorded with no link still never stands. On an application that does not allow
  `external_provider` it answers `method_not_allowed` before anything is read.
- A second `linkScopeWidened()` for the same widening finds nothing live and revokes and reports nothing.

## Implementation Anchors

- `src/Contracts/ExternalIdentityLinks.php`, `src/External/*` (`ExternalResult`, `ExternalLink`, `NoExternalLinks`,
  and the evidence values), `src/Events/ExternalResultUnlinked.php`.
- `src/Sessions/Concerns/SignsInExternally.php`, `src/Sessions/ExternalSignIn.php`, `ExternalResults.php`,
  `ExternalReauthentication.php`, `SessionService.php` (`startFor()`), `SessionPreconditions.php`,
  `SignInMethodManager.php` (`EXTERNAL_METHOD`).
- `src/Sessions/Concerns/EndsConnectionSessions.php`, `src/Sessions/ConnectionRevocations.php` (`link()`),
  `src/Sessions/RevocationSettings.php`, `src/Database/CommittedReads.php`.
- `src/Proofs/Provenance.php`, `ProofWriter.php` (`provenance()`), `SessionProofs.php` (`provenance()`),
  `src/Models/SessionProvenance.php`,
  `database/migrations/2026_04_06_000009_create_authentication_provenance_table.php`.
- `src/Events/Enums/FailureReason.php` (`external_result_unlinked`, `link_mismatch`),
  `src/Events/Enums/RevocationReason.php` (`link_scope_widened`).

## Authoritative Tests

- `tests/Feature/Sessions/ExternalSignInTest.php`: the method and link checks, the unlinked event, admission as
  `start()` admits, the principal, accepted evidence meeting the identity's and a tenant's requirement, a result never
  arriving as input.
- `tests/Feature/Sessions/ExternalReauthenticationTest.php`: the renewal and the later-time rule, every link mismatch,
  the refusals, changes under the lock, the standing.
- `tests/Feature/Sessions/ConnectionRevocationsTest.php`, `tests/Integration/Sessions/ConnectionRevocationsTest.php`,
  `IntegerKeyConnectionRevocationsTest.php`: a link's sessions only, the mandatory and idempotent widening, the
  settings, folded collations, the caller's transaction.
- `tests/Integration/Sessions/ExternalSignInTest.php`, `ExternalReauthenticationTest.php`: the adapter's transaction,
  an exception from the link contract, the byte-exact link id, the largest evidence stored whole.
- `tests/Integration/Sessions/ReplicaExternalSessionsTest.php`: the provenance, the accepted evidence and a link's
  sessions read on the primary, so a session the replica has not seen reauthenticates, stands and is revoked.
- `tests/Integration/Sessions/ConcurrentExternalReauthenticationsTest.php`,
  `ConcurrentExternalReauthenticationAndWideningTest.php`: the races on the session's row lock;
  `ConcurrentExternalSignInAndWideningTest.php`, `ConcurrentExternalSignInAndConnectionDisablingTest.php`: a widening
  or disabling finds a sign-in committed after its transaction first read, is refused at PostgreSQL's REPEATABLE READ,
  and a widening holds up no other identity's sign-in. `tests/Unit/Database/CommittedReadsTest.php`: the isolation
  rule.
- `tests/Unit/External/*`, `tests/Unit/Events/ExternalResultUnlinkedTest.php`,
  `tests/Feature/Sessions/SignInMethodManagerTest.php`, `tests/Unit/Sessions/SessionPreconditionsTest.php`.
- `tests/Performance/SessionServiceQueryBudgetTest.php`, `ProofQueryBudgetTest.php`,
  `ConnectionRevocationsQueryBudgetTest.php`.

## Change Triggers

- Finding an identity by email or any attribute other than the link, or recording an external session anywhere but
  `signInExternally()`.
- Taking any lock of the package's before the link contract is asked, or catching a database exception on these paths.
- Letting a reauthentication through a link other than the one the provenance records, or issuing it a refresh token.
- Letting a link's revocation end sessions through another link, or making the widening optional.
- Finding a connection's or link's sessions with a plain read, or letting either revocation run where its reads see a
  snapshot (PostgreSQL above READ COMMITTED).
- Storing links, issuing or redeeming handoffs, or verifying provider responses in this package.
