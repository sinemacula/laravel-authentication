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
  the provider asserted. Its answer (`External\ExternalLink`) is the identity and the link's own opaque id.
- The link contract and the evidence policy are asked before the package takes any lock, so the adapter's own locks,
  taken inside its transaction, always come first and the package's session rows (the session reauthenticated, or the
  one a sign-in supersedes) last. No identity row is locked on these paths.
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
5. To reauthenticate, the adapter hands a later result to `reauthenticateExternally($session, $result)`: the method,
   the session as stored (its generation) and its standing, the provider's time and the link are checked before any
   lock; then `ProofIssuance` locks the session's row and checks it again, records an `external_reauthentication` and
   issues one access token whose `auth_time` is the later of the session's and the provider's. An adapter that must
   answer a locked standing before it renews asks `externalStanding($session, $identity, $connectionId, $linkId)` in the
   same transaction, which locks the row and answers `null` or the reason, writing nothing.
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
- A sign-in through a link racing that link's revocation is serialised by the adapter's own lock on the link, taken
  before the session's row; the package documents the order and does not enforce it. The revocation finds the link's
  sessions and their provenance with locking reads, which see what is committed now: a plain read on MySQL's
  REPEATABLE READ would use the snapshot the adapter's transaction opened at its first read, before it took the link's
  lock, and miss a session the sign-in committed meanwhile. The identity's live sessions are locked in key order, as the
  revocation then locks them, until the transaction ends.
- `externalStanding()` outside a transaction on the session model's connection is a `LogicException`, checked before
  anything is read; on an application that does not allow `external_provider` it answers `method_not_allowed`.
- A second `linkScopeWidened()` for the same widening finds nothing live and revokes and reports nothing.

## Implementation Anchors

- `src/Contracts/ExternalIdentityLinks.php`, `src/External/*` (`ExternalResult`, `ExternalLink`, `NoExternalLinks`,
  and the evidence values), `src/Events/ExternalResultUnlinked.php`.
- `src/Sessions/Concerns/SignsInExternally.php`, `src/Sessions/ExternalSignIn.php`, `ExternalResults.php`,
  `ExternalReauthentication.php`, `SessionService.php` (`startFor()`), `SessionPreconditions.php`,
  `SignInMethodManager.php` (`EXTERNAL_METHOD`).
- `src/Sessions/Concerns/EndsConnectionSessions.php`, `src/Sessions/ConnectionRevocations.php` (`link()`),
  `src/Sessions/RevocationSettings.php`.
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
  an exception from the link contract, the byte-exact link id.
- `tests/Integration/Sessions/ConcurrentExternalReauthenticationsTest.php`,
  `ConcurrentExternalReauthenticationAndWideningTest.php`: the races on the session's row lock;
  `ConcurrentExternalSignInAndWideningTest.php`: a widening finds a sign-in committed after its transaction first read.
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
- Storing links, issuing or redeeming handoffs, or verifying provider responses in this package.
