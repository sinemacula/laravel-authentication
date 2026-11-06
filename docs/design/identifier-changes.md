# Identifier Changes

## Purpose

This note records how `Auth::identifierChanges($guard)` replaces an identity's email address or phone number: what a
request must prove, where a pending change lives and how a newer one replaces it, how a confirmation spends its proof
only together with the change, how uniqueness of the normalised identifier is kept under a race, which proofs a change
outdates, and why the change stands when the notice to the old identifier fails.

## Invariants

- The identity keeps its identifier until the new one is proven: by a one-time code sent to the new identifier
  (`CodePurpose::CHANGE_IDENTIFIER`) or by a signed link the application sends there. Nothing else changes it.
- One change waits per identity and type, in `identifier_changes`, keyed by `SHA-256(AccountAttempts::account($identity)
  . "\0" . type)` (not secret, so not keyed). It records the guard that requested it, the identifier it replaces exactly
  as stored (`previous`, `null` for none), the new one in normal form, a random `request_id`, and when it was requested
  and expires (whole seconds). A request writes it whatever row was there, through any guard: an `UPDATE` by key of the
  change it read, an `insertOrIgnore` when it read none, and each falls back to the other when a concurrent write got
  there first. Inside the request's transaction an `UPDATE` of a missing key would make MySQL lock the gap it searched
  until the commit, and two requests inserting into one gap would deadlock, so a missing row is inserted, never updated;
  the request's code is issued the same way (`OneTimeCodes::issueFirst()`). The newest request wins; the code of the one
  it replaced is invalidated. No unique violation on a package table is caught.
- A code is bound with `CodeBinding::identifierChange(guard, type, new identifier, identity, request_id)`, so it proves
  that one request; a link carries the guard, the identity, the type, the purpose `change_identifier`, the request and
  `SHA-256` of the new identifier in normal form, signed by Laravel's URL generator, and expires with the change. A
  change proven by code expires no later than its code.
- Every read that decides a proof, an identity, a session or a pending change is on the write connection. Every
  comparison of a secret or digest uses `hash_equals`. One `now` per operation; a deadline has passed from the second it
  names.
- A request proves a recent authentication (`Sessions\Reauthentication`) as the freshness policy's `identifier_change`
  operation requires (`Contracts\FreshnessPolicy`, see `proofs-and-freshness.md`): a session of the identity's, of this
  guard, live, read again by key, holding a counting proof of a kind the requirement takes, made within its age (a
  refresh or a switch records no proof; a reauthentication or a step-up does; a sign-in starts a new session); or the
  current password, a first-factor reauthentication made now, taken only when the requirement takes
  `first_factor_reauthentication` and asks for neither multifactor authentication nor phishing resistance, on a guard
  whose application allows the `password` method, checked in the guard's credential timebox against the identity read
  again through the guard's provider, counted under `sign_in` against the account and the IP address and given back
  when correct. There is no trusted confirmation time: a further factor proves the change only once recorded on the
  session by a step-up. The requirement is read before anything is counted, so a malformed one fails every request and
  confirmation closed.
- A request checks the proof, the new identifier and the limits first, on the identity's row read again by key on the
  write connection; the limiter never counts inside the transaction that follows, where a counter's row would stay
  locked until the commit and MySQL deadlocks two transactions that each create a counter in one gap of the index. Then,
  in one transaction on the identity's connection, it locks the identity's row (`Database\IdentityLock`), and, for a
  session proof, the session's row (`SessionRecords\SessionLookup::lock()`), and checks again that the proof stands
  (`RecentAuthentication::stands()`: the session as locked and the freshness policy asked again, under that lock, on
  the session's proofs as committed, `freshProof()` asked current; for a password, the locked row's hash is the one
  read before the password was checked) and that the new identifier is not the current one. So a step-up a factor's
  removal voided before the lock never counts, whatever a caller's transaction read first.
  The first check reads plainly and locks nothing (locking there would take the session's row before the identity's,
  against the order the transaction takes): inside a caller's transaction at REPEATABLE READ it misses a step-up
  committed after the caller's snapshot and refuses (`reauthentication_required`), failing closed. A password write
  takes the identity's lock with its `UPDATE`, and a standalone bulk revocation updates the session's row before it
  deletes the pending changes, so a password write racing a request proven by the old password, and a revocation of the
  proving session, come either before that check, which then fails, or after the change is written, which they then
  cancel. A password proof racing a revocation that leaves the password as it is is not serialised. The current
  identifier and whether it is verified are read from the row as locked. A refusal under the lock writes nothing,
  commits, and gives the `identifier_change` slots back.
- A confirmation by code takes the account's and the IP address's `identifier_change` slots before the challenge id and
  the code are judged, so a full limit answers `rate_limited` even for a malformed check, and a malformed one keeps its
  slots; only a made change gives them back. A rate-limited refusal is still reported, so the volume of failure events
  is bounded by the application's own request throttling.
- A request needs a new identifier the type's normaliser accepts (a type without a normaliser is a misconfiguration)
  that is not the current one in canonical form, and a slot of `rate_limits.identifier_change` for the new identifier,
  the identity's account and the IP address, given back only by a refusal under the lock. It never looks for another
  holder of the new identifier, so its answer cannot tell whether one exists.
- A confirmation runs in one transaction on the identity's connection, which must be the storage connection (the codes'
  and the pending changes'), checked by `Database\SharedConnection`, the rule password resets share, before anything is
  counted or written. It locks the identity's row first (`Database\IdentityLock`, the lock order every transaction that
  writes an identity with its proofs follows, so a password write, a reset, a request or a cancellation racing it waits
  rather than deadlocks), refuses an identity no longer stored (`invalid_credentials`) or not active as its row reads
  under the lock (`identity_inactive`), whatever the instance given says, with nothing counted, reads the change (this
  guard's, live), checks the proof, deletes the change while it still names its request, looks for another holder
  through the guard's provider, invalidates the outdated proofs and replaces the identifier conditionally on `previous`
  (`HasChangeableIdentifiers::replaceIdentifier()`, which records the new one as verified). A refused proof commits, so
  a code's attempt count is durable; any refusal after the proof is accepted throws inside the transaction, so it rolls
  back whole and the proof is not spent.
- A change invalidates, in one statement, for every `jwt` guard whose provider can return the identity
  (`JwtGuards::namesFor()`: its configured model reads the identity's table on the identity's connection, or it names no
  model) and for both the canonical previous identifier and the new one: the sign-in, password reset and password reset
  link codes, and the identity's verification codes. A sign-in or reset code names its guard, type and identifier, not
  an identity, so through a guard over another table it belongs to whoever holds the identifier there, and is kept.
  Verification links need nothing: they carry the digest of the identifier they verify.
- `IdentifierChangeRequested` and `IdentifierChanged` are dispatched once the write commits on the identity's connection;
  the code's delivery and the notice are queued through `Delivery\QueuedDelivery` on the same commit. A caller's
  rollback undoes the write and dispatches nothing.
- A machine identity has no identifiers to change: every method throws `InvalidArgumentException`. An identity that is
  not an Eloquent model implementing `HasChangeableIdentifiers` throws `LogicException`; so does an unbound
  `IdentifierChangeNotifier`, on requests and confirmations.

## Success Path

1. `requestByCode($identity, 'email', $new, Reauthentication::session($session), $client)`: configuration checked (a
   code needs a `OneTimeCodeSender` bound, as every change needs a notifier); the proof is recent; the new identifier is
   normalised and differs; the limits have room. In one transaction: a code is issued for a fresh `request_id`, the
   change is written, the replaced change's code invalidated, the code's delivery queued. After commit:
   `IdentifierChangeRequested`, and the job sends the code to the new identifier while the code is live and the change
   still names its request and guard.
2. `confirmByCode($identity, 'email', $challengeId, $code, $client)` (the challenge id `requestByCode()` answered): in
   one transaction the code is accepted and used up, the change deleted, no other holder found, the outdated proofs
   invalidated, the identifier replaced and verified. After commit: `IdentifierChanged`, and the notice to `previous` is
   queued.
3. `requestByLink(...)` / `confirmByLink($link, $client)` are the same with a signed link in place of the code: the link
   is returned for the application to send, and the confirmation takes it as `SignedLink::fromRequest()` captured it
   (the address and the raw query string) and checks its signature, expiry, purpose, guard, request and digest again
   from those values.

## Failure / Edge Cases

- A confirmation link's `GET` should only show a confirmation whose form posts back to the same signed address (the
  documented routes do): mail scanners and link previews fetch links unasked, and a change confirmed by such a fetch, of
  an address mistyped into a stranger's scanned mailbox, would make that address the one password resets go to.
  The signature is in the link's query string, which `SignedLink::fromRequest()` captures as received, so the `POST`
  carries it.
- No recent authentication, a wrong password, or a password on a guard that does not allow passwords (a code- or
  passkey-only application, which counts nothing): `reauthentication_required`. A password checked too often: the
  `sign_in` limits' wait, as `rate_limited`.
- Two confirmations of one change: the conditional delete lets one through; the other is `invalid`.
- Two identities confirming one value: the provider's check may find neither (the other has not committed), so the
  application's unique index decides. The loser's statement fails inside the confirmation's own transaction, a savepoint
  when the caller holds one, so PostgreSQL's aborted statement is rolled back with it and the caller's transaction stays
  usable; the loser answers `taken` with its change and code intact. Without a unique index the check is best effort and
  a race can leave two holders.
- The identifier changed by another path between request and confirmation: the conditional replacement writes nothing,
  the transaction rolls back, `invalid`.
- A confirmation through another guard, or a link signed for another guard: `invalid`; the change is left waiting.
- A confirmation for an identity that is not active (`ActivationPolicy::isActive()`, on the row as locked): `invalid`,
  reported as `identity_inactive`, before anything else is read, counted or spent. The link needs no session, so no
  guard has checked the identity, and an account suspended after the request must keep its identifier; once active
  again, the change can still be confirmed while it waits, unless the suspension ended its sessions through
  `identityDeactivated()`, which cancels it (below).
- An expired change: `expired` (`code_expired`, or `link_expired` for a link, also when the link's own signature has
  not yet expired at the change's last second).
- The notifier fails: the job fails and the queue retries; the change stands. The new identifier was proven and the
  request recently authenticated, so rolling back on a mail outage would block the owner while protecting nothing the
  proof did not, and notices are dispatched after commit by design, outside the atomic unit.
- The old identifier was never verified (an address mistyped at registration, say): it may be a stranger's. The pending
  change records whether it was verified when the change was requested (`previous_verified`, read with
  `hasVerifiedIdentifier()`), and the notice carries it (`IdentifierChangeNotice::$previousVerified`), so the notifier
  decides what, if anything, to tell it; the package still queues the notice, since whether an unverified address is
  the owner's is the application's to judge. The documented notifier sends nothing to one, and names only part of the
  new identifier to a verified one.
- Sessions are not revoked by a change; the application may sign the identity out everywhere if it wants that.
- Every bulk revocation of an identity's sessions deletes every pending change of the identity, of each type with a
  registered normaliser and through any guard, in one `DELETE` by key inside the revocation's transaction on the storage
  connection (`PendingChanges::forget()`, from `Sessions\RevocationWriter` for the scope
  `SessionService::revokeSessions()` builds): `signOutEverywhere()`, `revokeSessions()`, `passwordChanged()`,
  `passwordReset()`, `credentialRemoved()`, `factorRemoved()`, `factorReset()`, `identityDeactivated()`,
  `identityDeleted()`, and so `PasswordService::set()` for a change or a reset, a reset by link or code, and the
  listeners. A link needs no session, so a change requested from a session that ended (an attacker's) would otherwise
  still move the account to the requester's address once its owner had signed it out, reset its password or had it
  suspended, whether or not the identity has a password at all. The change's code needs nothing: it is checked only
  against its pending change's binding, so without the row it confirms nothing until it is pruned. Revoking one session,
  ending a principal's sessions and a registration leave the identity's other sessions, and so its pending changes. A
  deactivation that only clears the identity's active flag, without `identityDeactivated()`, keeps them, and the change
  can be confirmed once the identity is active again.

## Implementation Anchors

- `src/IdentifierChanges/IdentifierChangeService.php` (`Auth::identifierChanges()`), `ChangeRequests.php`,
  `ChangeConfirmation.php`, `ChangeRefused.php`, `PendingChanges.php`, `RequestedChange.php`, `ChangeLinks.php`,
  `PresentedChangeLink.php`, `IdentifierChangeSettings.php`, `IdentifierChangeRequest.php`,
  `PendingIdentifierChange.php`, `IdentifierChangeNotice.php`, `Enums/*`.
- `src/IdentifierChanges/SendIdentifierChangeCode.php`, `SendIdentifierChangeNotice.php`; `src/Http/SignedLink.php`.
- `src/Sessions/Reauthentication.php`, `src/Sessions/RecentAuthentication.php`, `src/Contracts/FreshnessPolicy.php`,
  `src/Freshness/ConfiguredFreshness.php`, `src/SessionRecords/SessionLookup.php` (`lock()`),
  `src/Database/IdentityLock.php`.
- `src/Contracts/HasChangeableIdentifiers.php`, `src/Concerns/ProvidesIdentifierChanges.php`
  (`replaceIdentifier()`), `src/Contracts/IdentifierChangeNotifier.php`, `src/Testing/FakeIdentifierChangeNotifier.php`.
- `src/Models/IdentifierChange.php`, `database/migrations/2026_04_06_000007_create_identifier_changes_table.php`.
- `src/Events/IdentifierChangeRequested.php`, `src/Events/IdentifierChanged.php`.
- `src/Console/CheckConfigurationCommand.php` (`[identifier_changes]`), `src/Database/SharedConnection.php` and
  `src/Console/PasswordChecks.php` (the connection rule and its warning, shared with password resets).
- `src/Config/JwtGuards.php` (`namesFor()`: the guards whose proofs a change outdates).

## Authoritative Tests

- `tests/Feature/IdentifierChanges/IdentifierChangeRequestsTest.php`: writes, deliveries, replacement through any
  guard, a racing first request, limits, refusals, pending and cancel, caller transactions.
- `tests/Feature/IdentifierChanges/IdentifierChangeConfirmationTest.php`: codes and links, every outcome, the provider
  check and the unique index (inside a caller's transaction), a lost delete, the conditional replacement, the
  invalidated proofs, notices and their failure.
- `tests/Feature/IdentifierChanges/RecentAuthenticationTest.php`: the requirement's age from its first second to its
  last, sessions that prove nothing, a refresh that does not renew, a step-up and a reauthentication that do, a password
  taken only when the requirement allows one, checked and counted; only the check under the lock reads the session's
  proofs current. `ReboundFreshnessPolicyTest.php`: the bound policy's current answer under the lock decides (fresh
  plainly but not current refuses).
- `tests/Integration/Sessions/CurrentFreshnessReadsTest.php`: inside a caller's transaction that read first, a step-up
  voided meanwhile refuses the request at READ COMMITTED and REPEATABLE READ on PostgreSQL and MySQL, and one committed
  meanwhile is counted at READ COMMITTED and refused by the plain first check at REPEATABLE READ.
- `tests/Feature/IdentifierChanges/IdentifierChangeServiceTest.php` (misconfiguration, the connection rule),
  `IdentifierChangeRoutesTest.php`, `ChangeLinksTest.php`; `tests/Feature/Database/SharedConnectionTest.php`.
- `tests/Feature/IdentifierChanges/EndedSessionsCancelChangesTest.php`: every bulk revocation of the identity cancels
  its pending changes; one session or a principal's sessions keep them.
- `tests/Integration/IdentifierChanges/ConcurrentIdentifierChangesTest.php`: races on PostgreSQL and MySQL;
  `tests/Integration/Passwords/ConcurrentProofSpendingTest.php`: a confirmation racing a password write, a reset, a
  bulk revocation, a cancellation and a replacing request; a request proven by the password racing a password change,
  either way and between its check and its lock, one proven by its session racing a bulk revocation the same ways, and
  requests for two identities creating their counters, codes and pending changes, neither deadlocking nor waiting;
  `tests/Integration/SessionRecords/SessionLookupLockTest.php`.
- `tests/Integration/IdentifierChanges/ReplicaIdentifierChangesTest.php`: `pending()`, the code's delivery and a
  session's reauthentication read what only the primary holds yet, behind a lagging replica.
- `tests/Integration/IdentifierChanges/ReplaceIdentifierTest.php`, `IdentifierChangeDeliveryTest.php`,
  `PendingChangesTest.php`; `tests/Integration/Models/IdentifierChangeTest.php`,
  `tests/Integration/Migration/IdentifierChangesTableSchemaTest.php`.
- `tests/Unit/Config/JwtGuardsTest.php`: which guards' provider can return an identity.
- `tests/Performance/IdentifierChangeQueryBudgetTest.php`.

## Change Triggers

- Letting a change complete without a proof of the new identifier, or without a recent authentication.
- Checking whether another identity holds the new identifier when a change is requested (its answer would tell).
- Spending a proof outside the transaction that makes the change, or catching a unique violation outside a savepoint.
- Narrowing which proofs a change invalidates, or what a code or link is bound to.
- Rolling a change back, or holding it, on a notice that failed.
