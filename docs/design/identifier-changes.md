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
  and expires (whole seconds). A request writes it whatever row was there, through any guard: an unconditional `UPDATE`
  by key, an `insertOrIgnore` when there was none, and the `UPDATE` again when a concurrent insert won. The newest
  request wins; the code of the one it replaced is invalidated. No unique violation on a package table is caught.
- A code is bound with `CodeBinding::identifierChange(guard, type, new identifier, identity, request_id)`, so it proves
  that one request; a link carries the guard, the identity, the type, the purpose `change_identifier`, the request and
  `SHA-256` of the new identifier in normal form, signed by Laravel's URL generator, and expires with the change. A
  change proven by code expires no later than its code.
- Every read that decides a proof, an identity, a device or a pending change is on the write connection. Every
  comparison of a secret or digest uses `hash_equals`. One `now` per operation; a deadline has passed from the second it
  names.
- A request proves a recent authentication (`Sessions\Reauthentication`) within
  `identifier_changes.recent_authentication_seconds`: a device of the identity's, of this guard, live, read again by key,
  signed in within the window (a refresh or a switch does not move `signed_in_at`; a sign-in does); the current password,
  on a guard whose audience allows the `password` method only, checked in the guard's credential timebox against the
  identity read again through the guard's provider, counted under `sign_in` against the account and the IP address and
  given back when correct; or a trusted confirmation time, not in the future.
- A request then needs a new identifier the type's normaliser accepts (a type without a normaliser is a
  misconfiguration) that is not the current one in canonical form, and a slot of `rate_limits.identifier_change` for the
  new identifier, the identity's account and the IP address, never given back. It never looks for another holder of the
  new identifier, so its answer cannot tell whether one exists.
- A confirmation runs in one transaction on the identity's connection, which must be the device model's (the codes' and
  the pending changes'), checked by `Database\SharedConnection`, the rule password resets share, before anything is
  counted or written. It reads the change (this guard's, live), checks the proof, deletes the change while it still
  names its request, looks for another holder through the guard's provider, invalidates the outdated proofs and replaces
  the identifier conditionally on `previous` (`HasChangeableIdentifiers::replaceIdentifier()`, which records the new one
  as verified). A refused proof commits, so a code's attempt count is durable; any refusal after the proof is accepted
  throws inside the transaction, so it rolls back whole and the proof is not spent.
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

1. `requestByCode($identity, 'email', $new, Reauthentication::device($device))`: configuration checked (a code needs a
   `OneTimeCodeSender` bound, as every change needs a notifier); the proof is
   recent; the new identifier is normalised and differs; the limits have room. In one transaction: a code is issued for
   a fresh `request_id`, the change is written, the replaced change's code invalidated, the code's delivery queued.
   After commit: `IdentifierChangeRequested`, and the job sends the code to the new identifier while the code is live
   and the change still names its request and guard.
2. `confirmByCode($identity, 'email', $code)`: in one transaction the code is accepted and used up, the change deleted,
   no other holder found, the outdated proofs invalidated, the identifier replaced and verified. After commit:
   `IdentifierChanged`, and the notice to `previous` is queued.
3. `requestByLink(...)` / `confirmByLink($request)` are the same with a signed link in place of the code: the link is
   returned for the application to send, and the confirmation checks its signature, purpose, guard, request and digest.

## Failure / Edge Cases

- A confirmation link's `GET` should only show a confirmation whose form posts back to the same signed address (the
  README's routes do): mail scanners and link previews fetch links unasked, and a change confirmed by such a fetch, of an
  address mistyped into a stranger's scanned mailbox, would make that address the one password resets go to.
  `confirmByLink()` reads the signature from the request's query, so the `POST` carries it.
- No recent authentication, a wrong password, or a password on a guard that does not allow passwords (a code- or
  passkey-only audience, which counts nothing): `reauthentication_required`. A password checked too often: the
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
- An expired change: `expired` (`code_expired`, or `link_expired` for a link, also when the link's own signature has
  not yet expired at the change's last second).
- The notifier fails: the job fails and the queue retries; the change stands. The new identifier was proven and the
  request recently authenticated, so rolling back on a mail outage would block the owner while protecting nothing the
  proof did not, and notices are dispatched after commit by design, outside the atomic unit.
- Sessions are not revoked by a change; the application may sign the identity out everywhere if it wants that.

## Implementation Anchors

- `src/IdentifierChanges/IdentifierChangeService.php` (`Auth::identifierChanges()`), `ChangeRequests.php`,
  `ChangeConfirmation.php`, `ChangeRefused.php`, `PendingChanges.php`, `RequestedChange.php`, `ChangeLinks.php`,
  `PresentedChangeLink.php`, `IdentifierChangeSettings.php`, `IdentifierChangeRequest.php`,
  `PendingIdentifierChange.php`, `IdentifierChangeNotice.php`, `Enums/*`.
- `src/IdentifierChanges/SendIdentifierChangeCode.php`, `SendIdentifierChangeNotice.php`.
- `src/Sessions/Reauthentication.php`, `src/Sessions/RecentAuthentication.php`.
- `src/Contracts/HasChangeableIdentifiers.php`, `src/Concerns/ProvidesIdentifierVerification.php`
  (`replaceIdentifier()`), `src/Contracts/IdentifierChangeNotifier.php`, `src/Testing/FakeIdentifierChangeNotifier.php`.
- `src/Models/IdentifierChange.php`, `database/migrations/2026_04_06_000007_create_identifier_changes_table.php`.
- `src/Events/IdentifierChangeRequested.php`, `src/Events/IdentifierChanged.php`.
- `src/Console/CheckConfigurationCommand.php` (`[identifier_changes]`), `src/Database/SharedConnection.php` and
  `src/Console/PasswordChecks.php` (the connection rule and its warning, shared with password resets).
- `src/Guards/JwtGuards.php` (`namesFor()`: the guards whose proofs a change outdates).

## Authoritative Tests

- `tests/Feature/IdentifierChanges/IdentifierChangeRequestsTest.php`: writes, deliveries, replacement through any
  guard, a racing first request, limits, refusals, pending and cancel, caller transactions.
- `tests/Feature/IdentifierChanges/IdentifierChangeConfirmationTest.php`: codes and links, every outcome, the provider
  check and the unique index (inside a caller's transaction), a lost delete, the conditional replacement, the
  invalidated proofs, notices and their failure.
- `tests/Feature/IdentifierChanges/RecentAuthenticationTest.php`: the window from its first second to its last, devices
  that prove nothing, a refresh that does not renew, passwords checked and counted.
- `tests/Feature/IdentifierChanges/IdentifierChangeServiceTest.php` (misconfiguration, the connection rule),
  `IdentifierChangeRoutesTest.php`, `ChangeLinksTest.php`; `tests/Feature/Database/SharedConnectionTest.php`.
- `tests/Integration/IdentifierChanges/ConcurrentIdentifierChangesTest.php`: races on PostgreSQL and MySQL.
- `tests/Integration/IdentifierChanges/ReplicaIdentifierChangesTest.php`: `pending()`, the code's delivery and a
  device's reauthentication read what only the primary holds yet, behind a lagging replica.
- `tests/Integration/IdentifierChanges/ReplaceIdentifierTest.php`, `IdentifierChangeDeliveryTest.php`,
  `PendingChangesTest.php`; `tests/Integration/Models/IdentifierChangeTest.php`,
  `tests/Integration/Migration/IdentifierChangesTableSchemaTest.php`.
- `tests/Unit/Guards/JwtGuardsTest.php`: which guards' provider can return an identity.
- `tests/Performance/IdentifierChangeQueryBudgetTest.php`.

## Change Triggers

- Letting a change complete without a proof of the new identifier, or without a recent authentication.
- Checking whether another identity holds the new identifier when a change is requested (its answer would tell).
- Spending a proof outside the transaction that makes the change, or catching a unique violation outside a savepoint.
- Narrowing which proofs a change invalidates, or what a code or link is bound to.
- Rolling a change back, or holding it, on a notice that failed.
