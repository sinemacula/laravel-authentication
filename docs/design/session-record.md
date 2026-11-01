# Session Record

## Purpose

This note records what the package calls the record it keeps per sign-in, and the decisions that came with naming it:
the names and the Laravel names they meet, the claim that still says `did`, what a client proves to have its previous
session replaced, the `superseded` reason, the flags that went, and the index names of the sessions table. A session
is one sign-in, on one application, on one device; its refresh state and its revocation live on it. The record was
called a device before, which mixed it up with the physical client: a client that signs in again on the same device now
gets a new session, so "the device" and "the record" are no longer one thing.

## Invariants

- The record is a session in every name the package gives it: the contracts (`Session`, `EloquentSession`,
  `EloquentSessionOrigin`, `HasSessions`, `ValidatesSessionKey`), the model (`Models\Session`), its traits, the
  `SessionRecords\` helpers, the service methods, events, failure reasons, listeners, testing helpers, configuration
  (`authentication.session.*`, `AUTHENTICATION_SESSION_*`), the table and the pending sign-in's columns
  (`proven_session_id`, `proven_session_refresh_key`). "Device" is left only where it means the physical client, and in
  Laravel's own `logoutOtherDevices()` and `OtherDeviceLogout`.
- The record helpers live in `SessionRecords\`, apart from the `Sessions\` service layer, so the token, guard, HTTP,
  admission and support code may name the record without reaching the service.
- `Models\Session` shares its short name with Laravel's `Session` facade and `Illuminate\Contracts\Session\Session`.
  The package never uses Laravel's session (its guards are stateless), so no package file imports both; an application
  file that needs both imports one under another name. `Auth::session()`, `ContextualGuard::session()` and
  `HasSessions::sessions()` meet no Laravel guard, manager or model method of the same name: `Auth::session()` is the
  bound session, as `Auth::identity()` is the bound identity, and `Auth::sessions()` stays the session service.
- A value object whose own name says session names the record `$record` (`SignedInSession::$record`,
  `ExchangedRefresh::$record`), so no call reads `->session->session`.
- The table defaults to `authentication_sessions`, which keeps it clear of the `sessions` table of Laravel's database
  session driver, and its indexes are named `<table>_owner_index`, `_principal_index`, `_guard_index`, `_idle_index`,
  `_absolute_index` and `_revoked_index`. Laravel's default name for the owner index of the default table is 69
  characters, over MySQL's 64; with these suffixes, a configured name of up to 47 characters fits PostgreSQL's 63.
- The access token still names its session in the `did` claim. Only the enum case says what it names
  (`Claims::SESSION_ID`); the claims change in an item of their own, and nothing here depends on the claim's name.
- Every sign-in is a new session. What a client proves to have its previous session replaced (the device key, in the
  package's reading) is that session's current refresh token, validly signed for the guard: possession of the only
  credential the client holds for it. No other key material exists, and the IP address and user agent never count. It
  only selects the session to replace; the sign-in is admitted on its own credentials first.
- A replaced session is revoked with `RevocationReason::SUPERSEDED` (`superseded`), in the transaction that creates the
  new one.
- `SignedInSession` and `SignedIn` carry no flag saying a session was created. Every sign-in creates one, so on
  `SignedIn` the flag would always be `!$refresh`, and on `SignedInSession` it would only repeat which result carries
  it; `SessionCreated` marks a creation.

## Success Path

- An identity model implements `HasSessions` with a `sessions()` relation over `Models\Session` (or its own
  `EloquentSession` model, configured as `authentication.session.model`), and the shipped migration creates the table
  under its configured name with the six named indexes.
- A sign-in with the previous session's refresh token in `SignInContext::$refreshToken` revokes that session as
  `superseded` and creates the new one; the reports and their order are `session-service.md`'s.

## Failure / Edge Cases

- A configured table name longer than 47 characters makes an index name longer than PostgreSQL allows, and PostgreSQL
  cuts it short without an error, so the index is not under its documented name; past 48 MySQL refuses it when the
  migration runs. The migration does not check the name itself, as no package migration does.
- A refresh token that proves nothing (another identity's, another guard's or principal's, a revoked session's, a
  previous rotation id) replaces nothing: the sign-in creates a session and revokes none, and nothing is reported.
- A proven session that changed before the replacement's compare-and-swap is not revoked; the sign-in is reconsidered
  without it (see `session-service.md`).

## Implementation Anchors

- `src/Contracts/Session.php`, `src/Contracts/EloquentSession.php`, `src/Contracts/HasSessions.php`.
- `src/Models/Session.php`, `src/Concerns/ActsAsSession.php`, `src/SessionRecords/`.
- `database/migrations/2026_04_06_000000_create_authentication_sessions_table.php`: the table and its index names.
- `src/Jwt/Enums/Claims.php`: `SESSION_ID`.
- `src/Events/Enums/RevocationReason.php`: `SUPERSEDED`.
- `src/Sessions/SessionWriter.php`: `replace()`; `src/Sessions/ProvenSessions.php`: what proves a session.
- `src/Sessions/SignedInSession.php`, `src/Events/SignedIn.php`.

## Authoritative Tests

- `tests/Integration/Migration/SessionsTableSchemaTest.php`
  `testNamesIndexesAfterTheConfiguredTable`, `testMigratesATableNameOfFortySevenCharacters`
- `tests/Integration/Migration/SessionMigrationCollisionTest.php`
- `tests/Unit/Jwt/Enums/ClaimsTest.php` `testEveryClaimKeepsItsWireName`
- `tests/Unit/Contracts/ContractDeclarationTest.php` `testNoContractNamesAMethodAfterADevice`
- `tests/Unit/Events/Enums/FailureReasonTest.php`: the failure and revocation values, `superseded` among them
- `tests/Unit/Events/SignedInTest.php`
- `tests/Feature/Sessions/SessionWriterTest.php` `testReplaceRevokesTheProvenSessionAndWritesANewOne`,
  `testReplaceMissesARowThatChangedSinceItWasProven`
- `tests/Feature/Sessions/SessionEstablishmentTest.php` `testAProvenSessionIsReplacedAndReportedInOrder`
- `tests/Integration/Sessions/ConcurrentSignInReplacementTest.php`

## Change Triggers

Update this note when any of the following change:

- the name of the record, its contracts, model, table, configuration or columns, or where its helpers live
- the claim that carries the session, or its enum case
- what proves a previous session for replacement, or the reason a replaced session is revoked with
- the index names of the sessions table, or the longest table name they fit
- whether a sign-in's results or events say a session was created
