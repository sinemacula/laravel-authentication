# Device Lifecycle

## Purpose

This note records what happens to a device after its session starts: which devices count as active and how an
identity's devices are listed, how sessions are signed out and revoked, and when a device whose session ended is
deleted. Starting a session is in
`session-service.md`; refresh rotation and replay are in `refresh-rotation-and-replay.md`.

## Invariants

- A device is active while `revoked_at` is null and both `idle_expires_at` and `absolute_expires_at` are after now: a
  deadline has passed from the second it names, as on the bearer, refresh and sign-in pin paths
  (`TokenLifetimes::hasEnded()`). The `active()` scope `ActsAsDevice` brings and the listing apply the same rule through
  `ActiveDevices::constrain()`, with the columns of the model's name accessors, so a model without the trait is listed
  the same way.
- The listing (`SessionService::devices()`, from `ManagesDevices`) reads the identity's `devices()` relation on the
  write connection (the query itself through `WriteConnection::query()`, and anything the relation reads while it is
  built inside `WriteConnection::during()` for the identity), so a revocation the primary holds is never listed as live.
  It covers every guard: a device list shows every session the identity has.
- The order is total on every database: last use, most recent first, with never-used devices last (an explicit
  `CASE ... IS NULL` term, because PostgreSQL sorts nulls first in a descending order and MySQL and SQLite last), then
  the key, newest first. Pages are therefore stable.
- A `DeviceSummary` never holds a digest, the rotation time, a revocation column, the owner or the principal; `current`
  compares the listed device with the guard's bound device by class and identifier.
- Revoking marks the device (`revoked_at`, `revoked_reason`, both digests cleared) with one conditional `UPDATE ...
  WHERE pk AND revoked_at IS NULL` on the device's own connection (`RefreshRotationStore::revoke()`), mirrored in memory
  only when it changed the row. It is idempotent, the first revocation's time and reason are kept, and only the call
  that changed the row reports `DeviceRevoked`, through `AfterCommit` on the device's connection.
- `signOut()` (and `JwtGuard::logout()`) revokes the guard's bound persisted device as `signed_out`, then dispatches
  `Logout` when an identity was bound, then `forgetUser()`. A device that is not an Eloquent `EloquentDevice` is only
  forgotten.
- `revokeDevice()` reads the device through the owner's `devices()` relation on the writer (`IdentityDevices::find()`),
  with the key-shape check first, so another identity's device is "not found" (`false`) and never revealed.
- A bulk revocation (`revokeDevices()`, `revokePrincipalDevices()`, `signOutEverywhere()`, and the security-change
  methods) is a list of `RevocationScope`s: (1) each scope's `HasTokensValidAfter` cutoff moved to `$now` on its own
  connection; (2) one transaction on the device model's connection that reads each scope's unrevoked devices on the
  writer in key order (`lazyById`, chunks of 500), revokes each conditionally, deletes the scope's pending sign-ins (by
  owner, or by principal) and, for an identity's scope whose identity implements `HasChangeableIdentifiers`, its pending
  identifier changes (by key, every type with a registered normaliser: a change link needs no session, so one requested
  from a session that ends must end with it); (3) once committed, `DeviceRevoked` per revoked device, then
  `SignedOutEverywhere` per scope, also when it revoked none. A failure in (2) leaves (1) in place: fail-safe, and a
  retry is idempotent.
- An identity's scope is every device its `devices()` relation returns, of every guard; a principal's is every device of
  the configured model whose principal columns record it. An identity without `HasDevices` can hold neither a device nor
  a pending sign-in (no session starts for it), so its scope, and that of a principal whose owner (read afresh on the
  writer through `WriteConnection::stored()`, whatever relation is loaded and in strict mode too) is such an identity,
  reads and deletes nothing and only moves the cutoff: access-only mode needs none of the package's tables to revoke. A
  principal whose owner cannot be read has its devices looked for anyway; an unsaved principal has neither devices nor
  pending sign-ins. A principal scope's events carry that owner as their identity.
- `signOutEverywhere(keepCurrentDevice: true)` keeps the request's device; a request without one (a device-less token)
  is kept by leaving the identity's cutoff unmoved, so the identity's other device-less tokens survive too, until they
  expire.
- The security-change methods (`RevokesOnSecurityChanges`: `passwordChanged()`, `passwordReset()`, `factorRemoved()`,
  `identityDeactivated()`, `principalDeactivated()`, `tenantDeactivated()`) are bulk revocations with their own reason.
  `tenantDeactivated()` checks every listed principal acts within the tenant (`getTenant()` on the writer, through
  `WriteConnection::stored()`, so a `tenant` relation whoever loaded the principal set does not decide and Eloquent's
  strict mode does not stop the read; same class and identifier; for a `CanBeActive` tenant that can no longer be
  loaded, the class and key the `TenantUnavailableException` carries, so a deleted or soft-deleted one still ends its
  principals' sessions; a tenant without `CanBeActive` reads as no tenant once it cannot be loaded, so the application
  calls it before deleting one) before anything is written, de-duplicates by recorded type and id, and ends all of them
  in one device transaction with one `SignedOutEverywhere` each.
- The optional listeners (`RevokeDevicesOnPasswordReset`, `RevokeDevicesOnPasswordChange`,
  `RevokeDevicesOnDeactivation`) run their revocation through `AfterCommit` on the changed model's connection, so a
  rolled-back change revokes nothing. They act through a jwt guard's session service: the guard bound to the
  listener's `$guard`, else the current default guard when it is a jwt guard, else the first jwt guard configured, so a
  route guarded by another driver (`shouldUse()`) still revokes; no jwt guard at all is an `InvalidArgumentException`.
- The password-change observer ignores a save of the user the container's scoped `Sessions\Methods\Rehashing` marks, and
  a save is a rehash only when it re-encodes the password signed in with: both the previous hash (the model's original,
  which Eloquent has not yet synced in `updated`) and the saved hash verify it (the hasher's `check()`; a hash it
  refuses to check is a change). Two rehashes are marked: the one `PasswordSignIn::rehash()` runs through the provider,
  for its identity and password (cleared in `finally`) until a change of that identity's password runs inside it, and
  the one `SessionGuard::attempt()`, `attemptWhen()` and `once()` run through an Eloquent user provider on the instance
  a guard validated during a credential attempt, from Laravel's `Validated` until that guard's `Login`, `Authenticated`
  or `Failed` carrying that instance (`Listeners\TrackCredentialAttempts`, registered by the provider). No event
  separates `attemptWhen()`'s callbacks from that rehash, so a save inside the bracket counts as the rehash only when it
  saves that instance (compared by its weak reference) for the user validated, with the attempt's `password` credential,
  and no change of the user's password has run since: a callback that saves another password revokes, and from then on
  so does every save of the user, a change back to the attempt's password through any instance included. A save taken
  for a rehash is held, not dropped, one per user (the latest), for `OtherDeviceLogout`, which
  `SessionGuard::logoutOtherDevices()` dispatches after its forced rehash, to run (a change like any other). A listener
  of the save may end or make attempts, or change the password in a transaction it rolls back, before that event, so
  nothing else lets go of a save held for an attempt: it is kept until the request or job ends, and a sign-out later in
  the same request or job runs it too, revoking twice. The package's own rehash holds its save only while it runs, so a
  forced rehash inside it (a listener of its save calling `logoutOtherDevices()`) still revokes, and then holds again
  the save held before it, which a forced rehash around it may be waiting for. The forced rehash is so answered as a
  change even inside an attempt's callback or after an attempt that threw after `Validated` and never ended. A
  `Validated` outside an attempt (`validate()`), or a second one within it, marks nothing. Each guard keeps its open
  attempts innermost last, since an `attemptWhen()` callback may attempt again on the same guard: an attempt's end
  closes the innermost attempt that validated the event's instance (or no one), so a nested attempt's `Login` and
  `Authenticated`, or a session or remember-me user resolved inside the callback, leave the outer attempt open for its
  own rehash. Two cases end the outer attempt early, and its rehash then revokes: an `Auth::login()` of its own instance
  inside its callback, and a refused inner attempt that validated that same instance (a provider that caches its users).
  An attempt that threw never ends, so a new attempt of the guard first lets go of every attempt that cannot be running
  around it (its instance is gone or its user's password changed, or it validated no one or was made without a
  password), and a validation lets go of the guard's earlier attempts for the same instance, so a long-running command
  keeps at most one attempt per guard and instance still held; an instance stays held while a save of it is held, so
  what a command keeps grows with the accounts it rehashes. Users are keyed as `AccountAttempts::account()` keys
  accounts (connection, database, prefixed table and key for a model), so the same key in another tenant's database is
  another user. The deactivation observer throws a `LogicException` for a deactivated model that is neither identity nor
  principal: a tenant's deactivation is `tenantDeactivated()`. With both password listeners registered, a broker reset
  is recorded as `password_changed` (the observer sees the save before the application fires `PasswordReset`).
- Pruning (`PrunesDevices`, with Laravel's `model:prune`) deletes a device revoked, or past either deadline, at or
  before now less `authentication.device.prune_after_days`: counted from the end of the session, never from creation.
  Each chunk is one conditional `DELETE`; nothing is read first.
- A pruned device is indistinguishable from an unknown one: its tokens already failed once it was revoked or ended, so
  retention never changes who authenticates.

## Success Path

- `Auth::sessions('api')->devices($identity, 20)` costs a count and a select and returns a `LengthAwarePaginator` of
  `DeviceSummary`, whose JSON uses snake_case keys and ISO-8601 times.
- `model:prune --model=...Device` deletes ceil(N / chunk) chunks and ends with one `DELETE` that finds nothing.

## Failure / Edge Cases

- A sign-in already past its credential check when a bulk revocation reads the devices can still create its device
  afterwards: closing that window would need a lock every sign-in and revocation take on the identity row, which is not
  added. Revocation races with refresh, switch and re-sign-in are safe: each of their compare-and-swaps requires
  `revoked_at IS NULL`.
- A page size outside 1 to 100 is an `InvalidArgumentException` before any read. An identity without `HasDevices`, or a
  `devices()` relation over a model that is not an `EloquentDevice`, is a `LogicException`.
- A retention that is not an integer (or canonical digit string) from 0 to 3650 is an `InvalidArgumentException` when
  pruning runs. With 0, a device is pruned from the second its session ends.
- `PrunesDevices` composes `MassPrunable` and replaces its `prunable()`; using `MassPrunable` beside it is a PHP trait
  collision, so a custom model uses `PrunesDevices` alone. A global scope on the model still narrows pruning: the three
  conditions are grouped.
- A pending sign-in can remember a device that is pruned before it completes; its completion then misses the
  continuation and creates a device.
- Queued listeners of an event about a pruned device cannot re-fetch it.

## Implementation Anchors

- `src/Sessions/ActiveDevices.php`, `src/Sessions/DeviceSummary.php`, `src/Sessions/Concerns/ManagesDevices.php`
  (`devices()`)
- `src/Concerns/ScopesActiveDevices.php` (`scopeActive()`, composed by `ActsAsDevice`), `src/Concerns/PrunesDevices.php`,
  `src/Database/DeviceRetention.php`, `src/Models/Device.php`
- `src/Sessions/Concerns/RevokesOnSecurityChanges.php`, `src/Listeners/RevokeDevicesOn*.php`,
  `src/Listeners/Concerns/RevokesOnceCommitted.php`, `src/Sessions/Methods/Rehashing.php`,
  `src/Listeners/TrackCredentialAttempts.php`
- `src/Sessions/Concerns/ManagesDevices.php`, `src/Sessions/DeviceRevocations.php`, `src/Sessions/RevocationScope.php`,
  `src/Sessions/IdentityDevices.php`, `src/Jwt/RefreshRotationStore.php` (`revoke()`), `src/Guards/JwtGuard.php`
  (`logout()`), `src/Guards/AbstractGuard.php` (`forgetUser()`)

## Authoritative Tests

- `tests/Feature/Sessions/ActiveDevicesTest.php`: the device list over HTTP behind `auth:api`;
  `tests/Feature/Sessions/ScopesActiveDevicesTest.php`: the `active()` scope
- `tests/Integration/Sessions/DeviceListingIntegrationTest.php`, `tests/Integration/Sessions/ReplicaDeviceListingTest.php`
- `tests/Unit/Sessions/DeviceSummaryTest.php`
- `tests/Feature/Sessions/ManagesDevicesTest.php`: logout, sign out everywhere and a device list's revoke over HTTP
- `tests/Integration/Http/RefreshCookieSessionLifecycleTest.php`: logout from outside the refresh cookie's path revokes
  the device and clears the cookie
- `tests/Integration/Sessions/ConcurrentSwitchAndRevocationTest.php`: two revocations in two processes on PostgreSQL
  and MySQL report each device once, after a commit and after a rollback
- `tests/Integration/Sessions/SecurityChangeEndToEndTest.php`: each security-change listener's revocation refused at
  the `auth` middleware and at refresh
- `tests/Feature/Sessions/DeviceRevocationsTest.php`, `tests/Integration/Sessions/DeviceRevocationsTest.php`,
  `tests/Integration/Sessions/SeparateConnectionDeviceRevocationsTest.php`,
  `tests/Integration/Sessions/RevocationScopeTest.php`, `tests/Feature/Sessions/RevocationScopeTest.php`,
  `tests/Integration/Sessions/ManagesDevicesTest.php`
- `tests/Performance/DeviceRevocationQueryBudgetTest.php`
- `tests/Feature/Sessions/RevokesOnSecurityChangesTest.php`,
  `tests/Integration/Sessions/ReplicaRevokesOnSecurityChangesTest.php`,
  `tests/Feature/Listeners/RevokeDevicesOn*Test.php`, `tests/Unit/Sessions/Methods/RehashingTest.php`,
  `tests/Feature/Listeners/TrackCredentialAttemptsTest.php`, `tests/Feature/Sessions/Methods/RehashingAccountsTest.php`,
  `tests/Integration/Process/QueueWorkerRehashingTest.php`, `tests/Performance/RehashingBudgetTest.php`
- `tests/Feature/Models/PrunesDevicesTest.php`, `tests/Feature/Database/DeviceRetentionTest.php`,
  `tests/Integration/Models/DevicePruningIntegrationTest.php`
- `tests/Performance/DeviceListingQueryBudgetTest.php`, `tests/Performance/DevicePruneQueryBudgetTest.php`

## Change Triggers

Update this note when any of the following change:

- what makes a device active, or which columns decide it
- which security change ends which sessions, or what the optional listeners react to
- what a revocation writes, which devices a scope covers, what a bulk revocation ends besides devices, or when and in
  which order it reports
- what a device summary holds, the listing's order, page bounds or connection
- what pruning selects, how retention is counted or configured, or how a custom model opts in
