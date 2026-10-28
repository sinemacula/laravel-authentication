# Device Lifecycle

## Purpose

This note records what happens to a device after its session starts: which devices count as active and how an
identity's devices are listed, how sessions are signed out and revoked, and when a device whose session ended is
deleted. Starting a session is in
`session-service.md`; refresh rotation and replay are in `refresh-rotation-and-replay.md`.

## Invariants

- A device is active while `revoked_at` is null and both `idle_expires_at` and `absolute_expires_at` are after now: a
  deadline has passed from the second it names, as on the bearer, refresh and sign-in pin paths
  (`TokenLifetimes::hasEnded()`). `ActsAsDevice::scopeActive()` and the listing apply the same rule through
  `ActiveDevices::constrain()`, with the columns of the model's name accessors, so a model without the trait is listed
  the same way.
- The listing (`SessionService::devices()`) reads the identity's `devices()` relation on the write connection (the
  query itself through `WriteConnection::query()`, and anything the relation reads while it is built inside
  `WriteConnection::during()` for the identity), so a revocation the primary holds is never listed as live. It covers
  every guard: a device list shows every session the identity has.
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
  writer in key order (`lazyById`, chunks of 500), revokes each conditionally, and deletes the scope's pending sign-ins
  (by owner, or by principal); (3) once committed, `DeviceRevoked` per revoked device, then `SignedOutEverywhere` per
  scope, also when it revoked none. A failure in (2) leaves (1) in place: fail-safe, and a retry is idempotent.
- An identity's scope is every device its `devices()` relation returns, of every guard; a principal's is every device of
  the configured model whose principal columns record it. An identity without `HasDevices` has no devices but still has
  its cutoff moved and its pending sign-ins deleted; an unsaved principal has neither devices nor pending sign-ins.
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

- `src/Sessions/ActiveDevices.php`, `src/Sessions/DeviceSummary.php`, `src/Sessions/SessionService.php` (`devices()`)
- `src/Concerns/ActsAsDevice.php` (`scopeActive()`), `src/Concerns/PrunesDevices.php`, `src/Models/Device.php`
- `src/Sessions/Concerns/ManagesDevices.php`, `src/Sessions/DeviceRevocations.php`, `src/Sessions/RevocationScope.php`,
  `src/Sessions/IdentityDevices.php`, `src/Jwt/RefreshRotationStore.php` (`revoke()`), `src/Guards/JwtGuard.php`
  (`logout()`), `src/Guards/AbstractGuard.php` (`forgetUser()`)

## Authoritative Tests

- `tests/Feature/Sessions/DeviceListTest.php`: the device list over HTTP behind `auth:api`
- `tests/Integration/Sessions/DeviceListingIntegrationTest.php`, `tests/Integration/Sessions/ReplicaDeviceListingTest.php`
- `tests/Unit/Sessions/DeviceSummaryTest.php`
- `tests/Feature/Sessions/ManagesDevicesTest.php`: logout, sign out everywhere and a device list's revoke over HTTP
- `tests/Feature/Sessions/DeviceRevocationsTest.php`, `tests/Integration/Sessions/DeviceRevocationsTest.php`
- `tests/Performance/DeviceRevocationQueryBudgetTest.php`
- `tests/Feature/Models/DevicePruningTest.php`, `tests/Integration/Models/DevicePruningIntegrationTest.php`
- `tests/Performance/DeviceListingQueryBudgetTest.php`, `tests/Performance/DevicePruneQueryBudgetTest.php`

## Change Triggers

Update this note when any of the following change:

- what makes a device active, or which columns decide it
- what a revocation writes, which devices a scope covers, what a bulk revocation ends besides devices, or when and in
  which order it reports
- what a device summary holds, the listing's order, page bounds or connection
- what pruning selects, how retention is counted or configured, or how a custom model opts in
