# Device Lifecycle

## Purpose

This note records what happens to a device after its session starts: which devices count as active and how an
identity's devices are listed, and when a device whose session ended is deleted. Starting a session is in
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

## Authoritative Tests

- `tests/Feature/Sessions/DeviceListTest.php`: the device list over HTTP behind `auth:api`
- `tests/Integration/Sessions/DeviceListingIntegrationTest.php`, `tests/Integration/Sessions/ReplicaDeviceListingTest.php`
- `tests/Unit/Sessions/DeviceSummaryTest.php`
- `tests/Feature/Models/DevicePruningTest.php`, `tests/Integration/Models/DevicePruningIntegrationTest.php`
- `tests/Performance/DeviceListingQueryBudgetTest.php`, `tests/Performance/DevicePruneQueryBudgetTest.php`

## Change Triggers

Update this note when any of the following change:

- what makes a device active, or which columns decide it
- what a device summary holds, the listing's order, page bounds or connection
- what pruning selects, how retention is counted or configured, or how a custom model opts in
