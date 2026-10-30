# Storage

## Purpose

This note describes where the package's tables live, why the tables the device-backed flows write share one connection,
and how the runtime models and the published migrations are kept choosing the same one.

## Invariants

- One resolver decides, `Database\StorageConnection`: `name()` is `authentication.storage.connection`, `null` or empty
  for the default connection; `forRateLimits()` is `authentication.rate_limits.connection` when it names a connection,
  and `name()` otherwise. A value that is neither a name nor `null` or empty fails closed with an
  `InvalidArgumentException` naming the key, rather than putting a table on another connection than the one meant.
- Every shipped model takes its connection from the resolver when it is built: `PendingSignIn`, `OneTimeCode`,
  `Passkey`, `PasskeyChallenge`, `ApiKey` and `IdentifierChange` from `name()`, `RateLimit` from `forRateLimits()`, and
  the shipped `Device` from `name()` unless its class names a connection of its own. No persistence model reads the
  device model, or `Jwt\DeviceLookup`, for its connection.
- Every published migration's `getConnection()` returns the same value its model reads, and its collision guard,
  `create()` and `dropIfExists()` run on `Schema::connection($this->getConnection())`. Laravel's migrator runs a
  migration, and its schema transaction, on the connection the migration names, so `php artisan migrate` and a direct
  `up()` or `down()` both put each table where its model reads and writes it. With `null` the migrations name no
  connection and follow the migrator's, as `--database` chooses it; the `migrations` table always stays on the
  migrator's connection.
- The tables share the storage connection because the flows that write several of them are single transactions on one
  model's connection: a session (the device, then both tokens), the completion of a pending sign-in (its delete with the
  session, on the pending row's connection), a bulk revocation (devices, pending sign-ins and pending identifier
  changes), a password reset and an identifier change (the proof with the identity, its cutoff and its devices). Two
  connections cannot commit as one.
- The device model must therefore live there: `Jwt\DeviceLookup::model()`, which every device path and
  `AuthenticationServiceProvider::createJwtGuard()` go through, refuses a configured device model on another connection
  (`InvalidDeviceModelConfigurationException::offStorage()`), and `Database\SharedConnection` refuses a reset or an
  identifier change for an identity elsewhere (`LogicException`). Connections are compared by name, a model's own or
  `database.default`, so no connection is opened, and two names for one database count as two connections.
- Machine credentials depend on no device configuration: `ApiKey` lives on the storage connection, and
  `createApiKeyGuard()` checks the storage connection setting, never the device model.
- The attempt counters are the one table with an option of its own, so that counts can stay out of a transaction a
  caller rolls back on the storage connection; nothing writes them in a transaction with another package table.
- A model takes its connection when it is built, so both settings are deployment configuration, fixed for the life of a
  process.

## Success Path

- With both settings `null`, every model and table is on the default connection; run the migrations on it.
- With `authentication.storage.connection` set, `php artisan migrate` creates every table on that connection, the
  counters included unless `rate_limits.connection` names their own, and the models read and write them there. The
  shipped `Device`, or a subclass that names no connection, follows; a custom model names the storage connection.
- `php artisan authentication:check` reports `[storage]` (each setting a connection name configured in
  `database.connections`, or none) and, while a `jwt` guard is configured, `[device]` (the device model on the storage
  connection), reading configuration only.

## Failure / Edge Cases

- A malformed setting fails closed when a model is built, a migration runs or an `api_key` guard is built; a name that
  `database.connections` does not configure fails on first use as Laravel's own error; `authentication:check` reports
  both before a deploy.
- A device model, shipped subclass or custom, on another connection fails when a `jwt` guard is built or a device is
  looked up, never by splitting a session across two transactions. An `api_key`-only application needs no device model.
- An identity on another connection is refused by password resets and identifier changes before anything is counted, and
  `authentication:check` warns about its guard; a password change still runs, revoking the devices on the storage
  connection inside the identity's transaction, so a failure after it ends more, never less.
- Laravel gives a related model that names no connection its parent's, so a device's `authenticatable()` and
  `principal()` relations look an owner up on the storage connection unless its model names its own. The package never
  loads an owner through them (it reloads owners through the guard's provider, and `Jwt\DeviceOwnership` reads only the
  relation's key names), so this concerns application code only, and the configuration guide says so.
- Changing a setting moves no table already created, and a rollback runs against the setting at the time it runs: moving
  the tables is a deploy, with a migration the application writes and a restart of every worker.

## Implementation Anchors

- `src/Database/StorageConnection.php`: `name()`, `forRateLimits()`, `holds()`.
- The constructors of `src/Models/Device.php`, `PendingSignIn.php`, `RateLimit.php`, `OneTimeCode.php`, `Passkey.php`,
  `PasskeyChallenge.php`, `ApiKey.php` and `IdentifierChange.php`; `getConnection()` in every migration under
  `database/migrations/`.
- `src/Jwt/DeviceLookup.php`: `model()`; `src/Exceptions/InvalidDeviceModelConfigurationException.php`: `offStorage()`;
  `src/Database/SharedConnection.php`.
- `src/AuthenticationServiceProvider.php`: `createJwtGuard()`, `createApiKeyGuard()`;
  `src/Console/CheckConfigurationCommand.php`: `packageChecks()`; `config/authentication.php`: `storage`.

## Authoritative Tests

- `tests/Feature/Database/StorageConnectionTest.php`
- `tests/Integration/Migration/StorageConnectionMigrationTest.php`
- `tests/Integration/Database/StorageConnectionSessionsTest.php`
- `tests/Integration/ApiKeys/StorageConnectionApiKeysTest.php`
- `tests/Feature/Jwt/DeviceLookupTest.php` `testTheModelMustLiveOnTheStorageConnection`
- `tests/Feature/AuthenticationServiceProviderGuardValidationTest.php`
  `testJwtGuardRejectsADeviceModelOffTheStorageConnection`
- `tests/Feature/AuthenticationServiceProviderTest.php` `testApiKeyGuardIgnoresTheDeviceModel`,
  `testApiKeyGuardRejectsAMalformedStorageConnection`
- `tests/Feature/Models/DeviceTest.php` `testTakesTheStorageConnectionUnlessTheClassNamesItsOwn`,
  `tests/Unit/Models/DeviceWithoutApplicationTest.php`
- `tests/Feature/Database/SharedConnectionTest.php`,
  `tests/Integration/Passwords/SeparateConnectionResetSubmissionsTest.php`
- `tests/Feature/Console/CheckConfigurationCommandTest.php`

## Change Triggers

- A new package table: its model and its migration take the resolver.
- Any flow that writes two package tables in one transaction, or that would write one outside the storage connection.
- Any change to how connections are compared, to what the counters' option allows, or to which guards read the device
  model.
