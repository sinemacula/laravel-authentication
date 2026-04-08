# Laravel Authentication — PRD Acceptance Criteria Traceability

Companion document to `01-laravel-authentication.md`. Maps every acceptance criterion in that PRD to the test(s) that
exercise the criterion. Maintained alongside the PRD so future changes to either can be cross-checked.

**Source PRD:** `docs/prd/.building/01-laravel-authentication.md`
**Test root:** `tests/`
**As of:** 2026-04-07, 238 tests / 709 assertions passing.

---

## P0 — Must Have

### 1. Stateless JWT guard

Valid bearer token → `check`/`user`/`id`/`principal`/`device` return bound values; invalid/expired/missing → `null`.

- `tests/Unit/Guards/JwtGuardUserResolutionTest.php`
- `tests/Integration/Guards/JwtGuardIntegrationTest.php`
- `tests/Integration/Facade/AuthFacadeMacroIntegrationTest.php`

### 2. Stateless Basic guard

Valid HTTP Basic → same accessors; invalid → `false`; credential validation runs in constant time via `Timebox`.

- `tests/Unit/Guards/BasicGuardTest.php`
- `tests/Unit/Guards/AbstractGuardAttemptTest.php` (timing-safe validation)
- `tests/Integration/Facade/AuthFacadeMacroIntegrationTest.php`

### 3. Refresh token flow

Valid refresh → new access + rotated refresh + `Refreshed` event; invalid/revoked → no session.

- `tests/Unit/Guards/JwtGuardRefreshTest.php`
- `tests/Integration/Guards/JwtGuardIntegrationTest.php`
- `tests/Unit/Jwt/RefreshTokenHasherTest.php`
- `tests/Unit/Events/RefreshedTest.php`
- `tests/Unit/Events/RefreshFailedTest.php`

### 4. Laravel Guard contract compliance

Every `Illuminate\Contracts\Auth\Guard` method implemented; guards work through the standard `Auth` facade and
middleware.

- `tests/Unit/Contracts/ContextualGuardTest.php`
- `tests/Unit/AuthManagerTest.php`
- `tests/Integration/Guards/JwtGuardIntegrationTest.php`
- `tests/Integration/Facade/AuthFacadeMacroIntegrationTest.php`

### 5. Standard Laravel auth events

Success fires `Attempting` → `Validated` → `Login` → `Authenticated`; failure fires `Attempting` → `Failed`.

- `tests/Integration/Events/StandardAuthEventsIntegrationTest.php`
- `tests/Unit/Guards/AbstractGuardAttemptTest.php`
- `tests/Unit/Guards/AbstractGuardLifecycleTest.php`

### 6. Custom contextual events

`PrincipalAssigned` / `DeviceAuthenticated` / `Refreshed` fire at the documented lifecycle points.

- `tests/Integration/Events/CustomEventsIntegrationTest.php`
- `tests/Unit/Events/PrincipalAssignedTest.php`
- `tests/Unit/Events/DeviceAuthenticatedTest.php`
- `tests/Unit/Events/RefreshedTest.php`

### 7. Contextual Auth facade methods

`Auth::principal()` / `device()` / `organization()` / `scope()` / `isInternal()` / `isExternal()` return bound values;
`null` / `false` when unauthenticated.

- `tests/Unit/Facades/AuthFacadeTest.php`
- `tests/Unit/Guards/AbstractGuardContextualTest.php`
- `tests/Integration/Facade/AuthFacadeMacroIntegrationTest.php`

### 8. Principal resolver contract

Custom resolver bound through the container is the one guards use; no domain-specific query hard-coded in the guard.

- `tests/Unit/Resolvers/DefaultPrincipalResolverTest.php`
- `tests/Unit/Guards/JwtGuardUserResolutionTest.php`
- `tests/Unit/Guards/BasicGuardTest.php`

### 9. Polymorphic device tracking

`devices` table has `authenticatable_type` / `authenticatable_id` + ULID primary key; any authenticatable model
resolves through the morph map.

- `tests/Unit/Models/DeviceTest.php`
- `tests/Unit/Traits/ActsAsDeviceTest.php`
- `tests/Unit/Traits/AuthenticatableTest.php`
- `tests/Integration/Events/CustomEventsIntegrationTest.php`

### 10. Configurable Device model and table names

Custom model class + custom table name override work and are verified by swapping defaults.

- `tests/Integration/Config/DeviceModelOverrideTest.php`
- `tests/Unit/Models/DeviceTest.php`

### 11. Standalone installability

`composer.json` declares no runtime dependency on sibling `sinemacula/laravel-*` IAM packages; suite runs clean.

- `composer.json` inspection (no sibling IAM entries in `require`)
- `tests/Unit/AuthServiceProviderTest.php` (boots the package standalone under Testbench)

### 12. Coexistence of 2D and 3D guards

Both modes configurable against the same guards; same test run authenticates both without cross-talk.

- `tests/Unit/Resolvers/DefaultPrincipalResolverTest.php` (exercises both the `Identity-is-Principal` and
  `HasPrincipals` paths)
- `tests/Unit/Guards/AbstractGuardAttemptTest.php`
- `tests/Integration/Events/CustomEventsIntegrationTest.php`

---

## P1 — Should Have

### 13. Migration safety check

Running the shipped migration against a database where the devices table already exists surfaces an actionable error
before any mutation.

- `tests/Integration/Migration/DeviceMigrationCollisionTest.php`
- `tests/Unit/Database/MigrationCollisionGuardTest.php`

### 14. Documented adoption guide

README covers installation, configuration, 2D and 3D worked examples.

- `README.md` (manual verification — no executable test)

### 15. Internal vs external principal helper

`Auth::isInternal()` / `isExternal()` return correct boolean; `false` when no principal resolved.

- `tests/Unit/Guards/AbstractGuardContextualTest.php`
- `tests/Unit/Facades/AuthFacadeTest.php`
- `tests/Unit/Contracts/ContextualGuardTest.php`

---

## P2 — Nice to Have

### 16. Test helpers (actingAs analog)

**Not implemented.** Deferred — consumers can still use Laravel's first-party `actingAs` via the package's `Auth`
subclass.

### 17. Artisan command for issuing tokens

**Not implemented.** Deferred.

---

## Release criteria coverage

- **All package tests pass on CI (PHP 8.3, Laravel 12.40 / 13.3)** — Pass. 238 tests / 709 assertions, matrix verified
  locally; CI workflow `tests.yml` has both Laravel minors wired in.
- **PHPStan level 8 strict reports zero errors on `src/`** — Pass. `composer check` clean.
- **Test coverage on guards / providers / manager ≥ 90%** — Measured via `composer test-coverage`; uploaded to qlty.sh
  on master builds.
- **Integration tests for standard `Auth` facade, `auth` middleware, `@auth` Blade, all six standard events** —
  covered by `StandardAuthEventsIntegrationTest.php`, `AuthFacadeMacroIntegrationTest.php`,
  `JwtGuardIntegrationTest.php`.
- **Integration tests for all three custom events** — `CustomEventsIntegrationTest.php`.
- **Clean-install integration test confirming no sibling IAM packages are pulled in** — `AuthServiceProviderTest.php`
  boots the provider under Testbench with only this package in scope.
- **README documents installation, configuration, 2D + 3D paths, migration path from monorepo** — `README.md`.
- **Package extracted to standalone repo and published to Packagist** — External release event, not a test.

---

## How this document should be maintained

- When a PRD acceptance criterion is added, amended, or removed, update the matching entry here in the same change.
- When a test file is renamed or split, update every entry that references it.
- This document is not a substitute for tests — it is a coverage audit that should be refreshed whenever the PRD or
  the test layout changes.
