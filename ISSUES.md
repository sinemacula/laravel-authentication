# Issues — Deep Analysis Pass 2

Independent review of `sinemacula/laravel-authentication` against the PRD
(`docs/prd/.building/01-laravel-authentication.md`), the README, and the
current implementation. Each finding cites the offending file, the PRD
clause it violates (where applicable), and a suggested remediation.

Severity key: **CRITICAL** (security impact or PRD violation), **HIGH**
(correctness bug), **MEDIUM** (design weakness / latent bug),
**LOW** (code quality / documentation).

---

## CRITICAL

### C1 — Timing-attack leak in `AbstractGuard::attempt()` and `validate()`

**Files:** `src/Guards/AbstractGuard.php:445-470` (`resolveContextForCredentials`),
`src/Guards/AbstractGuard.php:151-160` (`validate`), `src/Guards/Concerns/ValidatesGuardCredentials.php:55-70` (
`hasValidCredentials`).

**PRD clause:** REQ "Stateless Basic guard" / AC: *"Credential validation completes in constant time regardless of
whether the supplied identifier exists, verified via the validation path consistently invoking Laravel's timing-safe
comparison helper."* Also Risk #4: *"Timing attacks on credential validation reveal which identifiers exist."*

**Problem:** The package wraps only the hasher check inside `Timebox::call()`; it does **not** wrap the entire
`attempt()` / `validate()` flow. Worse, the relevant helpers short-circuit on `$user === null` so the timebox is never
entered at all when the supplied identifier does not exist:

```php
// AbstractGuard::resolveContextForCredentials(), lines 450-460
$this->lastRetrievedUser = $this->provider->retrieveByCredentials($credentials); // NOT inside timebox
$user = $this->lastRetrievedUser;

$credentialsValid = $user !== null
    && $this->hasValidCredentials($user, $credentials) // short-circuits out when $user is null
    && ...;
```

```php
// AbstractGuard::validate(), lines 151-160
$user = $this->provider->retrieveByCredentials($credentials); // NOT inside timebox
if ($user === null) {
    return false; // early return bypasses timebox entirely
}
return $this->hasValidCredentials($user, $credentials);
```

`tests/Unit/Guards/AbstractGuardAttemptTest.php:185` literally **asserts the bug**:

```php
$this->provider->shouldNotReceive('validateCredentials');
```

— i.e. when the identifier does not resolve, `validateCredentials` (and therefore the Timebox path) is never invoked. An
attacker can distinguish "user exists" from "user does not exist" purely by measuring response time: a
valid-but-wrong-password call takes ≥400 ms (timebox budget); a nonexistent user returns immediately (a DB SELECT, no
hashing).

Laravel's first-party `SessionGuard::attempt()` (see
`vendor/laravel/framework/src/Illuminate/Auth/SessionGuard.php:419-446`) wraps the *entire* attempt —
`retrieveByCredentials`, `hasValidCredentials`, failed event dispatch — inside one `$this->timebox->call(...)`. The
package should mirror that pattern.

Note: `BasicGuard::user()` is *accidentally* correct because `validateAndResolvePrincipal()` passes the `null` user into
`hasValidCredentials()`, which still enters the timebox before short-circuiting. The bug affects `attempt()` and
`validate()` on **every** guard that extends `AbstractGuard`, including `BasicGuard` inheritance of those methods.

**Fix:** Restructure `attempt()` and `validate()` so the entire body — from `fireAttemptingEvent` through
`fireFailedEvent` — is inside a single `$this->timebox->call(...)` wrapper, matching `SessionGuard::attempt()`. Do not
rely on `hasValidCredentials()` to carry the budget.

---

### C2 — Refresh-token rotation is not atomic; no reuse detection

**Files:** `src/Jwt/RefreshTokenExchange.php:72-91` (`exchange`), `:161-181` (`loadDeviceForRefresh`), `:328-340` (
`rotateDeviceRefreshKey`).

**Claim being violated:** `README.md:39` — *"Refresh-token rotation with constant-time digest
verification, **atomic per-device rotation**."*

**Problem:** The verify-then-rotate sequence is **not atomic**:

1. `loadDeviceForRefresh()` reads the device row with a plain `Model::newQuery()->find($id)` — **no lock, no transaction
   **.
2. `RefreshTokenHasher::verify(...)` compares the claim's `jti` to the stored digest.
3. `hydrateRefreshContext()` lazy-loads `authenticatable` and resolves a principal (may issue further queries).
4. `rotateDeviceRefreshKey()` opens a fresh transaction and calls `forceFill([...])->save()`.

Between steps 2 and 4 there is a race window of unbounded length (cross-process, cross-host). Two concurrent refresh
requests carrying the same refresh token can both pass `verify()` and both issue new token pairs — defeating the
security value of rotation (a stolen refresh token can be replayed in parallel with the legitimate client, each side
getting a fresh pair).

Related: there is **no refresh-token reuse detection
**. [OAuth 2.0 Security BCP §4.13.2](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics) recommends
that whenever a refresh-token reuse is detected (an attempt to exchange a token whose rotation id has already been
burned) the server SHOULD invalidate the entire token family for that device. The package ships no such mechanism — a
reused token just produces `RefreshFailed::REASON_ROTATION_MISMATCH` and the legitimate session continues unaware.

**Fix:** Either (a) wrap the verify + hydrate + rotate steps in one transaction using a `SELECT ... FOR UPDATE` on the
device row, or (b) perform the rotation as an atomic compare-and-swap — a single
`UPDATE devices SET refresh_key = :new WHERE id = :id AND refresh_key = :old_digest` and reject the exchange when
affected rows ≠ 1. Option (b) is preferable for MySQL/PostgreSQL. Also add a reuse-detection path: when the CAS returns
0 rows AND the device exists, the token was a replay — emit a distinct reason (`rotation_reuse`) and revoke the device
by setting `refresh_key` to a sentinel, forcing all clients in that family to re-authenticate.

---

### C3 — Standard `Login` / `Authenticated` event order is inverted

**Files:** `src/Guards/AbstractGuard.php:355-370` (`bindAuthenticationLifecycle`),
`src/Guards/AbstractGuard.php:380-385` (`setIdentity`), `tests/Unit/Guards/AbstractGuardAttemptTest.php:94-98`.

**PRD clause:** REQ "Standard Laravel auth events" / AC: *"A successful authentication
emits `Attempting`, `Validated`, `Login`, and `Authenticated` **in the order Laravel emits them**."*

**Problem:** The package emits **Authenticated before Login**, while Laravel emits **Login before Authenticated**.

Laravel's `SessionGuard::login()` (`vendor/laravel/framework/src/Illuminate/Auth/SessionGuard.php:557-576`):

```php
public function login(AuthenticatableContract $user, $remember = false) {
    $this->updateSession(...);
    // ...
    $this->fireLoginEvent($user, $remember);      // → Login
    $this->setUser($user);                        // → fireAuthenticatedEvent → Authenticated
}
```

The package's `AbstractGuard::bindAuthenticationLifecycle()`:

```php
$this->setIdentity($identity);          // dispatches Authenticated   (first)
$this->setPrincipal($principal);        // dispatches PrincipalAssigned
// ...
$this->events->dispatch(new Login(...)); // dispatches Login          (last)
```

`tests/Unit/Guards/AbstractGuardAttemptTest.php:94-98` currently enforces the wrong order via
`assertSame([Attempting, Validated, Authenticated, PrincipalAssigned, Login], $dispatched)` and
`BasicGuardTest.php:468-471` does the same. The tests lock in the PRD violation.

**Fix:** Fire `Login` before `Authenticated`. Reorder `bindAuthenticationLifecycle` so that `dispatch(new Login(...))`
runs *before* `setIdentity()` — or factor a `fireLoginEvent()` helper that matches Laravel's shape. Update both test
files to assert the correct order.

Also note: Laravel's `SessionGuard::attempt()` does **not** fire `Login` at all from `attempt()` — it only calls
`setUser()` (i.e. `Authenticated`). The package fires `Login` from every `attempt()` (through
`bindAuthenticationLifecycle`), which is an additional divergence from Laravel's behaviour. Worth checking against the
PRD's "in the order Laravel emits them" requirement — the package emits an *extra* event Laravel does not.

---

## HIGH

### H1 — `BasicGuard::user()` does not catch `UnresolvableIdentityException`

**File:** `src/Guards/BasicGuard.php:163-184` (`validateAndResolvePrincipal`).

**Problem:** `AbstractGuard::attempt()` and `JwtGuard::user()` both use the `safeResolvePrincipal()` helper, which
catches `UnresolvableIdentityException` and converts it to a `null` return (→ `Failed` event → 401). But
`BasicGuard::user()` calls `$this->resolver->resolve($user)` **directly**:

```php
// BasicGuard.php:176
$principal = $this->resolver->resolve($user);
```

If a consumer misconfigures their identity model (implements neither `Principal` nor `HasPrincipals`), the exception
propagates out of `user()` as an uncaught 500, while the `JwtGuard` and `attempt()` paths correctly surface a 401.
Inconsistent behaviour on the same failure mode.

**Fix:** Route the call through `safeResolvePrincipal()`, or inline the `try/catch(UnresolvableIdentityException)` here
too.

---

### H2 — `UpdateDeviceTimestamp` throttle breaks with `CarbonImmutable`

**Files:** `src/Listeners/UpdateDeviceTimestamp.php:75-94` (`shouldUpdate`), `src/Traits/ActsAsDevice.php:36-41` (
`getLastLoggedIn`).

**Problem:** Both locations check `$value instanceof \Carbon\Carbon`. If the consumer application calls
`Date::use(\Carbon\CarbonImmutable::class)` (a common Laravel idiom — Eloquent will return `CarbonImmutable` instances
for datetime casts), these type checks **return `null` / `true`** respectively, and:

- `ActsAsDevice::getLastLoggedIn()` always returns `null`, silently dropping the timestamp.
- `UpdateDeviceTimestamp::shouldUpdate()` returns `true` unconditionally, meaning the throttle window never fires and *
  *every authenticated request produces a write to the device row**. This is exactly the hot-spot the throttle exists to
  prevent (README line 40).

**Fix:** Widen the check to `$value instanceof \Carbon\CarbonInterface` (the parent interface `Carbon` and
`CarbonImmutable` both implement), or to `\DateTimeInterface` more liberally. Add a regression test that uses
`CarbonImmutable` as the Eloquent date class.

---

### H3 — `JwtGuard::refresh()` does not emit `Login` (or `Validated` / `Attempting`)

**File:** `src/Guards/JwtGuard.php:116-137`.

**Problem:** The refresh flow binds identity/principal/device via `setIdentity` → `setPrincipal` → `setDevice` and
dispatches `Refreshed`, but fires none of the standard Laravel auth events. A refresh therefore produces:

- `Authenticated` (from `setIdentity`)
- `PrincipalAssigned`
- `DeviceAuthenticated`
- `Refreshed`

and no `Attempting`, `Validated`, or `Login`. Consumers listening to `Login` to detect "a session started" (for
audit-log writes, analytics, session-store warming, rate-limit resets, etc.) miss every refresh. This is inconsistent
with the bearer-token `user()` path, which goes through `login()` and DOES fire the standard event set.

The PRD's REQ-03 "Refresh token flow" AC says: *"… updates the device's last-login timestamp, fires a `Refreshed` event,
and continues to return the same identity and principal."* It does not explicitly require the standard event set — but
the PRD also says the package fires "all six standard Laravel authentication events" consistently, which implies the
refresh path should too.

**Fix:** Either (a) route `refresh()` through the `login()` lifecycle helper (which already fires `Validated` + `Login`
around the bind) instead of calling the low-level setters directly, or (b) document explicitly that refresh skips the
standard events so consumers know to listen to `Refreshed` as well.

---

### H4 — `JwtKeyring::buildKeyMap` does not guard against `null` secrets

**File:** `src/Jwt/JwtKeyring.php:185-213`.

**Problem:** The fail-closed guard checks `$material === ''`, which does not match `null`. Kid-mode configuration looks
like:

```php
'keys' => [
    '2026-04' => env('AUTHENTICATION_JWT_KEY_2026_04'),
    '2026-03' => env('AUTHENTICATION_JWT_KEY_2026_03'),
],
```

If either env var is unset, `env(...)` returns `null`. `AuthServiceProvider::buildKeyring()` then forwards the raw array
with a PHPStan-only hint `/** @var array<string, string> $keys */` (no runtime coercion), and `buildKeyMap()` iterates
without rejecting the `null` value. The downstream `new Key($material, $algorithm)` call (firebase/php-jwt) may reject
it, but the error will be opaque and distant from the actual misconfiguration.

Defence-in-depth: the fail-closed boundary should reject `null` with the same friendly message as empty string.

**Fix:** Change `if ($material === '')` to `if (!is_string($material) || $material === '')`. Do the same narrowing in
`AuthServiceProvider::buildKeyring()`.

---

### H5 — Migration: `refresh_key` column is `NOT NULL UNIQUE` — no way to revoke a device

**File:** `database/migrations/2026_04_06_000000_create_devices_table.php:42`.

**Problem:** `$blueprint->string($refreshKeyColumn, 64)->unique();` — the column is non-nullable and unique.
Consequences:

1. **No graceful logout-by-device**: the only way to invalidate an issued refresh token server-side is to `DELETE` the
   device row (losing forensic history) or to `UPDATE refresh_key = <sentinel>` (risks accidentally collapsing multiple
   revoked devices onto the same sentinel and failing the unique index). There is no revocation column.
2. **No nullable state for "device registered but refresh not yet issued"**: e.g. a first-authentication flow that
   creates the device row before the first refresh token, or a device stripped of its refresh capability by an incident
   response.
3. **Mass revocation by identity** (e.g. "log this user out everywhere") requires a
   `DELETE WHERE authenticatable_id = ?` — there's no "soft revoke".

**Fix:** Make `refresh_key` nullable; drop the `UNIQUE` index (a SHA-256 collision is not a real concern, and the
`did → device` lookup is by primary key). Alternatively, add an explicit `revoked_at` nullable timestamp column and have
the exchange reject revoked devices.

---

## MEDIUM

### M1 — `primeDeviceTableCache` couples the package to a process-wide mutable static

**Files:** `src/AuthServiceProvider.php:208-215`, `src/Models/Device.php:70-104`.

**Problem:** `Device::$cachedTable` is a process-wide static, set once at boot. Consumers or tests that swap
`laravel-authentication.device.table` at runtime must remember to call `Device::useTable(...)` manually. The existing
`DeviceModelOverrideTest` works around it; the comment in `AuthServiceProvider::primeDeviceTableCache` admits this.
Paratest runs each test in a separate process so cross-test contamination is unlikely, but within a process it is
possible. Also, if a consumer registers multiple Device subclasses with different tables, the static is shared across
all of them.

**Fix:** Read the config lazily inside the model constructor (the performance argument in the docblock is not strong —
the Config facade call is microseconds), or bind `laravel-authentication.device.table` into the constructor via
dependency injection.

---

### M2 — `RefreshTokenExchange::rotateDeviceRefreshKey` uses `forceFill+save` (triggers observers)

**File:** `src/Jwt/RefreshTokenExchange.php:328-340`.

**Problem:** The rotation uses `$device->forceFill([...])->save()`, which fires Eloquent's `updating`/`updated` model
events and runs any registered observers. The `UpdateDeviceTimestamp` listener, by contrast, uses `newQuery()->update()`
to bypass observers (line 58-60 of `UpdateDeviceTimestamp.php`). The inconsistency is not a bug per se, but:

- A consumer observer that touches the device on `updated` may now also fire on refresh, causing surprise cascades.
- `forceFill+save` persists every `$device->isDirty()` attribute, not just `refresh_key`. Any stray in-memory mutation
  from earlier in the request will leak into the rotation write.

**Fix:** Use a raw `$this->connections->connection(...)->table(...)->where(...)->update(...)` against the query builder
instead of `forceFill+save`, matching the CAS pattern suggested in C2.

---

### M3 — `JwtGuard::resolveBearerToken` never populates `lastRetrievedUser` on `Failed`

**File:** `src/Guards/JwtGuard.php:170-185`.

**Problem:** On the bearer-token failure path, `fireFailedEvent(null, [])` is always called with a `null` user, even
when the `sub` claim resolved to an identity that was then rejected (e.g. inactive, principal-unresolved,
device-missing). Laravel's `Failed` event carries `?Authenticatable $user` specifically so SIEM consumers can attribute
the failure to a specific account. The package discards this information.

Compare with `AbstractGuard::attempt()` which dutifully tracks `$this->lastRetrievedUser` and passes it to
`fireFailedEvent`.

**Fix:** Track the retrieved identity (or a claims-stringified `sub`) from `loadIdentityFromClaims()` and forward it to
`fireFailedEvent` on the null path.

---

### M4 — `JwtTokenService::decodeToken` mutates `JWT::$leeway` global

**File:** `src/Jwt/JwtTokenService.php:202-218`.

**Problem:** `firebase/php-jwt` exposes `JWT::$leeway` as a public static. The package writes it, decodes, then resets
in `finally`. In a single-threaded PHP request this is safe, but:

- If decode throws an exception whose constructor re-enters this method (unlikely but possible), the `finally` will
  reset *twice* incorrectly.
- In a fiber-based runtime (ReactPHP, Swoole with coroutines, Octane in persistent-process mode), concurrent parses from
  different requests in the same worker leak the leeway into each other.
- Any other code in the request (e.g. a consumer calling `JWT::decode` directly) that runs between the write and reset
  sees the package's leeway, not its own.

firebase/php-jwt v6+ supports passing leeway per-call via `Key::$leeway` instead of the static. Use that.

**Fix:** Construct `Key` instances with `$leeway` set in the constructor via reflection or — cleaner — pull the leeway
into the `JwtKeyring::verificationKeys()` output by wrapping each `Key` with its `leeway` property set. Alternatively,
wrap `JWT::decode` in a mutex, though that does not address the cross-request leak.

---

### M5 — `AuthServiceProvider::buildKeyring` coerces raw config via PHPStan hint only

**File:** `src/AuthServiceProvider.php:345-365`.

**Problem:**

```php
/** @var array<string, string> $keys */
$keys = $rawKeys;
return JwtKeyring::fromKeyMap($keys, ...);
```

The `@var` comment is a static-analysis hint with no runtime effect. If a consumer populates `jwt.keys` with integer
keys (a common mistake in Laravel config arrays: `['secret_a', 'secret_b']` instead of `['2026-04' => 'secret_a']`), the
resulting kid values are `"0"` and `"1"`, which pass `JwtKeyring::fromKeyMap`'s empty-string check but produce
meaningless kid headers in issued tokens and brittle configuration downstream.

**Fix:** Add a runtime check in `buildKeyring()` that rejects non-string keys with a clear
`InvalidJwtConfigurationException` — or move the check into `JwtKeyring::fromKeyMap()` itself.

---

### M6 — Tests assert event *presence* not *order* for JwtGuard success path

**File:** `tests/Unit/Guards/JwtGuardUserResolutionTest.php:404-409`.

**Problem:** The happy-path test uses `assertContains` for each event class, not `assertSame` on the full ordered list.
The test would pass even if the events fire in any arbitrary order — including the inverted `Login`→`Authenticated`
order flagged in C3. Contrast with `AbstractGuardAttemptTest.php:94-98` and `BasicGuardTest.php:468-471` which DO assert
order (but assert the wrong one).

**Fix:** Tighten to `assertSame([...expected order...])` once C3 is fixed.

---

---

## LOW

### L1 — README claim "hardened JWT pipeline enforces … `jti` / `exp` / leeway" — `jti` is not verified on parse

**File:** `src/Jwt/JwtTokenService.php:249-293` (`matchesExpectedClaims`, `firstClaimMismatch`).

**Problem:** README line 38 claims the JWT pipeline "enforces `iss` / `aud` / `typ` / `jti` / `exp` / leeway". In
practice, only `iss`, `aud`, `typ`, and `exp` (via firebase/php-jwt) are verified. The `jti` claim is embedded on issue
but not validated on parse — it's only consulted during the refresh-token rotation flow. There is no replay-protection
nonce tracking for access tokens.

Either update the README to match the implementation, or add a minimal `jti`-present check to the `firstClaimMismatch`
loop (and document that revocation lists are out of scope).

---

### L2 — `matchesPidHint` rejects principals whose identifier stringifies to `null`

**File:** `src/Guards/JwtGuard.php:297-307`.

**Problem:** If `IdentifierCoercion::stringify($resolved->getPrincipalIdentifier())` returns `null` (e.g. the principal
model hasn't been saved and its key is null), `matchesPidHint` returns `false` and `user()` rejects the token. In
practice this won't happen for a persisted model, but a resolver that returns a transient (unsaved) principal will
silently fail bearer-token auth without a clear reason. Worth a docblock note, or swap the check to include-null-guards
on either side.

---

### L3 — `UpdateDeviceTimestamp` listener writes the timestamp column name as a literal

**File:** `src/Listeners/UpdateDeviceTimestamp.php:60`.

**Problem:** `$device->newQuery()->whereKey($device->getKey())->update(['last_logged_in_at' => $now]);` — the column
name is hardcoded. `ActsAsDevice::getLastLoggedInName()` is specifically designed to let consumers remap this column,
and `Device::getLastLoggedIn()` reads via `getLastLoggedInName()`. The listener should too, otherwise a consumer with a
custom column name has a broken throttle.

**Fix:** Change to `[$device->getLastLoggedInName() => $now]` with a type guard for non-`ActsAsDevice` models.

---

### L4 — PRD P1 "Documented adoption guide" — README is thin on 3D example

**File:** `README.md`.

**Problem:** The PRD P1 acceptance criterion says: *"A new developer following the guide on a fresh Laravel 13
application reaches an authenticated `Auth::check() === true` state without consulting source code"* and *"at least one
worked example for each of the 2D and 3D adoption paths"*. The current README covers installation and configuration for
2D mode, but has **no worked 3D example** (no Principal/Organization model sketch, no principal resolver example, no
`@phpstan-require-extends` note for Identity). A fresh developer cannot reach `Auth::principal()` returning a
non-identity model without reading the contracts source.

**Fix:** Add a "3D adoption" section walking through a minimal Identity / Principal / Organization setup and a custom
PrincipalResolver.

---

### L5 — PRD P2 "Test helpers" and "Artisan command for issuing tokens" — neither shipped

**Problem:** Both are P2 (nice-to-have), neither exists in `src/`. No `actingAsIdentity` / `actingAsPrincipal` helper,
no `php artisan auth:jwt` command. Not a bug, but worth logging as missing functionality relative to the PRD.

---

### L6 — PRD "Coexistence of 2D and 3D guards" — no integration test proves it

**File:** `tests/Integration/`.

**Problem:** REQ "Coexistence of 2D and 3D guards" AC says: *"A test application configures one route protected by a 2D
guard and another protected by a 3D guard. … Both routes return correct results in the same test run."* No such
integration test exists — all tests use a single guard per test case. The architecture plausibly supports coexistence (
both guards share the same codebase), but there is no test evidence for the claim.

**Fix:** Add one integration test that registers two `jwt` guards with different providers/resolvers and verifies they
do not contaminate each other's state.

---

### L7 — PRD "Clean-install standalone dependency" — no test

**Problem:** REQ-10 AC: *"A clean Laravel 13 application can install the package and run its test suite without any of
those packages being present in the vendor tree."* `composer.json` requires only `firebase/php-jwt` and
`laravel/framework`, which is good, but no automated check guards against a future accidental require on a sibling
package. A trivial CI step (`composer show | grep sinemacula/laravel- | grep -v authentication && exit 1`) would lock
this in.

---

### L8 — `algorithm` config is trusted without validation at boot

**File:** `src/AuthServiceProvider.php:313`, `src/Jwt/JwtTokenService.php`.

**Problem:** `JwtTokenService` accepts any string as `$algorithm` and forwards it to `firebase/php-jwt`. A typo (
`HS526`) or a deliberately insecure value (`none` — though firebase/php-jwt rejects this) will fail at first use, not at
boot. Boot-time validation against an allow-list (e.g. `HS256`, `HS384`, `HS512`, `RS256`, `RS384`, `RS512`, `ES256`,
`ES384`) would fail loudly at container resolution and narrow the blast radius.

---

## Missing functionality vs. PRD

Summary of PRD items that are missing or under-specified:

| PRD item                                                | Priority | Status                                                             |
|---------------------------------------------------------|----------|--------------------------------------------------------------------|
| Timing-safe validation for nonexistent identifiers      | P0       | **Broken** (C1) — breaks AC of "Stateless Basic guard"             |
| Event order matches Laravel                             | P0       | **Wrong order** (C3) — breaks AC of "Standard Laravel auth events" |
| Refresh token atomic rotation                           | README   | **Not atomic** (C2) — contradicts documentation                    |
| Coexistence of 2D/3D guards proven by test              | P0       | **Missing integration test** (L6)                                  |
| Clean-install standalone verified                       | P0       | **Missing CI guard** (L7)                                          |
| 3D adoption worked example in README                    | P1       | **Missing** (L4)                                                   |
| Test helpers (`actingAsIdentity`, etc.)                 | P2       | **Missing** (L5)                                                   |
| Artisan token-issuing command                           | P2       | **Missing** (L5)                                                   |
| Refresh token reuse detection                           | Implied  | **Missing** (C2) — industry best practice not shipped              |
| Device revocation mechanism                             | Implied  | **Missing** (H5) — migration shape prevents it                     |
| `auth` middleware / `@auth` Blade directive integration | P0       | Plausibly works through Laravel, but **no integration tests**      |

---

## Key functionality that IS well covered

For completeness, the following are solid and do not need attention:

- `JwtKeyring` — fail-closed on empty secrets, clear error messages, kid mode + legacy mode split cleanly.
- `DefaultPrincipalResolver` — covers 2D, 3D, and hint paths cleanly; the `UnresolvableIdentityException` signalling is
  a good design.
- `ModelProvider::retrieveByCredentials` — careful filtering of password-containing keys; refuses where-less queries;
  handles scalars, arrays, and closures.
- `MigrationCollisionGuard` — does its job, has an integration test.
- `JwtGuard::user()` pid/did fail-closed matching — correctly rejects silent downgrades; well-tested in
  `JwtGuardUserResolutionTest` (apart from the event-order weakness in M6).
- `RefreshTokenHasher` — correct primitive choice, constant-time comparison, edge-case handling.
- `InvalidJwtConfigurationException` and friends — good fail-closed posture at boot.
- PHPStan level 8 strict + no suppressions beyond a handful of narrowly-scoped Eloquent dynamic-call hints.
