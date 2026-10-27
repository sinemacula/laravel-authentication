<h1 align="center">Laravel Authentication</h1>

<div align="center">

[![Latest Stable Version](https://img.shields.io/packagist/v/sinemacula/laravel-authentication.svg)](https://packagist.org/packages/sinemacula/laravel-authentication)
[![Build Status](https://github.com/sinemacula/laravel-authentication/actions/workflows/tests.yml/badge.svg?branch=master)](https://github.com/sinemacula/laravel-authentication/actions/workflows/tests.yml)
[![Quality Gates](https://github.com/sinemacula/laravel-authentication/actions/workflows/quality-gates.yml/badge.svg?branch=master)](https://github.com/sinemacula/laravel-authentication/actions/workflows/quality-gates.yml)
[![Maintainability](https://qlty.sh/gh/sinemacula/projects/laravel-authentication/maintainability.svg)](https://qlty.sh/gh/sinemacula/projects/laravel-authentication)
[![Code Coverage](https://qlty.sh/gh/sinemacula/projects/laravel-authentication/coverage.svg)](https://qlty.sh/gh/sinemacula/projects/laravel-authentication)
[![Total Downloads](https://img.shields.io/packagist/dt/sinemacula/laravel-authentication.svg)](https://packagist.org/packages/sinemacula/laravel-authentication)

</div>

Stateless contextual authentication for Laravel. Distinguishes the authenticated **Identity** from the acting
**Principal** and the issuing **Device**, exposed through Laravel's standard `Auth` facade, middleware, and events.

Drops into Laravel's existing auth machinery - same `Auth::check()`, `Auth::user()`, `auth()->guard('api')`, same
middleware, same events. Adds contextual accessors (`Auth::identity()`, `Auth::principal()`, `Auth::device()`) and
ships a hardened JWT guard.

## Core Concept

Most auth packages collapse "who you are" and "who you're acting as" into a single user. This package separates them:

| Concept       | What it is                                                                                 |
|---------------|--------------------------------------------------------------------------------------------|
| **Identity**  | Who logged in. The account behind the request - a person or a service account.             |
| **Principal** | Who the request is acting as. Often the same as the identity; can be a role or membership. |
| **Device**    | Which client obtained the login - a browser, a mobile app, a CLI session.                  |
| **Tenant**    | The isolation boundary the principal acts within. Optional, for multi-tenant apps.         |
| **Type**      | An optional categorical label on the tenant - e.g. `"staff"` vs `"customer"`.              |

Both **2D** (identity-is-principal) and **3D** (identity → separate principal → tenant) adoption modes are supported
by the same guards. Start 2D, grow into 3D without re-platforming.

Access tokens are self-verifying JWTs with no server-side store. Refresh is stateful - the rotation digest and
device record live in the `devices` table so replay and stale credentials can be detected server-side.

## Features

- **A sessionless `jwt` guard** that authenticates Bearer tokens and signs in with credentials through `attempt()`.
- **Contextual accessors** on the standard `Auth` facade: `identity()`, `principal()`, `device()`, `tenant()`,
  `type()`.
- **Hardened JWT pipeline**: HMAC-only signing (`HS256`, `HS384`, `HS512`), strict `iss` / `aud` / `typ` / `exp` /
  leeway enforcement, per-token `jti`, and fail-closed behaviour on empty or short keys, unsupported algorithms,
  type confusion, and `pid` / `did` mismatches.
- **Refresh-token rotation** with constant-time digest verification, atomic per-device rotation, and
  machine-readable `RefreshFailed` events for SIEM attribution.
- **Kid-based key rotation** - signing keys are always a `kid → secret` map; every token carries the kid that signed
  it, so keys rotate without signing anyone out.
- **Device tracking** with debounced `last_logged_in_at` writes.
- **First-class events** - Laravel's standard `Attempting` / `Validated` / `Authenticated` / `Login` / `Failed`
  alongside custom `PrincipalAssigned` / `DeviceAuthenticated` / `Refreshed` / `RefreshFailed`.
- **Pluggable everywhere**: identity model, device model, principal resolver, table names.

## Design Notes

Adoption-focused quick-starts are below. Maintainer-oriented security and lifecycle contracts live in
`docs/design/`:

- `docs/design/guard-lifecycle-and-events.md`
- `docs/design/refresh-rotation-and-replay.md`
- `docs/design/fail-closed-pid-did.md`
- `docs/design/access-only-mode.md`

## Installation

```bash
composer require sinemacula/laravel-authentication
```

Publish the config and device migration, then migrate:

```bash
php artisan vendor:publish --tag=authentication-config
php artisan vendor:publish --tag=authentication-migrations
php artisan migrate
```

Generate a random JWT signing key into `.env`:

```bash
echo "AUTHENTICATION_JWT_KEY=$(openssl rand -base64 48)" >> .env
```

Signing keys are always configured as a `kid → secret` map. Out of the box the map holds one key, `default`, read from
`AUTHENTICATION_JWT_KEY`, and `AUTHENTICATION_JWT_ACTIVE_KID` (default `default`) selects the key that signs new
tokens. Every token carries its kid in the JWT header. See [Key Rotation](#key-rotation) for adding keys.

Every key must be at least as long as the algorithm's digest: 32 bytes for `HS256` (the default), 48 for `HS384`,
and 64 for `HS512`. `openssl rand -base64 48` prints a 64-character value that satisfies all three. Generate every
key this way rather than writing or copying one by hand.

The package fails closed when a JWT guard or `Auth::jwt(...)` service is resolved with an empty key map, a missing,
empty, or too-short key, or an `active_kid` that is not in the map.

### Access-only mode (no devices, no refresh)

Device tracking and refresh are opt-in. For M2M APIs, simple backends, or short-lived session flows:

1. Skip the `authentication-migrations` publish.
2. Do not implement `HasDevices` on your identity model.
3. Issue access tokens with `Auth::jwt('api')->issueAccessToken($identity, $principal, null)`.
4. Do not call `$guard->refresh(...)`. Clients re-authenticate when the access token expires.

`Auth::device()` returns `null` in this mode; the rest of the contextual surface works normally. See
`docs/design/access-only-mode.md`.

## Configuration

### Guards and providers

Register guards and providers in `config/auth.php` exactly as you would with any first-party guard:

```php
'guards' => [
    'api' => [
        'driver'   => 'jwt',
        'provider' => 'users',
    ],
],

'providers' => [
    'users' => [
        'driver' => 'model',
        'model'  => App\Models\User::class,
    ],
],
```

### Unauthenticated requests

A guest on a route that only package guards protect (`auth:api`, or `auth` when the default guard is a package guard)
gets `401` with `{"message": "Unauthenticated."}`, whatever its `Accept` header. The guards are stateless, so there
is no login page to redirect to, and an API without a `login` route no longer answers browser-style requests with a
server error. Laravel's own guards keep their guest redirect, and so does a route that also accepts one of them
(`auth:web,api`).

The package binds its `SineMacula\Laravel\Authentication\Http\Middleware\Authenticate` in place of Laravel's `auth`
middleware and registers the `401` as an exception-handler render callback, after any your application registers for
`AuthenticationException`. If your application aliases its own `auth` middleware, extend the package's class.

### Per-guard JWT configuration

Every JWT guard inherits its signing material, audience, issuer, TTLs, and leeway from the package-wide
`authentication.jwt.*` defaults. Any guard may override them with a `jwt` sub-block on its `config/auth.php`
entry; missing fields fall back to the defaults:

```php
'guards' => [
    'staff' => [
        'driver'   => 'jwt',
        'provider' => 'users',
        'jwt'      => [
            'keys'       => ['staff-2026-05' => env('STAFF_JWT_KEY')],
            'active_kid' => 'staff-2026-05',
            'audience'   => 'staff-api',
        ],
    ],
    'customer' => [
        'driver'   => 'jwt',
        'provider' => 'users',
        'jwt'      => [
            'keys'       => ['customer-2026-05' => env('CUSTOMER_JWT_KEY')],
            'active_kid' => 'customer-2026-05',
            'audience'   => 'customer-api',
        ],
    ],
],
```

Routes opt into a boundary via `auth:staff` or `auth:customer` middleware. The `aud` claim on each issued token
matches the guard that issued it, so tokens minted for one audience cannot authenticate against the other. Every
field in the package `jwt` block is overridable (`keys`, `active_kid`, `algorithm`, `access_ttl_minutes`,
`refresh_ttl_minutes`, `leeway_seconds`, `issuer`, `audience`). `keys` and `active_kid` fall back independently: a
guard that overrides `keys` should also set `active_kid` to a kid in its own map.

### Per-guard principal resolvers

By default, every guard uses the app-wide `PrincipalResolver` binding. Any guard may override it locally:

```php
'guards' => [
    'staff' => [
        'driver'             => 'jwt',
        'provider'           => 'users',
        'principal_resolver' => App\Auth\Resolvers\StaffPrincipalResolver::class,
    ],
],
```

Precedence: guard-local `principal_resolver` → app-wide `PrincipalResolver::class` binding → package default
`DefaultPrincipalResolver`. The same resolver is used on bearer-token and refresh paths.

### Device

The published `authentication.php` config controls the device model, table, and last-seen debounce:

```php
'device' => [
    'model'                      => SineMacula\Laravel\Authentication\Models\Device::class,
    'table'                      => 'devices',
    'last_seen_throttle_seconds' => 60,
],
```

The shipped `Device` model uses UUID v7 primary keys and a polymorphic `authenticatable` relation. Subclass it
or swap `device.model` entirely - custom models must implement the `EloquentDevice` contract. Column names come from
that contract's accessors (`getRefreshKeyName()`, `getRevokedAtName()`, and so on); the shipped migration creates
the default names, so a model that renames a column needs its own migration.

### Credential validation timing

`attempt()` and `validate()` wrap credential checks in a constant-time `Timebox` to prevent timing side-channels:

```php
'timebox' => [
    'credentials_microseconds' => 400000,
],
```

Must exceed the worst-case hasher cost.

### Read replicas

Every read that decides authentication - the identity, the principal, and the device with its refresh digest and
revocation state - goes to the write connection, even when the database connection has `read` and `write` hosts. A
replica can lag behind a revocation, a deactivation, or a refresh rotation, and a lookup it served could admit a
credential the primary has already rejected.

The package pins the queries it builds. Code you plug in carries the same obligation:

- a custom `IdentityProvider`, a `ModelProvider` subclass that builds its own query, or a custom `PrincipalResolver`
  must read from the write connection;
- `resolveDefaultPrincipal()` and `resolveHintedPrincipal()` already run with reads on the identity's connection pinned
  to the write connection; a lookup they make on another connection must pin itself.

`WriteConnection` does both:

```php
use SineMacula\Laravel\Authentication\Database\WriteConnection;

// A query you build: route it to the write PDO.
$membership = WriteConnection::query(Membership::query())->find($hint);

// Code that reads through a model's connection: pin it for the callback.
$principal = WriteConnection::during($identity, fn () => $this->lookUpPrincipal($identity));
```

## Identity Models

### 2D adoption (identity is the principal)

One model implements both `Identity` and `Principal` - the user who logs in *is* the acting principal:

```php
use Illuminate\Foundation\Auth\User;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Concerns\ActsAsPrincipal;
use SineMacula\Laravel\Authentication\Concerns\Authenticatable;

class AppUser extends User implements Identity, Principal
{
    use Authenticatable, ActsAsPrincipal;
}
```

Point `auth.providers.users.model` at `AppUser::class`. `Auth::identity()` and `Auth::principal()` both return
the same instance.

Add `HasDevices` for device tracking and refresh-token rotation:

```php
use Illuminate\Database\Eloquent\Relations\MorphMany;
use SineMacula\Laravel\Authentication\Contracts\HasDevices;
use SineMacula\Laravel\Authentication\Models\Device;

class AppUser extends User implements Identity, Principal, HasDevices
{
    use Authenticatable, ActsAsPrincipal;

    public function devices(): MorphMany
    {
        return $this->morphMany(Device::class, 'authenticatable');
    }
}
```

### 3D adoption (separate identity, principal, tenant)

For multi-tenant apps where the logged-in human acts on behalf of a tenant-scoped actor, split identity and
principal into two models. The identity implements `HasPrincipals` and returns its own principals query:

```php
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Database\Eloquent\Relations\MorphMany;
use Illuminate\Foundation\Auth\User;
use SineMacula\Laravel\Authentication\Contracts\CanBeActive;
use SineMacula\Laravel\Authentication\Contracts\HasDevices;
use SineMacula\Laravel\Authentication\Contracts\HasPrincipals;
use SineMacula\Laravel\Authentication\Contracts\HasType;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal as PrincipalContract;
use SineMacula\Laravel\Authentication\Contracts\Tenant as TenantContract;
use SineMacula\Laravel\Authentication\Models\Device;
use SineMacula\Laravel\Authentication\Concerns\ActsAsPrincipal;
use SineMacula\Laravel\Authentication\Concerns\ActsAsTenant;
use SineMacula\Laravel\Authentication\Concerns\Authenticatable;
use SineMacula\Laravel\Authentication\Concerns\ProvidesActiveState;
use SineMacula\Laravel\Authentication\Concerns\ProvidesTenantType;

class AppIdentity extends User implements Identity, HasDevices, HasPrincipals
{
    use Authenticatable;

    public function principals(): HasMany
    {
        return $this->hasMany(AppMembership::class, 'identity_id');
    }

    public function devices(): MorphMany
    {
        return $this->morphMany(Device::class, 'authenticatable');
    }

    public function resolveDefaultPrincipal(): ?PrincipalContract
    {
        return $this->principals()->where('is_active', true)->first();
    }
}

class AppMembership extends Model implements CanBeActive, PrincipalContract
{
    use ActsAsPrincipal, ProvidesActiveState;

    protected $fillable = ['identity_id', 'tenant_id', 'role', 'is_active'];

    public function tenant(): BelongsTo
    {
        return $this->belongsTo(AppTenant::class);
    }
}

class AppTenant extends Model implements HasType, TenantContract
{
    use ActsAsTenant, ProvidesTenantType;
}
```

With that shape:

- `Auth::identity()` returns the `AppIdentity`.
- `Auth::principal()` returns the `AppMembership` - resolved via `principals()->find($pid)` when the JWT carries
  a `pid`, or via `resolveDefaultPrincipal()` otherwise.
- `Auth::tenant()` returns the `AppTenant` the membership belongs to.
- `Auth::type()` returns the tenant's type string, or `null` when `HasType` is absent.
- A membership whose `is_active` is `false` cannot sign in, refresh, or authenticate a request (see
  [Active-state enforcement](#active-state-enforcement)).

Implement `ResolvesHintedPrincipal` on the identity to replace the default `principals()->find($hint)` lookup
with a custom query - for example, joining the tenant row in one SQL so `Auth::tenant()` does not lazy-load.

For domain-specific resolution (subdomain, header, session claim), implement `PrincipalResolver` and bind it in
a service provider:

```php
$this->app->singleton(PrincipalResolver::class, MyTenantScopedResolver::class);
```

### Active-state enforcement

Activation is opt-in. A model that does not implement `CanBeActive` is always active, so the 2D example above, on
Laravel's default `users` table, signs in without an activation column. Implement `CanBeActive` on an identity or a
principal to have the guard consult `isActive()` on every credential, bearer, and refresh path and reject
authentication when it returns `false`:

```php
use SineMacula\Laravel\Authentication\Contracts\CanBeActive;

class AppUser extends User implements Identity, Principal, CanBeActive
{
    use Authenticatable, ActsAsPrincipal;

    public function isActive(): bool
    {
        return $this->suspended_at === null;
    }
}
```

To read the flag from a column instead, use the `ProvidesActiveState` trait, as `AppMembership` does above. It reads
`is_active` (override `getActiveAttributeName()` to use another column) and throws a `LogicException` when the model
was loaded without that column, so a partial select is reported instead of being read as either active or inactive.

A tenant opts in the same way. When the tenant a principal acts within implements `CanBeActive` and reports inactive,
every principal in it is rejected on the same paths (refresh fails with `tenant_inactive`):

```php
class AppTenant extends Model implements CanBeActive, HasType, TenantContract
{
    use ActsAsTenant, ProvidesActiveState, ProvidesTenantType;
}
```

Checking the tenant reads `$principal->getTenant()` on every request, so eager-load the tenant in your principal
resolver (or `ResolvesHintedPrincipal`) to avoid a lazy load per request.

## Usage

Contextual accessors on the standard `Auth` facade:

```php
use SineMacula\Laravel\Authentication\Facades\Auth;

Auth::check();          // bool - same as Laravel
Auth::user();           // Identity|null - same as Laravel

Auth::identity();       // Identity|null   - the authenticated subject
Auth::principal();      // Principal|null  - the acting principal
Auth::device();         // Device|null     - the issuing device
Auth::tenant();         // Tenant|null     - the tenant the principal acts within
Auth::type();           // string|null     - the tenant's type when HasType is declared
```

Like `Auth::user()` and `Auth::id()`, each accessor authenticates the request on first access, so they also work on
routes without `auth` middleware. A request is authenticated at most once, whether its token is accepted or rejected,
and after `Auth::logout()` it stays signed out for the rest of the request.

`setUser()`, which Laravel's `actingAs()` uses, replaces the whole context: it binds the identity with its default
principal (and no device), and throws an `InvalidArgumentException` when the identity has none. Use the guard's
`login($identity, $principal, $device)` to bind a specific principal or a device.

Sign in with credentials through `attempt()`, optionally pinning the principal and device to act as:

```php
$guard->attempt(['email' => $email, 'password' => $password], $membership, $device);
```

The pins are verified rather than trusted, because they often come from request input: the principal must be one the
resolver returns for that identifier on the authenticated identity (same class, same identifier), and the device must
be one of the identity's own devices (through `HasDevices`) and not revoked. A pin that fails either check fails the
attempt. `login()` is the trusted entry point: it binds exactly what it is given, so only pass it a principal and device
you have already proven belong to the identity.

Issue tokens through the guard-scoped JWT service, then use the guard for refresh:

```php
$tokens = Auth::jwt('api');
$guard  = auth()->guard('api');

$accessToken = $tokens->issueAccessToken($identity, $principal, $device);

$rotated = $guard->refresh($refreshToken);

if ($rotated === null) {
    // RefreshFailed event already dispatched with a machine-readable reason
    abort(401);
}

return [
    'access_token'  => $rotated->accessToken,
    'refresh_token' => $rotated->refreshToken,
];
```

## Key Rotation

Signing keys live in `jwt.keys` as a `kid → secret` map, and `jwt.active_kid` names the key that signs new tokens.
New tokens carry the active kid in their JWT header; the verifier accepts any kid in the map. To rotate, add the new
key to the published `config/authentication.php` alongside the current one and point `active_kid` at it:

```php
'jwt' => [
    'keys' => [
        'default' => env('AUTHENTICATION_JWT_KEY'),
        '2026-05' => env('AUTHENTICATION_JWT_KEY_2026_05'),
    ],
    'active_kid' => env('AUTHENTICATION_JWT_ACTIVE_KID', 'default'),
],
```

Generate the new key into `.env`, then set `AUTHENTICATION_JWT_ACTIVE_KID` to its kid:

```bash
echo "AUTHENTICATION_JWT_KEY_2026_05=$(openssl rand -base64 48)" >> .env
```

```dotenv
AUTHENTICATION_JWT_ACTIVE_KID="2026-05"
```

Tokens signed under `default` keep verifying while it stays in the map. Remove it once every token signed under it
has expired (the longer of the access and refresh token lifetimes). Removing a kid immediately rejects every token
signed under it, which is also how to revoke a compromised key.

## Events

| Event                                       | Fired when                                                |
|---------------------------------------------|-----------------------------------------------------------|
| `Illuminate\Auth\Events\Attempting`         | Bearer, refresh, or credential attempt starts             |
| `Illuminate\Auth\Events\Validated`          | A successful `login()` path is about to bind context      |
| `Illuminate\Auth\Events\Authenticated`      | Identity bound to the guard                               |
| `Illuminate\Auth\Events\Login`              | Full lifecycle complete                                   |
| `Illuminate\Auth\Events\Failed`             | Any bearer, refresh, or credential rejection              |
| `SineMacula\...\Events\PrincipalAssigned`   | Principal resolved and bound                              |
| `SineMacula\...\Events\DeviceAuthenticated` | Device hydrated and bound; listeners may persist metadata |
| `SineMacula\...\Events\Refreshed`           | Refresh exchange completed                                |
| `SineMacula\...\Events\RefreshFailed`       | Refresh exchange failed (carries machine-readable reason) |

The credentials on `Attempting` and `Failed` never include a password: every key whose name contains `password`
(case-insensitive), such as `password`, `current_password`, or `password_confirmation`, is removed before the event is
dispatched, and the identifier is kept for throttling and audit listeners. To remove more keys, list name fragments in
the published config:

```php
'events' => [
    'redacted_credential_keys' => ['secret', 'code'],
],
```

`RefreshFailed` carries a `RefreshFailureReason` backed enum for SIEM attribution:

| Reason                    | Meaning                                              |
|---------------------------|------------------------------------------------------|
| `token_invalid`           | Decode, expiry, typ, iss, or aud failure             |
| `device_unknown`          | Device id did not resolve                            |
| `rotation_mismatch`       | Digest did not match the stored refresh key          |
| `rotation_reuse`          | Replay or concurrent rotation; device revoked        |
| `device_revoked`          | Device row marked revoked                            |
| `authenticatable_missing` | Device authenticatable relation missing              |
| `identity_inactive`       | Resolved identity reported inactive                  |
| `principal_unresolved`    | Principal resolver returned null                     |
| `principal_mismatch`      | Resolved principal does not match refresh token hint |
| `principal_inactive`      | Resolved principal reported inactive                 |
| `tenant_inactive`         | Tenant the resolved principal acts within inactive   |

## Extensibility

Concrete classes in this package are `final` unless noted below. Extension is through **composition and DI**, not
inheritance:

| Extension point                   | How                                                                    |
|-----------------------------------|------------------------------------------------------------------------|
| Custom identity / principal model | Implement `Identity`, `Principal` (and optional capability interfaces) |
| Custom device model               | Implement `EloquentDevice`, use the `ActsAsDevice` trait               |
| Custom principal resolution       | Implement `PrincipalResolver`, bind per-guard or globally              |
| Custom identity retrieval         | Subclass `ModelProvider` (non-final)                                   |
| Custom `auth` middleware          | Subclass `Http\Middleware\Authenticate` (non-final)                    |
| Guard-scoped JWT settings         | Override `jwt.*` keys in `auth.guards.<name>.jwt`                      |

`AbstractGuard` is not final and may be extended for entirely new guard types.

## Requirements

- PHP ^8.3 (extensions: hash, mbstring, openssl)
- Laravel ^12.40 || ^13.3

## Testing

```bash
composer test               # all suites in parallel (Paratest)
composer test:coverage      # all suites with clover coverage
composer test:unit          # unit suite only
composer test:feature       # feature suite only
composer test:integration   # integration suite only
composer test:performance   # performance budget suite (serial)
composer test:mutation      # scoped mutation gate
composer test:mutation:full # full mutation suite (no thresholds)
composer bench              # PHPBench hot-path benchmarks
composer check              # static analysis + style
composer format             # format the codebase
composer smells             # advisory code smells (duplication, complexity)
```

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for a list of notable changes.

## Contributing

Contributions are welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on branching, commits, code
quality, and pull requests.

## Security

If you discover a security vulnerability, please report it responsibly. See [SECURITY.md](SECURITY.md) for the
disclosure policy and contact details.

## License

Licensed under the [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0).
