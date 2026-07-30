# Laravel Authentication

[![Latest Stable Version](https://img.shields.io/packagist/v/sinemacula/laravel-authentication.svg)](https://packagist.org/packages/sinemacula/laravel-authentication)
[![Build Status](https://github.com/sinemacula/laravel-authentication/actions/workflows/tests.yml/badge.svg?branch=master)](https://github.com/sinemacula/laravel-authentication/actions/workflows/tests.yml)
[![Maintainability](https://qlty.sh/gh/sinemacula/projects/laravel-authentication/maintainability.svg)](https://qlty.sh/gh/sinemacula/projects/laravel-authentication)
[![Code Coverage](https://qlty.sh/gh/sinemacula/projects/laravel-authentication/coverage.svg)](https://qlty.sh/gh/sinemacula/projects/laravel-authentication)
[![Total Downloads](https://img.shields.io/packagist/dt/sinemacula/laravel-authentication.svg)](https://packagist.org/packages/sinemacula/laravel-authentication)

Stateless contextual authentication for Laravel. Distinguishes the authenticated **Identity** from the acting
**Principal** and the issuing **Device**, exposed through Laravel's standard `Auth` facade, middleware, and events.

Drops into Laravel's existing auth machinery - same `Auth::check()`, `Auth::user()`, `auth()->guard('api')`, same
middleware, same events. Adds contextual accessors (`Auth::identity()`, `Auth::principal()`, `Auth::device()`) and
ships hardened JWT and HTTP Basic guards.

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

- **Two guards**, both sessionless: `jwt` (Bearer token) and `basic` (HTTP Basic).
- **Contextual accessors** on the standard `Auth` facade: `identity()`, `principal()`, `device()`, `tenant()`,
  `type()`.
- **Hardened JWT pipeline**: strict `iss` / `aud` / `typ` / `exp` / leeway enforcement, per-token `jti`, and
  fail-closed behaviour on empty secrets, unsupported algorithms, type confusion, and `pid` / `did` mismatches.
- **Refresh-token rotation** with constant-time digest verification, atomic per-device rotation, and
  machine-readable `RefreshFailed` events for SIEM attribution.
- **Kid-based key rotation** - issue under one kid, verify against a `kid → secret` map.
- **Device tracking** with debounced `last_logged_in_at` writes.
- **First-class events** - Laravel's standard `Attempting` / `Validated` / `Authenticated` / `Login` / `Failed`
  alongside custom `PrincipalAssigned` / `DeviceAuthenticated` / `Refreshed` / `RefreshFailed`.
- **Pluggable everywhere**: identity model, device model, principal resolver, identifier field, table names.

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

Set the JWT secret:

```dotenv
AUTHENTICATION_JWT_SECRET="a-strong-random-value-of-at-least-32-bytes"
```

The package fails closed when a JWT guard or `Auth::jwt(...)` service is resolved with empty or invalid signing
material.

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
    'cli' => [
        'driver'   => 'basic',
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
            'secret'   => env('STAFF_JWT_SECRET'),
            'audience' => 'staff-api',
        ],
    ],
    'customer' => [
        'driver'   => 'jwt',
        'provider' => 'users',
        'jwt'      => [
            'secret'   => env('CUSTOMER_JWT_SECRET'),
            'audience' => 'customer-api',
        ],
    ],
],
```

Routes opt into a boundary via `auth:staff` or `auth:customer` middleware. The `aud` claim on each issued token
matches the guard that issued it, so tokens minted for one audience cannot authenticate against the other. Every
field in the package `jwt` block is overridable (`secret`, `keys`, `active_kid`, `algorithm`,
`access_ttl_minutes`, `refresh_ttl_minutes`, `leeway_seconds`, `issuer`, `audience`).

### Per-guard basic-auth identifier field

The `basic` driver accepts an `identifier_field` override - e.g. an `email`-keyed web guard alongside a `key_id`
-keyed tenant API guard:

```php
'guards' => [
    'cli' => [
        'driver'   => 'basic',
        'provider' => 'users',
    ],
    'tenant_api' => [
        'driver'           => 'basic',
        'provider'         => 'tenant_api_keys',
        'identifier_field' => 'key_id',
    ],
],

'providers' => [
    'tenant_api_keys' => [
        'driver' => 'model',
        'model'  => App\Models\TenantApiKey::class,
    ],
],
```

Omitting `identifier_field` falls back to `authentication.credentials.identifier_field` (default `email`).

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
    'refresh_key_column'         => 'refresh_key',
    'last_seen_throttle_seconds' => 60,
],
```

The shipped `Device` model uses UUID v7 primary keys and a polymorphic `authenticatable` relation. Subclass it
or swap `device.model` entirely - custom models must implement the `EloquentDevice` contract.

### Credential validation timing

The `basic` guard wraps credential checks in a constant-time `Timebox` to prevent timing side-channels:

```php
'timebox' => [
    'credentials_microseconds' => 400000,
],
```

Must exceed the worst-case hasher cost.

### Optional bearer identity cache

Cross-request resolution caching is off by default. When enabled, it applies only to JWT bearer identity
rehydration through model providers - basic-auth lookups, device lookups, principal resolution, and the refresh
path stay live.

```php
'resolution_cache' => [
    'store' => env('AUTHENTICATION_RESOLUTION_CACHE_STORE'),
    'jwt'   => [
        'identity_ttl_seconds'  => env('AUTHENTICATION_JWT_IDENTITY_CACHE_TTL_SECONDS', 0),
        'principal_ttl_seconds' => env('AUTHENTICATION_JWT_PRINCIPAL_CACHE_TTL_SECONDS', 0),
    ],
],
```

- `identity_ttl_seconds = 0` disables the cache.
- `principal_ttl_seconds` is reserved for future use; leave at `0`.
- Active-state checks, `pid` matching, and `did` device validation still run live on every request.

If you opt in, wire explicit invalidation from your identity model observer:

```php
use App\Models\User;
use SineMacula\Laravel\Authentication\Cache\ResolutionCacheInvalidator;

final class UserObserver
{
    public function saved(User $user): void
    {
        app(ResolutionCacheInvalidator::class)->forgetIdentity($user);
    }

    public function deleted(User $user): void
    {
        app(ResolutionCacheInvalidator::class)->forgetIdentity($user);
    }
}
```

Do not enable the cache unless that invalidation wiring is in place. If the auth identifier itself changes, pass
the previous identifier to `forgetIdentity()` as well.

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

class AppMembership extends Model implements PrincipalContract
{
    use ActsAsPrincipal;

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

Implement `ResolvesHintedPrincipal` on the identity to replace the default `principals()->find($hint)` lookup
with a custom query - for example, joining the tenant row in one SQL so `Auth::tenant()` does not lazy-load.

For domain-specific resolution (subdomain, header, session claim), implement `PrincipalResolver` and bind it in
a service provider:

```php
$this->app->singleton(PrincipalResolver::class, MyTenantScopedResolver::class);
```

### Active-state enforcement

When an identity model implements `CanBeActive`, both guards consult `isActive()` on every bearer and credential
path and reject authentication when it returns `false`:

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

### HTTP Basic behind PHP-FPM / nginx

The `basic` guard reads credentials via `Request::getUser()` / `Request::getPassword()`, which pull from
`$_SERVER['PHP_AUTH_USER']` / `PHP_AUTH_PW`. Behind **PHP-FPM + nginx**, the `Authorization` header is **not**
forwarded into those superglobals by default - forward it explicitly:

```nginx
location ~ \.php$ {
    fastcgi_pass_header Authorization;
    # ...rest of the fastcgi block
}
```

Apache with `mod_php` populates these variables automatically.

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

For graceful signing-key rotation, configure `jwt.keys` and `jwt.active_kid`:

```php
'jwt' => [
    'keys' => [
        '2026-04' => env('AUTHENTICATION_JWT_KEY_2026_04'),
        '2026-03' => env('AUTHENTICATION_JWT_KEY_2026_03'),
    ],
    'active_kid' => env('AUTHENTICATION_JWT_ACTIVE_KID', '2026-04'),
],
```

New tokens are signed with the active kid and carry it in the JWT header. The verifier accepts any kid in the
map - add a new kid, point `active_kid` at it, retire the old kid once every token signed under it has expired.

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

## Extensibility

All concrete classes in this package are `final`. Extension is through **composition and DI**, not inheritance:

| Extension point                   | How                                                                    |
|-----------------------------------|------------------------------------------------------------------------|
| Custom identity / principal model | Implement `Identity`, `Principal` (and optional capability interfaces) |
| Custom device model               | Implement `EloquentDevice`, use the `ActsAsDevice` trait               |
| Custom principal resolution       | Implement `PrincipalResolver`, bind per-guard or globally              |
| Custom identity retrieval         | Subclass `ModelProvider` (the one non-final service)                   |
| Guard-scoped JWT settings         | Override `jwt.*` keys in `auth.guards.<name>.jwt`                      |
| Resolution caching                | Bind your own `ResolutionCache` implementation                         |

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
```

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for a list of notable changes.

## Contributing

Contributions are welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md)
for guidelines on branching, commits, code quality, and pull requests.

## Security

If you discover a security vulnerability, please report it responsibly.
See [SECURITY.md](SECURITY.md) for the disclosure policy and contact
details.

## License

Licensed under the [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0).
