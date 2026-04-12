# Laravel Authentication

[![Latest Stable Version](https://img.shields.io/packagist/v/sinemacula/laravel-authentication.svg)](https://packagist.org/packages/sinemacula/laravel-authentication)
[![Build Status](https://github.com/sinemacula/laravel-authentication/actions/workflows/tests.yml/badge.svg?branch=master)](https://github.com/sinemacula/laravel-authentication/actions/workflows/tests.yml)
[![Maintainability](https://qlty.sh/gh/sinemacula/projects/laravel-authentication/maintainability.svg)](https://qlty.sh/gh/sinemacula/projects/laravel-authentication)
[![Code Coverage](https://qlty.sh/gh/sinemacula/projects/laravel-authentication/coverage.svg)](https://qlty.sh/gh/sinemacula/projects/laravel-authentication)
[![Total Downloads](https://img.shields.io/packagist/dt/sinemacula/laravel-authentication.svg)](https://packagist.org/packages/sinemacula/laravel-authentication)

Stateless contextual authentication for Laravel. Distinguishes the authenticated **Identity** from the acting
**Principal** and the issuing **Device**, exposed through Laravel's standard `Auth` facade, middleware, and events.

Drops into Laravel's existing auth machinery - no new API to learn. Same `Auth::check()`, `Auth::user()`,
`auth()->guard('api')`, same middleware, same events. Adds contextual accessors (`Auth::identity()`,
`Auth::principal()`, `Auth::device()`) and ships hardened JWT and HTTP Basic guards.

## Core Concept

Most auth packages collapse "who you are" and "who you're acting as" into a single user. This package separates them:

| Concept       | What it is                                                                                 |
|---------------|--------------------------------------------------------------------------------------------|
| **Identity**  | Who logged in. The account behind the request - a person or a service account.             |
| **Principal** | Who the request is acting as. Often the same as the identity; can be a role or membership. |
| **Device**    | Which client obtained the login - a browser, a mobile app, a CLI session.                  |
| **Tenant**    | The isolation boundary the principal acts within. Optional, for multi-tenant apps.         |
| **Type**      | An optional categorical label on the tenant - e.g. `"staff"` vs `"customer"`.              |

Both **2D** (identity-is-principal) and **3D** (identity → separate principal → tenant) adoption modes are
supported by the same guards. Start 2D, grow into 3D without re-platforming.

**Self-verifying for access, stateful for refresh.** Access tokens are validated as standalone JWTs: there is no
session, remember-token, or server-side access-token store. On the bearer path, however, the guard still rehydrates
the identity from the configured provider, resolves the active principal, and may reload the device record when the
token carries a usable `did` hint. When a persisted device is rebound, normal device-authenticated side effects such
as debounced `last_logged_in_at` updates can still occur. Refresh tokens are a different story: the rotation digest,
device record, and last-login timestamp all live in the `devices` table. Refresh is therefore inherently stateful,
and the package owns that state so replay attacks and stale credentials can be detected server-side.

## Features

- **Two guards**, both sessionless: `jwt` (Bearer token) and `basic` (HTTP Basic) - register via `auth.guards.*.driver`
- **Contextual accessors** on the standard `Auth` facade: `identity()`, `principal()`, `device()`, `tenant()`,
  `type()`
- **Hardened JWT pipeline**: enforces `iss` / `aud` / `typ` / `exp` / leeway on every parse, embeds a per-token `jti`
  on issue, fails closed on empty secrets, unsupported algorithms, type-confusion attacks, and mismatched `pid` /
  `did` claims
- **Refresh-token rotation** with constant-time digest verification, atomic per-device rotation, and machine-readable
  `RefreshFailed` events on every failure path for SIEM attribution
- **Kid-based key rotation** - issue under one kid, verify against a `kid → secret` map, retire old kids once their
  tokens expire
- **Device tracking** with debounced `last_logged_in_at` writes to avoid per-request hot-spots
- **First-class events** - fires Laravel's standard `Attempting` / `Validated` / `Authenticated` / `Login` / `Failed`
  alongside custom `PrincipalAssigned` / `DeviceAuthenticated` / `Refreshed` / `RefreshFailed`
- **Pluggable everywhere**: identity model, device model, principal resolver, identifier field, table names

## Design Notes

The quick-start sections below focus on adoption. The maintainer-oriented security and lifecycle contracts live in
`docs/design/` and cite the concrete implementation paths and tests that are meant to be authoritative:

- `docs/design/guard-lifecycle-and-events.md`
- `docs/design/refresh-rotation-and-replay.md`
- `docs/design/fail-closed-pid-did.md`
- `docs/design/access-only-mode.md`

## Installation

```bash
composer require sinemacula/laravel-authentication
```

Publish the config and the device migration, then migrate:

```bash
php artisan vendor:publish --tag=authentication-config
php artisan vendor:publish --tag=authentication-migrations
php artisan migrate
```

Set the JWT secret in your environment:

```dotenv
AUTHENTICATION_JWT_SECRET="a-strong-random-value-of-at-least-32-bytes"
```

The package fails closed when a JWT guard or `Auth::jwt(...)` service is resolved with empty or invalid signing
material - silent acceptance of forged tokens is never the default.

### Minimal setup: access-only, no refresh, no devices

The device entity and refresh-token rotation are opt-in. If you only need access tokens without device binding or
refresh (the common pattern for M2M APIs, simple backends, and short-lived session flows), you can skip the devices
migration entirely:

1. Publish only the config: `php artisan vendor:publish --tag=authentication-config`. Skip the
   `authentication-migrations` tag.
2. Do not implement the `HasDevices` capability contract on your identity model.
3. Issue access tokens through the guard-scoped issuer: `Auth::jwt('api')->issueAccessToken($identity, $principal, null)`.
   The token carries `did = null`, so there is no usable device hint on the bearer path.
4. Do not call `$guard->refresh($refreshToken)`. Clients re-authenticate when their access token expires.

In this mode the package never touches a `devices` table because the access token carries no usable device hint and
refresh is unused. Bearer auth still rehydrates the identity and principal through the configured provider and
resolver, `Auth::device()` returns `null`, and the full identity/principal contextual surface (`Auth::identity()`,
`Auth::principal()`, `Auth::tenant()`, `Auth::type()`) still works normally. Add the migration and refresh flow later
if the use case grows into it - it's additive, not a rewrite.

Security note: access-token `jti` values are not consulted on the bearer path. Revoking a device blocks refresh for
that device, but already-issued access tokens remain valid until expiry unless the underlying identity, principal, or
device can no longer be rehydrated.

## Configuration

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

Your identity model implements `Identity` (and optionally `Principal`, `HasPrincipals`, `HasDevices`,
`CanBeActive`) - most apps just `use Authenticatable` and `use ActsAsPrincipal` from the package traits.

### Optional bearer identity cache

Cross-request resolution caching is off by default. When enabled, it applies only to JWT bearer identity
rehydration through model providers; basic-auth credential lookups, bearer device lookup, principal resolution,
and the entire refresh path stay live.

```php
'resolution_cache' => [
    'store' => env('AUTHENTICATION_RESOLUTION_CACHE_STORE'),
    'jwt'   => [
        'identity_ttl_seconds'  => env('AUTHENTICATION_JWT_IDENTITY_CACHE_TTL_SECONDS', 0),
        'principal_ttl_seconds' => env('AUTHENTICATION_JWT_PRINCIPAL_CACHE_TTL_SECONDS', 0),
    ],
],
```

- `identity_ttl_seconds = 0` disables the shared cache.
- `principal_ttl_seconds` is reserved for future use and should stay `0`.
- Cache hits only short-circuit the bearer identity provider lookup. Active-state checks, `pid` matching, and
  `did` device validation still run live on every request.
- Refresh never uses this cache. Revocation and replay detection remain device-backed and immediate.

If you opt in, wire explicit invalidation from your identity model observer or equivalent write path:

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

If the auth identifier changes, invalidate the previous identifier explicitly as well:

```php
$previousIdentifier = $user->getOriginal($user->getAuthIdentifierName());

app(ResolutionCacheInvalidator::class)->forgetIdentity($user, $previousIdentifier);
app(ResolutionCacheInvalidator::class)->forgetIdentity($user);
```

Do not enable the shared cache unless that invalidation wiring is in place.

### Per-guard JWT configuration

Every JWT guard inherits its signing material, audience, issuer, TTLs, and leeway from the package-wide
`authentication.jwt.*` defaults. Any guard may override these per-guard by adding a `jwt` sub-block to its
`config/auth.php` entry - missing fields fall back to the package defaults. This lets you register multiple
jwt guards with distinct trust boundaries in a single app:

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

Routes then opt into a specific boundary via `auth:staff` or `auth:customer` middleware, and the `aud` claim
on every issued token matches the guard that issued it - tokens minted for one audience cannot authenticate
against the other. Any field from the package `jwt` block is overridable (`secret`, `keys`, `active_kid`,
`algorithm`, `access_ttl_minutes`, `refresh_ttl_minutes`, `leeway_seconds`, `issuer`, `audience`), so each
guard can also carry its own kid-rotation set if you want fully independent signing-key lifecycles.

Issue tokens through that same guard context:

```php
$staffAccessToken = Auth::jwt('staff')->issueAccessToken($identity, $principal, $device);
```

### Per-guard basic-auth identifier field

The same layering applies to the basic driver via `identifier_field`. Register multiple basic guards backed by
different providers and looked up by different columns - e.g. an `email`-keyed web guard for users and a
`key_id`-keyed tenant API guard for per-tenant service credentials:

```php
'guards' => [
    'cli' => [
        'driver'   => 'basic',
        'provider' => 'users',
        // identifier_field omitted - falls back to `authentication.credentials.identifier_field` (default `email`)
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

The `TenantApiKey` model implements `Identity` (and `Principal` in 2D mode), carries whatever tenant foreign
key your domain uses, and is hashed/verified against the standard Laravel hasher just like a user password.

### Per-guard principal resolvers

Principal resolution layers the same way. By default, every guard uses the app-wide
`SineMacula\Laravel\Authentication\Contracts\PrincipalResolver` binding. Any individual guard may override that
with a `principal_resolver` entry in `config/auth.php`:

```php
'guards' => [
    'staff' => [
        'driver'             => 'jwt',
        'provider'           => 'users',
        'principal_resolver' => App\Auth\Resolvers\StaffPrincipalResolver::class,
    ],
    'customer' => [
        'driver'             => 'jwt',
        'provider'           => 'users',
        'principal_resolver' => App\Auth\Resolvers\CustomerPrincipalResolver::class,
    ],
],
```

Precedence is:

1. `auth.guards.<name>.principal_resolver`
2. the app-wide `PrincipalResolver::class` container binding
3. the package default `DefaultPrincipalResolver`

This applies equally to bearer-token resolution and JWT refresh exchange: when a guard declares a local
resolver, both paths use that same resolver instance.

### 2D adoption (identity is the principal)

The simplest shape. One model implements both `Identity` and `Principal` - the user who logs in *is* the actor on
whose behalf the request runs:

```php
use Illuminate\Foundation\Auth\User;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Traits\ActsAsPrincipal;
use SineMacula\Laravel\Authentication\Traits\Authenticatable;

class AppUser extends User implements Identity, Principal
{
    use Authenticatable, ActsAsPrincipal;
}
```

Point `auth.providers.users.model` at `AppUser::class` and you're done. `Auth::identity()` and `Auth::principal()`
both return the same `AppUser` instance.

### 3D adoption (separate identity, principal, and tenant)

For multi-tenant apps where the logged-in human operates on behalf of a tenant-scoped actor, split identity and
principal into two models. The identity implements `HasPrincipals` and returns its own `principals()` query:

```php
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Foundation\Auth\User;
use SineMacula\Laravel\Authentication\Contracts\HasPrincipals;
use SineMacula\Laravel\Authentication\Contracts\HasType;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal as PrincipalContract;
use SineMacula\Laravel\Authentication\Contracts\Tenant as TenantContract;
use SineMacula\Laravel\Authentication\Traits\ActsAsPrincipal;
use SineMacula\Laravel\Authentication\Traits\ActsAsTenant;
use SineMacula\Laravel\Authentication\Traits\Authenticatable;
use SineMacula\Laravel\Authentication\Traits\ProvidesTenantType;

// The human - implements Identity + HasPrincipals, NOT Principal.
class AppIdentity extends User implements Identity, HasPrincipals
{
    use Authenticatable;

    /**
     * Returns the principals this identity is permitted to act as.
     * The package's default resolver calls `->find($hint)` when the
     * access token carries a `pid` claim, and `resolveDefaultPrincipal()`
     * otherwise.
     */
    public function principals(): HasMany
    {
        return $this->hasMany(AppMembership::class, 'identity_id');
    }

    public function resolveDefaultPrincipal(): ?PrincipalContract
    {
        return $this->principals()->where('is_active', true)->first();
    }
}

// The acting principal - a per-tenant membership. Implements Principal
// and belongs to a Tenant.
class AppMembership extends \Illuminate\Database\Eloquent\Model implements PrincipalContract
{
    use ActsAsPrincipal;

    protected $fillable = ['identity_id', 'tenant_id', 'role', 'is_active'];

    public function tenant(): \Illuminate\Database\Eloquent\Relations\BelongsTo
    {
        return $this->belongsTo(AppTenant::class);
    }
}

// The tenant - implements Tenant so `Auth::tenant()` can return it.
// Also declares HasType so `Auth::type()` exposes the tenant's
// category label (e.g. `'staff'` vs `'customer'`). The HasType
// capability is optional - drop it if your app doesn't need it.
class AppTenant extends \Illuminate\Database\Eloquent\Model implements HasType, TenantContract
{
    use ActsAsTenant, ProvidesTenantType;
}
```

With that shape:

- `Auth::identity()` returns the `AppIdentity` (the human)
- `Auth::principal()` returns the `AppMembership` (the tenant-scoped actor) - resolved via the `pid` claim in the
  access token, or via `resolveDefaultPrincipal()` on first login
- `Auth::tenant()` returns the `AppTenant` the membership belongs to
- `Auth::type()` returns the tenant's type string (e.g. `'staff'`, `'customer'`) when the tenant implements
  `HasType`, and `null` otherwise; compose your own predicates at the call site (`Auth::type() === 'staff'`)

If you need a domain-specific resolution strategy (scoped by subdomain, header, session claim, etc.), implement
`SineMacula\Laravel\Authentication\Contracts\PrincipalResolver` yourself and bind it in a service provider:

```php
$this->app->singleton(PrincipalResolver::class, MyTenantScopedResolver::class);
```

All guards without a local `principal_resolver` override will use that binding for bearer-token and refresh
resolution. Guards that do declare `auth.guards.<name>.principal_resolver` take precedence over the app-wide
binding. No guard subclassing required.

### HTTP Basic behind PHP-FPM / nginx

The `basic` guard reads credentials via `Request::getUser()` / `Request::getPassword()`, which in turn pull from
PHP's `$_SERVER['PHP_AUTH_USER']` / `PHP_AUTH_PW`. Behind **PHP-FPM + nginx**, the `Authorization` header is **not**
automatically forwarded into those superglobals - the guard will see no credentials and return `null` from
`Auth::user()`. Forward the header explicitly in your nginx site config:

```nginx
location ~ \.php$ {
    fastcgi_pass_header Authorization;
    # …rest of the fastcgi block
}
```

Apache with `mod_php` populates these variables automatically; the gotcha is specific to FastCGI transports.

## Usage

The contextual accessors are exposed on the standard `Auth` facade:

```php
use SineMacula\Laravel\Authentication\Facades\Auth;

Auth::check();          // bool - same as Laravel
Auth::user();           // Identity|null - same as Laravel

Auth::identity();       // Identity|null   - the authenticated subject
Auth::principal();      // Principal|null  - the acting principal
Auth::device();         // Device|null     - the issuing device
Auth::tenant();         // Tenant|null     - the tenant the principal acts within
Auth::type();           // string|null     - the tenant's type, when the tenant declares HasType
```

Issue tokens through the guard-scoped JWT service, then use the guard for refresh:

```php
$tokens = Auth::jwt('api');
$guard = auth()->guard('api');

$accessToken = $tokens->issueAccessToken($identity, $principal, $device);

$rotated = $guard->refresh($refreshToken);   // RefreshResult|null

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

For production deployments that need graceful signing-key rotation, configure `jwt.keys` and `jwt.active_kid`:

```php
'jwt' => [
    'keys' => [
        '2026-04' => env('AUTHENTICATION_JWT_KEY_2026_04'),
        '2026-03' => env('AUTHENTICATION_JWT_KEY_2026_03'),
    ],
    'active_kid' => env('AUTHENTICATION_JWT_ACTIVE_KID', '2026-04'),
],
```

New tokens are signed with the active kid and carry it in the JWT header. The verifier accepts any kid present in the
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

## Requirements

- PHP ^8.3
- Laravel ^12.40 || ^13.3

## Testing

```bash
composer test
composer test-coverage
composer check
```

## Contributing

Contributions are welcome via GitHub pull requests.

## Security

If you discover a security issue, please contact Sine Macula directly rather than opening a public issue.

## License

Licensed under the [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0).
