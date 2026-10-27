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
| **Type**      | An optional label on the principal, or its tenant - e.g. `"staff"` vs `"client_admin"`.    |

Both **2D** (identity-is-principal) and **3D** (identity → separate principal → tenant) adoption modes are supported
by the same guards. Start 2D, grow into 3D without re-platforming.

Access tokens are self-verifying JWTs with no server-side store. Refresh is stateful - the rotation digest and
device record live in the `devices` table so replay and stale credentials can be detected server-side.

## Features

- **A sessionless `jwt` guard** that authenticates Bearer tokens and signs in with credentials through `attempt()`.
- **Pluggable sign-in methods** behind one `SignInMethod` contract (a password method ships; SSO and others register
  on the `SignInMethodManager`), checked against each guard's audience policy and attempt limits, with an
  additional-factor seam whose default never asks for one.
- **Contextual accessors** on the standard `Auth` facade: `identity()`, `principal()`, `device()`, `tenant()`,
  `type()`.
- **Hardened JWT pipeline**: HMAC-only signing (`HS256`, `HS384`, `HS512`), every token bound to the guard that
  issued it, strict `iss` / `aud` / `typ` / `exp` / leeway enforcement, required claims per token type (`exp`, `iat`,
  `jti`, `typ`, and `grd` on both, plus `sub` and `pid` on access tokens and `did` on refresh tokens), the principal's
  type in `pty` on access tokens when it has one, and fail-closed behaviour on empty or short keys, unsupported
  algorithms, type confusion, tokens from another guard, missing claims, and `pid` / `did` mismatches.
- **Refresh-token rotation with replay detection**: constant-time digest verification, atomic per-device rotation, a
  short grace window for lost responses and parallel refreshes, revocation of the device when a rotated refresh token
  is replayed, and machine-readable `RefreshFailed` and `DeviceRevoked` events for SIEM attribution. Every refresh is
  held to the device's guard and the guard's audience policy, and failed refreshes are counted, with a 429 past the
  limit.
- **Kid-based key rotation** - signing keys are always a `kid → secret` map; every token carries the kid that signed
  it, so keys rotate without signing anyone out.
- **A session service** per JWT guard, `Auth::sessions('api')`, that signs in through a method or starts a session for
  an externally verified identity, creates the device (or continues the one a client proves it holds), issues the first
  token pair, binds the guard, and reports `DeviceCreated` and `SignedIn` once committed.
- **Device records**, one per signed-in session: owner, principal, guard, sign-in method and client metadata, the last
  use (time, IP address, user agent, debounced), the session's idle and absolute deadlines, and revocation with a
  reason. Refresh digests are hidden from serialisation.
- **First-class events** - Laravel's standard `Attempting` / `Validated` / `Authenticated` / `Login` / `Failed`
  alongside custom `PrincipalAssigned` / `DeviceAuthenticated` / `SignedIn` / `DeviceCreated` / `SignInFailed` /
  `Refreshed` / `RefreshFailed` / `DeviceRevoked` / `IdentifierVerified`.
- **Audiences per guard**: the sign-in methods and principal types each guard admits, and token and session lifetimes
  per principal type.
- **Normalised identifiers**: designated identifiers stored and looked up in one form (trimmed, lower-cased email by
  default), and a password rehash that never overwrites a concurrent change.
- **Rate limits in the database**: sign-in and refresh limited per identifier and per IP address, counted atomically on
  the write connection without a cache.
- **Identifier verification**: signed verification links bound to their purpose and identifier, and an opt-in,
  per-guard requirement that sign-in identifiers be verified.
- **Pluggable everywhere**: identity model, device model, principal resolver, sign-in methods, additional-factor
  policy, audience policy, attempt limiter, identifier normalisers, table names.

## Design Notes

Adoption-focused quick-starts are below. Maintainer-oriented security and lifecycle contracts live in
`docs/design/`:

- `docs/design/guard-lifecycle-and-events.md`
- `docs/design/refresh-rotation-and-replay.md`
- `docs/design/fail-closed-pid-did.md`
- `docs/design/access-only-mode.md`
- `docs/design/guard-bound-tokens.md`
- `docs/design/session-service.md`
- `docs/design/audience-policy.md`

## Installation

```bash
composer require sinemacula/laravel-authentication
```

Publish the config and the migrations (the `devices`, `pending_sign_ins` and `rate_limits` tables), then migrate:

```bash
php artisan vendor:publish --tag=authentication-config
php artisan vendor:publish --tag=authentication-migrations
php artisan migrate
```

Each migration refuses to run over an existing table of the same name, before changing anything, with a
`TableAlreadyExistsException` that names the configuration key renaming its table (`device.table`,
`sign_in.pending_table`, `rate_limits.table`).

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

1. Do not implement `HasDevices` on your identity model.
2. Issue access tokens with `Auth::jwt('api')->issueAccessToken($identity, $principal, null)`.
3. Do not call `$guard->refresh(...)` or the session service. Clients re-authenticate when the access token expires.

`Auth::device()` returns `null` in this mode; the rest of the contextual surface works normally. Bearer requests need
none of the package's tables. A guard that signs in with `attempt()` counts its attempts in the `rate_limits` table (see
[Rate limits](#rate-limits)), so publish and run the migrations for it, or set the guard's `rate_limits.sign_in` to
`null`; the `devices` and `pending_sign_ins` tables then stay empty. See `docs/design/access-only-mode.md`.

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

Routes opt into a boundary via `auth:staff` or `auth:customer` middleware. Every token carries a `grd` claim naming the
guard that issued it, and a guard rejects any token whose `grd` names another guard, so a staff token cannot
authenticate as a customer even when both guards share the package key map and identity model. Separate keys and
audiences, as above, are optional defence in depth on top of that. On refresh, the guard reloads the device's owner
through its own user provider, so the provider's scoping applies and an owner it does not serve is rejected. The device
row stores the owner's primary key and the provider looks identities up by their auth identifier, so refresh requires an
identity model whose auth identifier is its primary key: one that overrides `getAuthIdentifierName()` fails to refresh
with `authenticatable_missing`. Every field in the package `jwt` block is overridable (`keys`, `active_kid`,
`algorithm`, `access_ttl_minutes`, `refresh_idle_ttl_minutes`, `refresh_absolute_ttl_minutes`, `refresh_grace_seconds`,
`leeway_seconds`, `issuer`, `audience`). `keys` and `active_kid` fall back independently: a guard that overrides `keys`
should also set `active_kid` to a kid in its own map. A guard's `jwt` entry must be an array (or `null` for no
overrides). `algorithm` must be a string, and `issuer` and `audience` a string or `null`: a guard that sets either to
`null` or `''` turns that claim check off even when the package value sets one. A value of any other type, in the
guard's block or the package block, fails closed with an `InvalidJwtConfigurationException` naming the key and the
guard, rather than being ignored.

### Token and session lifetimes

Each guard issues access tokens and keeps sessions for these lifetimes, set in the package `jwt` block and overridable
in a guard's `jwt` block. The defaults are 5 minutes for access tokens, and 90 days idle and 180 days absolute for
sessions:

| Key                            | Default | Range        | Env                                               |
|--------------------------------|---------|--------------|---------------------------------------------------|
| `access_ttl_minutes`           | 5       | 1 to 1440    | `AUTHENTICATION_JWT_ACCESS_TTL_MINUTES`           |
| `refresh_idle_ttl_minutes`     | 129600  | 1 to 5256000 | `AUTHENTICATION_JWT_REFRESH_IDLE_TTL_MINUTES`     |
| `refresh_absolute_ttl_minutes` | 259200  | 1 to 5256000 | `AUTHENTICATION_JWT_REFRESH_ABSOLUTE_TTL_MINUTES` |
| `refresh_grace_seconds`        | 30      | 0 to 300     | `AUTHENTICATION_JWT_REFRESH_GRACE_SECONDS`        |
| `leeway_seconds`               | 30      | 0 to 300     | `AUTHENTICATION_JWT_LEEWAY_SECONDS`               |

A session is a device. It ends at its idle deadline unless a refresh moves that deadline forward, and at its absolute
deadline however often it is refreshed: each refresh sets the idle deadline to the idle lifetime from now, never past
the absolute deadline, and never moves the absolute deadline. Tokens mirror the device: a refresh token expires at the
device's idle deadline, and an access token after the access lifetime but never after the device's idle or absolute
deadline. With an idle lifetime shorter than the access lifetime, access tokens therefore expire at the idle deadline,
together with the refresh token, so clients must refresh before their access token expires. A device past either
deadline, or without one, is over everywhere: its access tokens are rejected (with no leeway), it cannot be pinned on
sign-in, it cannot be refreshed (`session_expired`), and no token can be issued for it. Ending a session this way does
not revoke the device.

A guard override that is present and not `null` wins; otherwise the package value applies. Each value must be an integer
or a string of digits (as `env()` returns it) within its range. A value that is missing, malformed, or out of range
fails closed with an `InvalidJwtConfigurationException` naming the key and the guard when the guard or `Auth::jwt()`
service is resolved; the defaults live only in the published config.

### Audiences

An audience is a guard. Each guard decides which sign-in methods may start its sessions and which principal types may
hold them, and can give each principal type its own token and session lifetimes. The defaults live in the package
`audience` block, and a guard overrides any key in an `audience` block of its own:

```php
'guards' => [
    'console' => [
        'driver'   => 'jwt',
        'provider' => 'users',
        'audience' => [
            'methods'         => ['password'],
            'principal_types' => ['staff', 'client_admin'],
        ],
    ],
    'mobile' => [
        'driver'   => 'jwt',
        'provider' => 'users',
        'audience' => [
            'methods'         => ['sso'],
            'principal_types' => ['client_staff'],
        ],
        'jwt' => [
            'by_principal_type' => [
                'client_staff' => ['refresh_absolute_ttl_minutes' => 60 * 24 * 365],
            ],
        ],
    ],
],
```

| Key                           | Default        | Meaning                                                                             |
|-------------------------------|----------------|-------------------------------------------------------------------------------------|
| `methods`                     | `['password']` | The sign-in methods that may start the guard's sessions (a non-empty list of names) |
| `principal_types`             | `null`         | `null` admits any principal; a non-empty list admits only principals of those types |
| `require_verified_identifier` | `false`        | Refuse a sign-in with an identifier the identity has not verified                   |

A principal's type is its own or its tenant's (see [Principal type](#principal-type)); with a list, a principal without
a type is refused. The session layer asks the guard before it issues anything: a sign-in with a method the guard does
not list fails with `method_not_allowed`, and a principal whose type it does not admit with `principal_ineligible`, at
sign-in and again on every refresh, so a valid credential for one audience cannot open or keep a session in another.
With `require_verified_identifier`, a sign-in that used an identifier (an email address for the password method) fails
with `identifier_unverified` unless the identity reports that identifier verified (see
[Identifier verification](#identifier-verification)); sign-ins that used no identifier, such as SSO through `start()`,
and refreshes are not gated, since the external provider or the existing session vouches for them.

A guard key that is present wins, `null` included, so a guard can admit any principal although the package default
lists types; a guard `audience` entry of `null` means no overrides. Nothing falls back to a literal: a key missing from
both blocks, a value of the wrong shape, an empty list, or a key the policy does not know fails closed with an
`InvalidArgumentException` naming the guard and the key the first time the guard's policy is used. The policy is
`Contracts\AudiencePolicy`, bound to `Audience\GuardAudiencePolicy`; bind your own implementation to decide
differently. A policy of your own decides the session's deadlines through `lifetimes()`, while an access token's
lifetime still comes from the guard's `jwt.by_principal_type` configuration (capped at the session's end). See
`docs/design/audience-policy.md` for every point where the policy is enforced.

Lifetimes per principal type are set per guard only, in `jwt.by_principal_type.<type>`, with any of
`access_ttl_minutes`, `refresh_idle_ttl_minutes` and `refresh_absolute_ttl_minutes` (same types and ranges as the
guard's own). Each key a type leaves out, or sets to `null`, is the guard's value; the refresh grace window and the
leeway stay the guard's, because a refresh judges them before it knows the principal. Any other key, or a map that is
not keyed by type names, fails closed with an `InvalidJwtConfigurationException` when the guard is resolved. Access
tokens expire after their principal type's access lifetime, `Auth::jwt('api')->lifetimesFor($principal)` returns the
lifetimes for a principal, and a guard without per-type lifetimes never reads a principal's type for them.

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

The published `authentication.php` config controls the device model, table, and how often a device's last use is
written:

```php
'device' => [
    'model'                      => SineMacula\Laravel\Authentication\Models\Device::class,
    'table'                      => 'devices',
    'last_used_throttle_seconds' => 60,
],
```

A device is one signed-in session. The shipped migration creates these columns:

| Column                                                 | Holds                                                  |
|--------------------------------------------------------|--------------------------------------------------------|
| `id`                                                   | UUID v7 primary key, carried in every token as `did`   |
| `authenticatable_type`, `authenticatable_id`           | The owning identity (required)                         |
| `principal_type`, `principal_id`                       | The principal the session acts as (any key type)       |
| `guard`, `sign_in_method`                              | The guard and sign-in method that created it           |
| `client_name`, `platform`                              | What the client calls itself (`Work laptop`, `macOS`)  |
| `created_ip`, `created_user_agent`                     | The client at sign-in                                  |
| `last_used_at`, `last_used_ip`, `last_used_user_agent` | The client at the last use                             |
| `refresh_key`, `previous_refresh_key`                  | Digests of the current and previous rotation ids       |
| `refresh_rotated_at`                                   | When the current rotation id replaced the previous one |
| `idle_expires_at`, `absolute_expires_at`               | End without a refresh, and end regardless (required)   |
| `revoked_at`, `revoked_reason`                         | When and why the session was revoked                   |

Every timestamp is a `datetime` stored to the whole second, so a deadline years ahead fits on every engine (MySQL's
`timestamp` type ends in January 2038), and the table is indexed on the owner, the principal, the guard, both
deadlines, and the revocation time. Every authentication that binds a persisted device (a bearer request or a refresh)
records its last use: the time, the request's IP address (only when it is a valid IPv4 or IPv6 address), and its user
agent (without NUL bytes, as valid UTF-8, at most 512 characters), at most once per `last_used_throttle_seconds` (0
records every use).

Like Laravel's own `datetime` columns, these times are stored as wall-clock times in the application timezone, without
an offset, so keep `app.timezone` at Laravel's default of `UTC` or another zone without daylight saving. In a zone with
daylight saving, both passes through the hour that repeats when the clocks go back store the same value, and
`ActsAsDevice` reads it as the first pass, whichever pass PHP itself would pick. A time stored in the second pass
therefore reads back early by the length of the shift (an hour in most zones): a deadline stored there ends the session
that much early (and when the idle lifetime is no longer than the shift, the refresh that sets it fails with an
`InvalidArgumentException` and changes nothing), and a rotation stored there leaves the previous refresh token no grace
window, so a retry of it counts as a replay and revokes the device. A last use recorded there reads early too, so for
the rest of that pass a `last_used_throttle_seconds` shorter than the shift records every use. The ambiguity can end a
session early, fail a refresh, or record extra uses; it never extends a session or a grace window.

The shipped `Device` model uses UUID v7 primary keys, a polymorphic `authenticatable` relation, and a polymorphic
`principal()` relation over the principal columns. Only `client_name` and `platform` are mass assignable; set the owner,
the request-derived columns, and the session state with `forceFill()`. Both refresh digests are hidden from `toArray()`
and `toJson()` by `ActsAsDevice`, under whatever column names the model uses. The session service writes
every column when it creates a device (see [Signing in](#signing-in-the-session-service)); `getGuard()` and
`getSignInMethod()` read the guard and method it recorded. The bearer path and refresh honour a device only for the
guard it records, and refresh only while that guard still allows the method it records, so a device written outside the
session service must record both.

Subclass the model or swap `device.model` entirely - custom models must implement the `EloquentDevice` contract. A
device's identifier is always its primary key: tokens carry it in `did`, and the bearer path and refresh find the device
by primary key, whatever the key column is called. Other column names come from the contract's accessors
(`getRefreshKeyName()`, `getRevokedAtName()`, and so on); the shipped migration creates the default names, so a model
that renames a column needs its own migration.

A device with `revoked_at` set is rejected everywhere: an access token naming it fails exactly as if the device were
missing, and its refresh token fails with `device_revoked`. Revoking a device therefore ends its session at once rather
than when its access tokens expire. Revocation marks the row, with the time and a reason in `revoked_reason`, and clears
both refresh digests; it never deletes the row. Today the package revokes a device only when the refresh exchange
detects a replay; revoking is idempotent, so a device that is already revoked keeps its first revocation, and
`DeviceRevoked` reports each revocation the package makes. The package has no revocation call for applications yet: to
revoke a device yourself, set its `revoked_at` (and `revoked_reason`), which takes effect at once but fires no event. A
device whose session has ended, past its idle or absolute deadline, is rejected the same way on the bearer path and as a
sign-in pin, and fails refresh with `session_expired` (see [Token and session lifetimes](#token-and-session-lifetimes)).
`ActsAsDevice` reads any stored timestamp as a value, with or without a `datetime` cast on the column, and throws a
`LogicException` when the device was loaded without one of its refresh or revocation state columns (both digests, the
rotation time, both deadlines, and the revocation time), for example through a `devices()` relation or a global scope
that selects other columns, so a partial select is reported instead of being read as a device that is not revoked or has
no deadline.

Before a token's `did` is looked up, it is checked against the device model's primary key: a UUID for `HasUuids`, a
ULID for `HasUlids`, an integer for an integer key, and a non-empty string otherwise. A `did` that cannot be a key is
treated as an unknown device without a query. A model whose key has some other format implements `ValidatesDeviceKey`
to describe it. Database errors are never read as an unknown device: they propagate as server errors.

### Sign-in

```php
'sign_in' => [
    'password_identifier' => 'email',
    'pending_table'       => 'pending_sign_ins',
    'pending_ttl_seconds' => 300,
],
```

The password sign-in method looks identities up by `password_identifier`, which is also the identifier type the
attempt limits count and a guard that requires verified identifiers checks. It must be a lower-case column name (a
letter, then letters, digits, or underscores) that does not contain `password`; anything else fails with an
`InvalidArgumentException` when a password sign-in runs. A sign-in that needs a further factor waits in `pending_table`
(on the device model's connection) for at most `pending_ttl_seconds`, an integer from 30 to 3600 (see
[Additional factors](#additional-factors)).

### Rate limits

Sign-in and refresh are limited per identifier and per IP address, counted in the database on the write connection, so
the limits hold across servers and do not depend on a cache. Publish the migration with the others
(`authentication-migrations` creates `rate_limits`), then set limits in the package `rate_limits` block or a guard's
own `rate_limits` block:

```php
'guards' => [
    'console' => [
        'driver'      => 'jwt',
        'provider'    => 'users',
        'rate_limits' => [
            'sign_in' => [
                'per_identifier' => ['max' => 3, 'decay_seconds' => 900],
                'per_ip'         => null,
            ],
        ],
    ],
],
```

| Flow      | Scope            | Default            | Counts                                                     |
|-----------|------------------|--------------------|------------------------------------------------------------|
| `sign_in` | `per_identifier` | 5 per 300 seconds  | Every attempt for the identifier; a success is given back  |
| `sign_in` | `per_ip`         | 50 per 300 seconds | Every attempt from the IP address; a success is given back |
| `refresh` | `per_identifier` | 10 per 60 seconds  | Failed refreshes of the device                             |
| `refresh` | `per_ip`         | 100 per 60 seconds | Failed refreshes from the IP address                       |

Each limit is `['max' => ..., 'decay_seconds' => ...]`: at most `max` attempts (at least 1) in each window of
`decay_seconds` (1 to 86400), or `null` for none. Windows are aligned to the clock (a 300-second window runs from
12:00:00 to 12:05:00), so, as with any fixed window, up to twice `max` attempts can fall within `decay_seconds` across a
boundary. A guard scope that is present wins, `null` included; a flow set to `null` turns both of its limits off; a
scope the guard leaves out is the package's. A malformed limit, a missing one, or an unknown key fails closed with an
`InvalidArgumentException` naming the guard and the key.

A sign-in guesses a secret, so it reserves its slots before the method runs: a refused sign-in fails with
`rate_limited` and a wait in seconds, without checking the password, and a successful one gives its own slots back.
Earlier failures are not forgiven: they count until their window ends, so concurrent attempts can never exceed `max`.
When the IP address's limit is full, the slot just taken for the identifier is given back. A refresh cannot guess a
secret (its tokens are signed and its rotation ids random), so it counts only its failures, per device and per IP
address, and a successful refresh costs one read. A refresh refused for its failures answers `429` with a
`Retry-After` header.

Identifiers are counted in their canonical form, through the normaliser of their type when one is registered (see
[Identifiers](#identifiers)), so every casing of an address shares one counter, and otherwise trimmed and lower-cased.
The table holds only SHA-256 digests of the guard, flow, scope and identifier or IP address, never either in clear.
Every change to a count is one statement the database applies atomically. A database error propagates as a server error:
a limiter that cannot count lets nothing through. The counters live on `rate_limits.connection` (the default connection
when `null`): counts written on the same connection as a transaction you open around a sign-in are rolled back with it,
so point it at a connection of its own if you wrap sign-ins in transactions you may roll back.

Ended windows stay in the table until they are pruned, as do pending sign-ins that were never completed (see
[Additional factors](#additional-factors)). Both models live outside your application's `app/Models`, so name them when
you schedule Laravel's pruning command:

```php
use Illuminate\Support\Facades\Schedule;
use SineMacula\Laravel\Authentication\Models\PendingSignIn;
use SineMacula\Laravel\Authentication\Models\RateLimit;

Schedule::command('model:prune', ['--model' => [PendingSignIn::class, RateLimit::class]])->hourly();
```

### Credential validation timing

`attempt()` and `validate()` wrap credential checks in a constant-time `Timebox` to prevent timing side-channels:

```php
'timebox' => [
    'credentials_microseconds' => 400000,
],
```

Must exceed the worst-case hasher cost.

### Read replicas

Every read that decides authentication - the identity, the principal and the tenant it acts within, and the device with
its refresh digests, rotation time, session deadlines and revocation state - goes to the write connection, even when the
database connection has `read` and `write` hosts. A replica can lag behind a revocation, a deactivation, a refresh
rotation, or an ended session, and a lookup it served could admit a credential the primary has already rejected.

The package pins the lookups it makes, including the relations the identity, principal and device models eager-load
(`$with`), on whichever connection those relations live (a tenant in a separate landlord database, say). Code you plug
in carries the same obligation:

- a custom `IdentityProvider`, a `ModelProvider` subclass that builds its own query, or a custom `PrincipalResolver`
  must read from the write connection, including the relations its results eager-load;
- `resolveDefaultPrincipal()`, `resolveHintedPrincipal()`, `devices()` and, when `ModelProvider` checks a password,
  `getAuthPassword()` already run inside `WriteConnection::during()` for the identity, `getTenant()` for the principal,
  `isActive()` for the model it belongs to, and a device's refresh state, session deadlines and revocation for the
  device: every model read made there, on any connection, goes to that connection's writer, and so does a query-builder
  read on the model's own connection. A query-builder or `DB` read on another connection, or made by a principal or
  identity that is not an Eloquent model, must pin itself.

`WriteConnection` does both. `query()` routes a single query; Eloquent fetches eager-loaded relations with separate
queries that it does not reach, so run a lookup whose results load relations inside `during()`, which pins every
connection a model resolves while its callback runs, plus the given model's own connection:

```php
use SineMacula\Laravel\Authentication\Database\WriteConnection;

// A query you build: route it to the write PDO, scoped to the identity.
$membership = WriteConnection::query(Membership::query()->where('identity_id', $identity->getKey()))->find($hint);

// Model reads on any connection, eager loads included, plus the identity's connection.
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
use SineMacula\Laravel\Authentication\Concerns\ProvidesType;

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

    public function identity(): BelongsTo
    {
        return $this->belongsTo(AppIdentity::class, 'identity_id');
    }

    public function tenant(): BelongsTo
    {
        return $this->belongsTo(AppTenant::class);
    }
}

class AppTenant extends Model implements HasType, TenantContract
{
    use ActsAsTenant, ProvidesType;
}
```

With that shape:

- `Auth::identity()` returns the `AppIdentity`.
- `Auth::principal()` returns the `AppMembership` - resolved via `principals()->find($pid)` from the token's `pid`
  (every access token carries one), or via `resolveDefaultPrincipal()` on sign-in and on a refresh token issued
  without a principal.
- `Auth::tenant()` returns the `AppTenant` the membership belongs to.
- `Auth::type()` returns the tenant's type string (see [Principal type](#principal-type)).
- A membership whose `is_active` is `false` cannot sign in, refresh, or authenticate a request (see
  [Active-state enforcement](#active-state-enforcement)).

Implement `ResolvesHintedPrincipal` on the identity to replace the default `principals()->find($hint)` lookup
with a custom query - for example, joining the tenant row in one SQL so `Auth::tenant()` does not lazy-load.

For domain-specific resolution (subdomain, header, session claim), implement `PrincipalResolver` and bind it in
a service provider. A hint can come from a caller pinning a principal on `attempt()`, so a custom resolver or
`resolveHintedPrincipal()` must look the hint up among the identity's own principals only, never by the hint alone:

```php
$this->app->singleton(PrincipalResolver::class, MyTenantScopedResolver::class);
```

### Principal type

A principal can carry a type: a categorical label such as `staff`, `client_admin`, `client_staff`, or `service` that
access tokens carry, `Auth::type()` returns, and a guard can key on. Implement `HasType` on the principal, the tenant,
or both, and use the `ProvidesType` trait to read it from a `type` column (override `getTypeAttributeName()` for
another column; a backed enum reads as its value, a unit enum as its name):

```php
use SineMacula\Laravel\Authentication\Concerns\ProvidesType;
use SineMacula\Laravel\Authentication\Contracts\HasType;

class AppMembership extends Model implements CanBeActive, HasType, PrincipalContract
{
    use ActsAsPrincipal, ProvidesActiveState, ProvidesType;
}
```

The principal's type is its own when it implements `HasType` and reports one, otherwise the type of the tenant it acts
within when that tenant implements `HasType`, otherwise `null`; an empty string counts as no type, so a membership with
an empty `type` column takes its tenant's. The tenant is loaded only when the principal has no type of its own, and both
are read from the write connection. `Audience\PrincipalType::of($principal)` reads it the same way outside a request.

Every access token carries the type in its `pty` claim when there is one (`typ` stays the token type, `access` or
`refresh`); refresh tokens never carry it, so a refreshed access token carries the type the principal has at the
refresh. Nothing checks `pty` on a bearer request: `Auth::type()` reads the bound principal as it is now, not the claim,
and a type change shows on the next request. The claim is for consumers of the token, such as a gateway or a client
choosing which screens to show, not a credential.

### Identifiers

Designate the attributes people sign in with as identifiers, so each is stored and looked up in one normal form. Cast
the attribute with `NormalisedIdentifier`, naming its identifier type:

```php
use SineMacula\Laravel\Authentication\Casts\NormalisedIdentifier;

class AppUser extends User implements Identity, Principal
{
    use Authenticatable, ActsAsPrincipal;

    protected function casts(): array
    {
        return [
            'email' => NormalisedIdentifier::using('email'),
        ];
    }
}
```

Setting the attribute stores what the type's normaliser returns: the `email` normaliser trims surrounding whitespace
and lower-cases the whole address, so `Ben@Example.com` is stored as `ben@example.com`. A value it rejects (blank, or
not valid UTF-8) throws an `InvalidArgumentException` naming the attribute but never the value; `null` stays `null`.
Reading returns the stored value unchanged. The `model` provider normalises a credential for a designated attribute
the same way before it looks the identity up (`attempt(['email' => ' BEN@example.com', ...])` finds `ben@example.com`),
element by element for an array, and a value the normaliser rejects finds nobody without a query. Closures and
attributes that are not designated are applied as given.

Normalisers are registered by identifier type in the published config, as container abstracts resolving to a
`Contracts\IdentifierNormaliser`. A type is a lower-case letter followed by lower-case letters, digits and
underscores:

```php
'identifiers' => [
    'normalisers' => [
        'email'         => SineMacula\Laravel\Authentication\Identifiers\EmailNormaliser::class,
        'member_number' => App\Auth\MemberNumberNormaliser::class,
    ],
],
```

A normaliser must be deterministic and idempotent (normalising a normal form returns it unchanged), and return `null`
for a value that cannot be an identifier of its type. A malformed map, or an abstract that does not resolve to a
normaliser, fails closed with an `InvalidArgumentException`.

Make the identifier unique on its normalised value, with a unique index on the stored column:

1. Normalise the rows you already have before adding the index, in a migration or a one-off command that saves each
   identity again (the cast normalises on set), or with SQL equivalent to the normaliser (`UPDATE users SET email =
   LOWER(TRIM(email))` for email, checking first for addresses that collide once normalised).
2. Then add the unique index on the column itself, not on an expression, so it holds whoever writes the row.

Why both engines need it: PostgreSQL compares strings case-sensitively, so without normalisation `Ben@x.com` and
`ben@x.com` are two accounts and a lookup with the other casing finds neither; MySQL's default `_ci` collations
compare them as equal, so lookups match but a unique index rejects the second address only by accident of the
collation, and `LOWER()` and the collation can disagree on non-ASCII letters. Storing the normal form makes both
behave the same, and lets the index mean what the application means.

A successful password sign-in rehashes the password when the hasher reports the stored hash outdated (a new algorithm or
cost) and Laravel's `hashing.rehash_on_login` is on; never on bearer requests, refresh, `validate()`, or a session
started with `start()` or `complete()`, which check no password. The `model` provider writes the new hash with one
conditional update, `WHERE <key> = :id AND <password> = :checkedHash`, so a password changed between the check and the
rehash is never overwritten with a hash of the old one; the write fires no model events and leaves `updated_at` alone. A
hash that does not come from the model's own password attribute (a `getAuthPassword()` that reads another table) is not
rehashed by the provider.

### Identifier verification

Implement `HasVerifiableIdentifiers` on the identity to let the package verify its identifiers and gate sign-in on
them. The `ProvidesIdentifierVerification` trait reads the identifier of a type from the column named after it
(`email`) and its verification time from `<type>_verified_at` (`email_verified_at`, as Laravel's own verification
uses), and throws a `LogicException` for an identity loaded without either column:

```php
use SineMacula\Laravel\Authentication\Concerns\ProvidesIdentifierVerification;
use SineMacula\Laravel\Authentication\Contracts\HasVerifiableIdentifiers;

class AppUser extends User implements HasVerifiableIdentifiers, Identity, Principal
{
    use ActsAsPrincipal, Authenticatable, ProvidesIdentifierVerification;
}
```

A type is a lower-case letter followed by lower-case letters, digits and underscores (`email`, `phone`). Recording a
verification is one conditional update, `WHERE <key> = :id AND <type> = :identifier AND <type>_verified_at IS NULL`, so
a proof for one address can never verify another, even when the address changes while the proof is checked; it fires
no model events and leaves `updated_at` alone. When an identifier changes, clear its `<type>_verified_at` with it.

Verify by signed link with `Verification\VerificationLinks`. The application owns the route, the message and its
delivery:

```php
use Illuminate\Http\Request;
use SineMacula\Laravel\Authentication\Verification\VerificationLinks;

// Send it: a signed link to your route, valid for `verification.link_ttl_minutes` (60 by default).
$url = app(VerificationLinks::class)->create('api', $user, 'email', 'verification.verify');

// Your route: verified, already_verified, mismatch, or null for an invalid link.
Route::get('/verify-email', function (Request $request, VerificationLinks $links) {
    return match ($links->consume($request)?->value) {
        'verified', 'already_verified' => response()->noContent(),
        default                        => abort(403),
    };
})->name('verification.verify');
```

A link is signed for its purpose (`verify_identifier`), its JWT guard, its identity, the identifier type and a SHA-256
digest of the identifier in its normal form; it never carries the identifier itself. It stops working when it expires
or when the identifier changes, and it verifies nothing for a guard that is not a JWT guard or an identity that cannot
verify identifiers. `create()` takes the route's own parameters (but not the reserved `guard`, `identity`, `type`,
`purpose`, `hash`, `expires` or `signature`) and an optional lifetime in minutes (1 to 10080, a week, like the
configured one). Consuming a link loads the identity through the guard's identity provider from the write connection
and verifies the identifier; it never signs anyone in. Following it again reports `already_verified`.

`Verification\IdentifierVerifier::verify($guard, $identity, $type, $identifier, $client)` is the step a link (or, later,
a one-time code) ends in: the proven identifier must be the identity's current one, compared in its normal form. Only
the call that records the verification dispatches `Events\IdentifierVerified` (guard, identity, type and client, never
the identifier), once the record is committed on the identity's connection; a rolled-back verification is never
reported.

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

To read the flag from a column instead, implement `CanBeActive` and use the `ProvidesActiveState` trait, as
`AppMembership` does above. The trait alone is never consulted: only models that implement `CanBeActive` are checked,
and PHPStan reports a class that uses the trait without the interface. It reads `is_active` (override
`getActiveAttributeName()` to use another column) and throws a `LogicException` when the model was loaded without that
column, so a partial select is reported instead of being read as either active or inactive.

A tenant opts in the same way. When the tenant a principal acts within implements `CanBeActive` and reports inactive,
every principal in it is rejected on the same paths (refresh fails with `tenant_inactive`):

```php
class AppTenant extends Model implements CanBeActive, HasType, TenantContract
{
    use ActsAsTenant, ProvidesActiveState, ProvidesType;
}
```

A principal whose opted-in tenant cannot be loaded is rejected on the same paths: when the principal's `BelongsTo`
tenant key names a `CanBeActive` tenant that is deleted, soft-deleted, or hidden by a scope,
`ActsAsPrincipal::getTenant()` throws a `TenantUnavailableException`, which the check reads as an inactive tenant,
instead of returning `null` as if the principal acted within no tenant. The default model a `withDefault()` relation
returns for such a missing row counts as missing too, rather than as a present tenant. A `Principal` that implements
`getTenant()` itself should do the same. As with `ProvidesActiveState`, a principal loaded without the key of an
opted-in tenant (a partial select) throws a `LogicException` rather than being read as acting within no tenant. A
polymorphic (`MorphTo`) tenant relation names its model through its type column, so a principal loaded without that
column throws a `LogicException` as well, and one whose type is empty while its key is set is rejected like a tenant
that cannot be loaded. A tenant that does not implement `CanBeActive` is never checked, so a missing one reads as no
tenant, and a `tenant` relation to a model that is not a `Tenant` is not a tenant at all.

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
Auth::type();           // string|null     - the principal's type, else its tenant's
```

Like `Auth::user()` and `Auth::id()`, each accessor authenticates the request on first access, so they also work on
routes without `auth` middleware. A request is authenticated at most once, whether its token is accepted or rejected,
and after `Auth::logout()` it stays signed out for the rest of the request. `Auth::tenant()` and `Auth::type()` throw a
`TenantUnavailableException` for a principal whose opted-in tenant cannot be loaded, and a `LogicException` for one
loaded without that tenant's key (or polymorphic type). Sign-in, bearer requests and refresh reject such a principal, so
that only happens for one bound through `login()`, `setUser()` or `setPrincipal()`, which skip the activity check.

`setUser()`, which Laravel's `actingAs()` uses, replaces the whole context: it binds the identity with its default
principal (and no device), and throws an `InvalidArgumentException` when the identity has none. Use the guard's
`login($identity, $principal, $device)` to bind a specific principal or a device. `actingAs()` binds the guard for code
that runs in the test itself; it does not yet carry through an HTTP request the test sends through the kernel, such as
`$this->actingAs($user, 'api')->getJson('/me')`, because each request rebinds the guard to its own request and starts
the context over.

Sign in with credentials through `attempt()`, optionally pinning the principal and device to act as:

```php
$guard->attempt(['email' => $email, 'password' => $password], $membership, $device);
```

`attempt()` signs in through the password sign-in method and the guard's sign-in policies: the audience policy must
allow the `password` method for the guard, the attempt takes a slot from the sign-in limits of the identifier (the
`sign_in.password_identifier` key of the credentials, whatever else they hold) and of the request's IP address, and only
then are the credentials checked, inside the timebox. After the password, the identity, the principal and its tenant
must be active, the pins must hold, the audience policy must admit the identity as that principal, the password is
rehashed when its stored hash no longer matches the hasher's algorithm or cost (unless Laravel's
`hashing.rehash_on_login` is off), and the additional-factor policy must not ask for a further factor: `attempt()`
cannot hand out a pending sign-in, so a guard whose policy requires a factor fails it with `additional_factor_required`.
A successful attempt gives its slots back; a failed one keeps them. Every failure fires Laravel's `Failed` and then
`SignInFailed` with a reason (see [Events](#events)). `validate()` checks only the credentials and never rehashes, as
with Laravel's own guards; neither does a bearer request or a refresh, which never see a password.

The pins are verified rather than trusted, because they often come from request input: the principal must be one the
resolver returns for that identifier on the authenticated identity (same class, same identifier) and must belong to that
identity (its `getIdentity()` is the authenticated identity), and the device must be one of the identity's own devices
(through `HasDevices`, looked up the way a bearer `did` is), not revoked, and with a session that has not ended. A pin
that fails either check fails the attempt. `login()` is the trusted entry point: it binds exactly what it is given, so
only pass it a principal and device you have already proven belong to the identity. `setPrincipal()` and `setDevice()`
are trusted binds in the same way: they do not check ownership, activity, revocation or session deadlines, so a
principal or device taken from request input (a header that switches the acting membership, say) must be verified
first, as `attempt()` verifies its pins.

Pinning a principal therefore needs a principal that can report its owner. With `ActsAsPrincipal`, declare the
`identity` relation, as `AppMembership` does above (or override `getIdentityRelationName()`). The owner is read again
from the principal's own stored key, even when Eloquent's strict mode prevents lazy loading, ignoring any identity
relation the resolver already set, and a principal whose owner cannot be read (no relation, or an owner that has been
deleted) fails the attempt.

### Signing in: the session service

Each JWT guard has a session service, `Auth::sessions('api')` (or `Auth::guard('api')->sessions()`), that signs in,
creates the device, issues the first token pair and binds the guard in one call:

```php
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;

$result = Auth::sessions('api')->signIn(
    'password',
    $request->only('email', 'password'),
    SignInContext::fromRequest(
        $request,
        clientName: $request->input('client_name'),
        platform: $request->input('platform'),
        refreshToken: $request->input('refresh_token'),
    ),
);

if ($result->isFailed()) {
    // Failed and SignInFailed were dispatched; $result->reason says why, and
    // $result->retryAfter how long to wait when it is rate_limited.
    abort(401);
}

if ($result->requiresFactor()) {
    // No session yet: hand the client the pending token to complete it with.
    return ['pending_token' => $result->pending->token];
}

return [
    'access_token'  => $result->session->tokens->accessToken,
    'refresh_token' => $result->session->tokens->refreshToken,
];
```

`signIn()` runs, in order: Laravel's `Attempting` (with only the identifier the method names, never the input); the
guard's audience policy must allow the method (`method_not_allowed`, nothing counted); the identifier and the client's
IP address must have attempts left (`rate_limited`, with the wait); then, inside the credential timebox, the method must
verify the input, the identity, the principal (the one the context names, verified like an `attempt()` pin, or the
resolver's default) and its tenant must be active, and the audience policy must admit the identity as that principal; a
password is rehashed when its hash is outdated; and the additional-factor policy is asked whether a further factor is
required (see [Additional factors](#additional-factors)). Failures are results, not exceptions: Laravel's `Failed` and
then `SignInFailed` report them, with the reason. An unknown method name, a misconfigured model and database errors
still throw. A successful sign-in gives its attempt slots back.

`start($identity, $principal, $method, $context)` begins a session for an identity something else verified, such as an
external identity provider. The identity is reloaded through the guard's provider (`identity_unknown` when that does not
return the very same identity), the method must be allowed, the identity, principal and tenant are checked and
admitted, and the additional-factor policy is asked, so a sign-in from outside cannot skip a required factor. No
attempt limit or timebox applies. The principal is given as the argument or on the context, not both.

A session starts on a new device that records the identity, the principal, the guard, the method, the client's name and
platform (from the context, cleaned as the user agent is), the client's IP address and user agent at creation and as its
last use, the digest of the first rotation id, and both deadlines from the guard's lifetimes for the principal. The
device is written and the pair issued in one transaction on the device's connection, so a failure while issuing leaves
no device behind. The guard is then bound (`Validated`, `Login`, `Authenticated`, `PrincipalAssigned` and
`DeviceAuthenticated` fire at once), and `DeviceCreated` and `SignedIn` are dispatched once the device is committed on
its own connection: at once outside a transaction, after your transaction commits inside one, and never when it is
rolled back. Do not roll back around a sign-in: the guard stays bound. A listener that throws on a bind event fails the
call after the device was committed, so the pair is lost; keep those listeners from throwing or queue them.

A client that signs in again with its current refresh token in the context continues on the same device instead of
creating another: the token proves the client holds that session, even when it has expired. It counts only when it is
the device's current refresh token, validly signed for this guard, for a device the identity owns, of this guard, for
the same principal, and not revoked; anything else simply creates a new device. Continuing a device starts a new
session on it: a new rotation id (the earlier refresh tokens of the device become replays, see
[Refresh token replay](#refresh-token-replay)), both deadlines from now, the method and the client's description
recorded, and `DeviceCreated` not dispatched. If the device changes before it can be continued (a parallel refresh,
say), the sign-in is reconsidered without it and starts on a new device. The additional-factor policy is told of the
device the client proved, so a factor policy can trust a device it has seen a factor on.

#### Additional factors

The additional-factor policy (`Contracts\AdditionalFactorPolicy`, by default one that never asks for a factor; an MFA
package or the application binds its own) is asked about every admitted sign-in, from `signIn()` and from `start()`,
with the guard, identity, principal, tenant, method, client, and the device the client proved it holds, if any. When it
requires a further factor, no session starts: the result's `pending` is a `PendingFactor` whose `token` completes the
sign-in once, for this guard, within `sign_in.pending_ttl_seconds` (five minutes by default). The token is opaque (not a
JWT), so it authenticates no request and refreshes nothing; only the digest of its secret is stored, in
`pending_sign_ins`. The attempt slots are given back as for a session.

The code that verifies the factor looks the pending sign-in up, verifies the factor for its identity and principal, and
only then completes it. Possessing the token proves nothing about the factor: `complete()` is a trusted entry point,
like `start()`.

```php
$sessions = Auth::sessions('api');
$pending  = $sessions->pending($request->input('pending_token'));

if ($pending === null || ! $factors->verify($pending->identity, $pending->principal, $request->input('code'))) {
    abort(401);
}

$result = $sessions->complete($request->input('pending_token'));
```

`pending()` never uses the pending sign-in up, and returns `null` for any token that does not name a live one of this
guard whose identity and principal still resolve as it recorded them. `complete()` uses it up whatever the outcome,
with a delete only one completion can make, checks it again in the same transaction (the method still allowed, the
identity, principal and tenant active, and the audience policy admitting them with the identifier type the sign-in
used; the factor policy is not asked again), and starts the session on the device the client proved it holds when that
is unchanged, otherwise on a new one, recording the client the sign-in came from. A token that completes nothing fails
as `pending_invalid`, without saying why.

Pending sign-ins that were never completed expire; schedule their pruning with the rate limit counters' (see
[Rate limits](#rate-limits)).

`attempt()` and `login()` remain for code that binds the guard itself; neither creates a device. Access-only guards
(identities without `HasDevices`) keep issuing access tokens with `Auth::jwt('api')->issueAccessToken()`.

Exchange the refresh token through the guard:

```php
$guard = auth()->guard('api');

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

A refresh is held to the guard as well as the token. A device the row records for another guard (or for none) fails
with `device_guard_mismatch` and is left alone, even for a token that would be a replay, and a bearer token naming it
is rejected as if the device were missing. The guard's audience policy is asked again on every refresh: the method that
started the session (the device's `sign_in_method`) must still be one the guard allows (`method_not_allowed`; a device
that records none fails too), and the policy must still admit the owner as the principal (`principal_ineligible`).
Neither revokes the device, so the session refreshes again once the policy allows it. Each rotation moves the idle
deadline by the idle lifetime the policy gives the principal's type.

Failed refreshes are counted against the token's device and the request's IP address by the bound `AttemptLimiter`;
successful ones are not. Once either count is full, `refresh()` dispatches `RefreshFailed` (`rate_limited`) and
`Failed` without looking the device up, then throws Laravel's `ThrottleRequestsException`, which renders as a 429 with
`Retry-After`.

A failure before the stored rotation commits, such as an error while signing the new pair, leaves the presented refresh
token valid for a retry. After the commit, `refresh()` binds the new context and dispatches `Refreshed`; an exception
from a listener on those events loses the new pair, but a retry with the presented token inside the grace window still
gets the current credential (see [Refresh token replay](#refresh-token-replay)). Keep those listeners from throwing or
queue them, so a retry is never needed.

### Refresh token replay

Refresh tokens stay signed JWTs, and each one carries the device's rotation id, which the device stores only as a
SHA-256 digest. Every successful refresh rotates the device to the next rotation id and remembers the one it replaced,
with the time of the rotation. A validly signed refresh token for a live device then carries one of three ids:

- the current one: the refresh rotates it and returns a new pair;
- the one the current one replaced, presented within `refresh_grace_seconds` (30 by default) of that rotation: the
  refresh returns a new pair carrying the device's current rotation id, and writes no rotation state, so a client that
  lost the response, or a second tab that refreshed at the same moment, keeps its session, and retries never extend the
  window;
- any other id: the token was rotated before, so it has been replayed, perhaps stolen. The device is revoked at once
  (`revoked_at` and `revoked_reason = rotation_reuse`, both digests cleared), `DeviceRevoked` and `RefreshFailed`
  (`rotation_reuse`) are dispatched, and every token of the device stops working, access tokens included.

Only the immediately previous id is honoured: after two quick refreshes, a delayed retry of the first token is a
replay. With `refresh_grace_seconds` set to 0 the previous id is a replay too. A device that holds no refresh
credential cannot tell a replay from anything else, so its tokens fail with `refresh_key_missing` and the device is
left alone. When a parallel refresh changes the device between this refresh's read and its write, the row is judged
again as it now is: usually that makes this refresh a grace retry; a deadline that moved in between fails it with
`rotation_conflict`, without revoking anything, and the client can simply retry.

A refresh token for a rotation id the device never held is a replay too, and that includes a token from an earlier
session of the same device. A client that signs in again on its device (see
[Signing in](#signing-in-the-session-service)) starts a new session with a new rotation id, so the refresh tokens of
its earlier session become replays: presenting one while the new session is live revokes the device. The client that
proved the device with its current refresh token has just received the replacement; a client that loses the sign-in
response and retries with the old token proves nothing, gets a new device, and leaves the old one to be revoked if
that token is ever presented again. Restarting the deadlines cannot revive an access token: its `exp` was capped at
the end of the session it was issued for. Do not give an existing device a new `refresh_key` yourself; let the session
service do it.

Every refresh judges the device at one moment, taken when it starts, so application servers should keep synchronised
clocks. The package opens no transaction. If you call `refresh()` inside your own transaction, do not roll it back after
a failed refresh: a rollback also undoes a replay revocation. `DeviceRevoked` is dispatched once the revocation is
committed on the device's own connection: at once outside a transaction, so before `RefreshFailed` and `Failed`, and
after the commit inside one, so after them; a rolled-back revocation is never reported, and a transaction on another
connection neither delays nor withdraws it. The transaction that Laravel's `DatabaseTransactions` and `RefreshDatabase`
testing traits wrap around each test does not count either, so a test sees `DeviceRevoked` when the application would.
Under PostgreSQL's REPEATABLE READ, a parallel refresh that commits first makes this one fail with a serialization
error, which surfaces as a server error for you to retry.

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
has expired: a refresh token never outlives its session, so at most the absolute session lifetime after the switch.
Removing a kid immediately rejects every token signed under it, which is also how to revoke a compromised key.

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
| `SineMacula\...\Events\DeviceRevoked`       | The package revoked a device (a replay); carries reason   |
| `SineMacula\...\Events\SignInFailed`        | A sign-in failed (carries machine-readable reason)        |
| `SineMacula\...\Events\DeviceCreated`       | The session service created a device, once committed      |
| `SineMacula\...\Events\SignedIn`            | The session service started a session, once committed     |
| `SineMacula\...\Events\IdentifierVerified`  | An identifier was verified (after commit); carries type   |

The credentials on `Attempting` and `Failed` never include a password: every key whose name contains `password`
(case-insensitive), such as `password`, `current_password`, or `password_confirmation`, is removed before the event is
dispatched, and the identifier is kept for throttling and audit listeners. To remove more keys, list name fragments in
the published config:

```php
'events' => [
    'redacted_credential_keys' => ['secret', 'code'],
],
```

`SignedIn` reports a real sign-in, with the method that proved who signed in, unlike Laravel's `Login` and
`Authenticated`, which also fire when a refresh or a bearer request binds the guard; a refresh dispatches `Refreshed`
instead. `DeviceCreated` precedes it for a new device. Both carry the guard, identity, principal, tenant, device,
method and client (IP address and user agent), and never a token.

`SignInFailed` follows Laravel's `Failed` on every failed sign-in. It carries the guard, the method, the request's
client (IP address and user agent), the identifier as given, the identity only once its sign-in method verified it (a
wrong password or an unknown identifier carries none), the principal and tenant once resolved, the wait for
`rate_limited`, and a `SignInFailureReason`. It never carries a password, code or token:

| Reason                       | Meaning                                                            |
|------------------------------|--------------------------------------------------------------------|
| `invalid_credentials`        | The sign-in method did not accept the input                        |
| `method_not_allowed`         | The guard does not allow the sign-in method                        |
| `rate_limited`               | The identifier or IP address used up its attempts for now          |
| `identity_unknown`           | The guard's identity provider does not return the identity         |
| `identity_inactive`          | The identity reported inactive                                     |
| `principal_unresolved`       | No principal could be resolved for the identity                    |
| `principal_mismatch`         | The requested principal does not belong to the identity            |
| `device_mismatch`            | The requested device is not one of the identity's live devices     |
| `principal_inactive`         | The principal reported inactive                                    |
| `tenant_inactive`            | The principal's tenant inactive, or opted in and missing           |
| `principal_ineligible`       | The guard does not accept principals of the principal's type       |
| `identifier_unverified`      | The guard requires a verified identifier and it is not             |
| `additional_factor_required` | A further factor is required, which only `signIn()` can ask        |
| `pending_invalid`            | The pending sign-in is unknown, expired, used, or not this guard's |

`RefreshFailed` carries a `RefreshFailureReason` backed enum for SIEM attribution, and the wait in `retryAfter` for
`rate_limited`:

| Reason                    | Meaning                                              |
|---------------------------|------------------------------------------------------|
| `token_invalid`           | Decode, expiry, missing claim, typ, guard, iss, aud  |
| `rate_limited`            | Too many failed refreshes for the device or IP       |
| `device_unknown`          | Device id is not a device key or names no device     |
| `device_guard_mismatch`   | Device is another guard's (or none's); not revoked   |
| `rotation_reuse`          | Rotated token replayed; device revoked               |
| `rotation_conflict`       | Device changed during the refresh; retry             |
| `refresh_key_missing`     | Device holds no refresh credential                   |
| `device_revoked`          | Device row marked revoked                            |
| `session_expired`         | Device's idle or absolute deadline reached, or unset |
| `authenticatable_missing` | Guard's provider did not return the device owner     |
| `identity_inactive`       | Resolved identity reported inactive                  |
| `principal_unresolved`    | Principal resolver returned null                     |
| `principal_mismatch`      | Resolved principal does not match refresh token hint |
| `principal_inactive`      | Resolved principal reported inactive                 |
| `tenant_inactive`         | Principal's tenant inactive, or opted in and missing |
| `method_not_allowed`      | Guard no longer allows the method of the session     |
| `principal_ineligible`    | Audience policy no longer admits the principal       |

## Extensibility

Concrete classes in this package are `final` except `AuthManager` (the package's subclass of Laravel's manager), the
shipped `Models\Device` model, and the extension points noted below. Extension is through **composition and DI**, not
inheritance:

| Extension point                   | How                                                                        |
|-----------------------------------|----------------------------------------------------------------------------|
| Custom identity / principal model | Implement `Identity`, `Principal` (and optional capability interfaces)     |
| Custom device model               | Implement `EloquentDevice`, use the `ActsAsDevice` trait                   |
| Custom principal resolution       | Implement `PrincipalResolver`, bind per-guard or globally                  |
| Custom identity retrieval         | Subclass `ModelProvider` (non-final)                                       |
| Custom `auth` middleware          | Subclass `Http\Middleware\Authenticate` (non-final)                        |
| Guard-scoped JWT settings         | Override `jwt.*` keys in `auth.guards.<name>.jwt`                          |
| Sign-in methods                   | Implement `SignInMethod`, register it with `SignInMethodManager::extend()` |
| Additional factors (MFA)          | Bind your own `AdditionalFactorPolicy` in the container                    |
| Audience decisions                | Implement `AudiencePolicy` and bind it in the container                    |
| Attempt limits                    | Implement `AttemptLimiter` and bind it in the container                    |
| Identifier normal forms           | Implement `IdentifierNormaliser`, register it by type in the config        |

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
