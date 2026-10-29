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

## Contents

- [Core Concept](#core-concept)
- [Features](#features)
- [Installation](#installation)
  - [Guards and providers](#guards-and-providers)
  - [Unauthenticated requests](#unauthenticated-requests)
  - [Access-only mode (no devices, no refresh)](#access-only-mode-no-devices-no-refresh)
- [Identity Models](#identity-models)
  - [2D adoption (identity is the principal)](#2d-adoption-identity-is-the-principal)
  - [3D adoption (separate identity, principal, tenant)](#3d-adoption-separate-identity-principal-tenant)
  - [Principal type](#principal-type)
  - [Identifiers](#identifiers)
  - [Identifier verification](#identifier-verification)
  - [Active-state enforcement](#active-state-enforcement)
- [Signing in](#signing-in)
  - [The `Auth` facade and `attempt()`](#the-auth-facade-and-attempt)
  - [Signing in: the session service](#signing-in-the-session-service)
  - [Signing in with a one-time code](#signing-in-with-a-one-time-code)
  - [Using passkeys](#using-passkeys)
  - [Writing a sign-in method](#writing-a-sign-in-method)
  - [Additional factors](#additional-factors)
  - [Choosing a principal](#choosing-a-principal)
  - [Enumeration resistance](#enumeration-resistance)
- [Refreshing](#refreshing)
  - [Refresh token cookie](#refresh-token-cookie)
  - [Refresh token replay](#refresh-token-replay)
- [Switching principal](#switching-principal)
- [Signing out and revoking sessions](#signing-out-and-revoking-sessions)
  - [Listing devices](#listing-devices)
  - [Revoking on security changes](#revoking-on-security-changes)
  - [Access tokens without a device](#access-tokens-without-a-device)
  - [Revocation reasons](#revocation-reasons)
- [Passwords](#passwords)
  - [Password policy](#password-policy)
  - [Setting a password](#setting-a-password)
  - [Password reset](#password-reset)
- [Changing identifiers](#changing-identifiers)
- [Machine credentials](#machine-credentials)
  - [Non-human identities](#non-human-identities)
  - [Credential scopes](#credential-scopes)
  - [API keys](#api-keys)
  - [Client credentials](#client-credentials)
- [Failure outcomes](#failure-outcomes)
- [Suite integration](#suite-integration)
  - [Further factors (`laravel-mfa`)](#further-factors-laravel-mfa)
  - [Authorization (`laravel-authorization`)](#authorization-laravel-authorization)
  - [Single sign-on (`laravel-sso`)](#single-sign-on-laravel-sso)
  - [Audit (`laravel-audit-log`)](#audit-laravel-audit-log)
- [Configuration](#configuration)
  - [Per-guard JWT configuration](#per-guard-jwt-configuration)
  - [Token and session lifetimes](#token-and-session-lifetimes)
  - [Audiences](#audiences)
  - [Per-guard principal resolvers](#per-guard-principal-resolvers)
  - [Device](#device)
  - [Sign-in](#sign-in)
  - [One-time codes](#one-time-codes)
  - [Passkeys](#passkeys)
  - [Rate limits](#rate-limits)
  - [API key settings](#api-key-settings)
  - [Credential validation timing](#credential-validation-timing)
- [Events](#events)
- [Operations](#operations)
  - [Read replicas](#read-replicas)
  - [Long-running processes](#long-running-processes)
  - [Key Rotation](#key-rotation)
  - [Pruning](#pruning)
  - [Checking the configuration](#checking-the-configuration)
- [Testing](#testing)
  - [Acting as an identity, principal or device](#acting-as-an-identity-principal-or-device)
  - [Fakes](#fakes)
  - [Running the package's tests](#running-the-packages-tests)
- [Extensibility](#extensibility)
- [Design Notes](#design-notes)
- [Requirements](#requirements)
- [Changelog](#changelog)
- [Contributing](#contributing)
- [Security](#security)
- [License](#license)

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
- **Pluggable sign-in methods** behind one `SignInMethod` contract (password, one-time code and passkey methods ship;
  SSO and others register on the `SignInMethodManager`), checked against each guard's audience policy and attempt
  limits, with an additional-factor seam whose default never asks for one.
- **One-time codes**: passwordless sign-in with a numeric code sent to a verified phone number (`phone_code`) or email
  address (`email_code`), and identifier verification by code, through a sender contract the application binds (no
  provider ships; a fake for tests does). Codes are stored as keyed hashes bound to their purpose, guard and
  identifier, work once, expire, lock after a few wrong guesses, resend after a cooldown, and are delivered by a queued
  job, so a request for a code looks the same whether or not anyone has the identifier.
- **Passkeys** (WebAuthn): usernameless sign-in with discoverable, user-verified credentials as the `passkey` method,
  registration through single-use challenges held in the database, a relying party per guard, a sign counter rule that
  refuses a cloned authenticator, `PasskeyAdded` / `PasskeyUsed` / `PasskeyRemoved` events, and a factor ceremony
  through which a further-factor package verifies the same passkeys.
- **Contextual accessors** on the standard `Auth` facade: `identity()`, `principal()`, `device()`, `tenant()`,
  `type()`, and `scopes()`, the ceiling a machine credential grants.
- **Non-human identities**: an identity marked `MachineIdentity` has no password, no interactive sign-in, no session
  and no device refresh, refused at every path that verifies something; it authenticates only with a credential bound to
  one principal in one tenant.
- **API keys for non-human identities**: an `api_key` guard that authenticates `Authorization: Bearer <key>` with one
  indexed lookup on the write connection and no password hashing; keys shown once, stored as a SHA-256 digest, bound
  to one guard, one principal and its tenant, with scopes, optional expiry, throttled last use, rotation with a bounded
  overlap, immediate revocation and lifecycle events.
- **OAuth 2.0 client credentials** (RFC 6749 section 4.4): an API key, as a client id and secret, exchanged for a
  short-lived access token of a `jwt` guard, with no device and no refresh, answered in RFC 6749's shapes; the token
  carries its key and scopes and is held to its key on every request, so revoking the key ends it at once.
- **Credential scopes for the suite**: the package carries a credential's scopes and never interprets them; they are
  opaque RFC 6749 scope tokens, a ceiling an authorization package intersects with the principal's permissions, held at
  issue to an optional `ScopeRegistry` (default: accept any).
- **Hardened JWT pipeline**: HMAC-only signing (`HS256`, `HS384`, `HS512`), every token bound to the guard that
  issued it, strict `iss` / `aud` / `typ` / `exp` / leeway enforcement, required claims per token type (`exp`, `iat`,
  `jti`, `typ`, and `grd` on both, plus `sub` and `pid` on access tokens and `did` on refresh tokens), the principal's
  type in `pty` on access tokens when it has one, and fail-closed behaviour on empty or short keys, unsupported
  algorithms, type confusion, tokens from another guard, missing claims, and `pid` / `did` mismatches.
- **Refresh-token rotation with replay detection**: constant-time digest verification, atomic per-device rotation, a
  short grace window for lost responses and parallel refreshes, revocation of the device when a rotated refresh token is
  replayed, and machine-readable `AuthenticationFailed` and `DeviceRevoked` events for SIEM attribution. Every refresh
  is held to the device's guard and the guard's audience policy, and failed refreshes are counted, with a 429 past the
  limit.
- **One refresh token transport per guard**: the token is read from the cookie, the body or a header as the guard
  allows, a request carrying it more than once is refused, and the result says where it came from. Browsers keep it in
  an `HttpOnly`, `Secure`, `SameSite=Strict` cookie the API sets and clears on its own responses, read only with an
  allowed origin and a custom header; nothing is stored on the server.
- **Kid-based key rotation** - signing keys are always a `kid → secret` map; every token carries the kid that signed
  it, so keys rotate without signing anyone out.
- **A session service** per JWT guard, `Auth::sessions('api')`, that signs in through a method or starts a session for
  an externally verified identity, creates the device (or continues the one a client proves it holds), issues the first
  token pair, binds the guard, and reports `DeviceCreated` and `SignedIn` once committed.
- **Device records**, one per signed-in session: owner, principal, guard, sign-in method and client metadata, the last
  use (time, IP address, user agent, debounced), the session's idle and absolute deadlines, and revocation with a
  reason. Refresh digests are hidden from serialisation. An identity's active devices list as safe, paginated
  summaries with the current device marked, and ended devices are pruned with `model:prune`.
- **Signing out and revoking sessions**: `logout()` revokes the session's device, so its tokens stop at once; the
  session service signs an identity out everywhere, optionally keeping the current device, revokes one of its devices or
  every session of a principal, and ends the affected sessions when a password changes or is reset, a factor is removed,
  or an identity, principal or tenant is deactivated, with optional listeners for identities and principals. Access
  tokens issued without a device end at a "tokens valid after" time the identity or principal records.
- **Choosing and switching principal**: a sign-in that names no principal, for an identity that has no default
  principal, waits for it to choose one of those it may act as, and a session switches to another principal on its
  device, proven by its refresh token, ending the previous principal's access tokens at once.
- **First-class events** - Laravel's standard `Attempting` / `Validated` / `Authenticated` / `Login` / `Failed` /
  `Logout` alongside custom `PrincipalAssigned` / `DeviceAuthenticated` / `SignedIn` / `DeviceCreated` /
  `AdditionalFactorRequired` / `PrincipalChoiceRequired` / `PrincipalSwitched` / `Refreshed` / `DeviceRevoked` /
  `SignedOutEverywhere` / `IdentifierVerified` / `PasswordSet` / `IdentifierChangeRequested` / `IdentifierChanged` /
  `PasskeyAdded` / `PasskeyUsed` / `PasskeyRemoved` / `ApiKeyIssued` / `ApiKeyRotated` / `ApiKeyRevoked` /
  `ClientCredentialsGranted` and one `AuthenticationFailed` with a reason, each
  carrying the same context (guard, client, identity, principal, tenant, device, method, and the credential and its
  scopes where one is used) and never a secret. A bearer request is not a sign-in: it fires only `Authenticated` and the
  contextual events.
- **Audiences per guard**: the sign-in methods and principal types each guard admits, and token and session lifetimes
  per principal type.
- **Normalised identifiers**: designated identifiers stored and looked up in one form (trimmed, lower-cased email and
  E.164 phone numbers by default), and a password rehash that never overwrites a concurrent change.
- **Rate limits in the database**: sign-in, code requests, password resets, identifier changes and refresh limited per
  identifier and per IP address; passkey sign-in options and client credentials exchanges per IP address (a client id
  only when you opt in); all counted atomically on the write connection without a cache.
- **Identifier verification**: signed verification links or one-time codes bound to their purpose and identifier, and
  an opt-in, per-guard requirement that sign-in identifiers be verified.
- **Passwords**: a configurable policy built on Laravel's `Password` rule, with a breached-password seam (no service
  ships) that fails closed, or open if you choose, when the service is down; one call that sets a password for a
  registration, a change or a reset, applying the policy, hashing, storing and ending the sessions the flow calls for;
  and reset by emailed link or one-time code, the same for an identifier no one holds, limited, and spent in one
  transaction with the new password and the revocation.
- **Changing identifiers**: an email address or phone number replaced only once the new one is proven by a code or a
  signed link, after a recent sign-in, reauthentication or confirmed factor, unique on its normalised value (the
  application's index decides a race), invalidating the proofs it outdates, and telling the old identifier through a
  notifier the application binds.
- **A configuration check**, `php artisan authentication:check`, that resolves every `jwt` and `api_key` guard's
  settings and fails the deploy on a problem, listing all of them.
- **Safe in long-running processes**: nothing one request or queued job binds reaches the next under Octane or a queue
  worker.
- **Testing helpers**: act as an identity, a principal or a device's session on a guard, through the requests a test
  sends, assert the context a guard has bound, and fake the delivery and checker contracts (see [Testing](#testing)).
- **Pluggable everywhere**: identity model, device model, principal resolver, sign-in methods, additional-factor
  policy, audience policy, attempt limiter, identifier normalisers, one-time code sender, breached-password checker,
  reset link sender, identifier change notifier, scope registry, table names.

## Installation

```bash
composer require sinemacula/laravel-authentication
```

Publish the config and the migrations (the `devices`, `pending_sign_ins`, `rate_limits`, `one_time_codes`, `passkeys`,
`passkey_challenges`, `api_keys` and `identifier_changes` tables), then migrate:

```bash
php artisan vendor:publish --tag=authentication-config
php artisan vendor:publish --tag=authentication-migrations
php artisan migrate
```

Each migration refuses to run over an existing table of the same name, before changing anything, with a
`TableAlreadyExistsException` that names the configuration key renaming its table (`device.table`,
`sign_in.pending_table`, `rate_limits.table`, `codes.table`, `passkeys.table`, `passkeys.challenges_table`,
`api_keys.table`, `identifier_changes.table`).

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

Non-human identities authenticate with API keys on a guard of the `api_key` driver, whose audience lists `api_key`
(see [API keys](#api-keys)):

```php
'guards' => [
    'machine' => [
        'driver'   => 'api_key',
        'provider' => 'clients',
        'audience' => ['methods' => ['api_key']],
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

### Access-only mode (no devices, no refresh)

Device tracking and refresh are opt-in. For simple backends or short-lived session flows (non-human clients use
[machine credentials](#machine-credentials) instead):

1. Do not implement `HasDevices` on your identity model.
2. Issue access tokens with `Auth::jwt('api')->issueAccessToken($identity, $principal, null)`.
3. Do not call `$guard->refresh(...)` or start sessions through the session service (`signIn()`, `start()`), which
   throws a `LogicException` for an identity without `HasDevices`. Clients re-authenticate when the access token
   expires. To end an identity's tokens before they expire, give the identity (or the principal) a "tokens valid after"
   time (below): the session service's revocation methods (`revokeDevices()`, `signOutEverywhere()`,
   `passwordChanged()` and the other security changes, `principalDeactivated()`, `revokePrincipalDevices()`) move it,
   and need none of the package's tables for such an identity, or call `invalidateTokensIssuedBefore()` yourself.

`Auth::device()` returns `null` in this mode; the rest of the contextual surface works normally. Such a token has no
device to revoke, so an identity or principal model that implements `HasTokensValidAfter` ends them instead: a token
whose `iat` is at or before either one's `getTokensValidAfter()` is rejected (`issued_before_cutoff`), counted in whole
seconds, so a token issued in the cutoff's own second is rejected too. Tokens that name a device are not held to it.
Bearer requests need none of the package's tables. A guard that signs in with `attempt()` counts its attempts in the
`rate_limits` table (see [Rate limits](#rate-limits)), so publish and run the migrations for it, or set the guard's
`rate_limits.sign_in` to `null`; the `devices` and `pending_sign_ins` tables then stay empty. See
`docs/design/access-only-mode.md`.

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

The relation must query the configured device model, or another model that implements `EloquentDevice`: the bearer
path, sign-in pins, the device list and revocations all read it, and a relation over any other model throws a
`LogicException`.

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
an empty `type` column takes its tenant's. `ProvidesType` throws a `LogicException` for a model loaded without its type
column (a resolver that selects only some columns, say), rather than reading it as untyped and handing it its tenant's
type. The tenant is loaded only when the principal has no type of its own, and both are read from the write
connection. `Audience\PrincipalType::of($principal)` reads it the same way outside a request.

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
        'phone'         => SineMacula\Laravel\Authentication\Identifiers\E164PhoneNormaliser::class,
        'member_number' => App\Auth\MemberNumberNormaliser::class,
    ],
],
```

A normaliser must be deterministic and idempotent (normalising a normal form returns it unchanged), and return `null`
for a value that cannot be an identifier of its type. A malformed map, or an abstract that does not resolve to a
normaliser, fails closed with an `InvalidArgumentException`.

The shipped `phone` normaliser accepts only a number already in E.164 form (`+`, a country code, at most 15 digits in
all, surrounding whitespace removed) and refuses anything else: spaces, dashes, brackets, a national format or a leading
`00`. It does not parse numbers, since turning what a person types into E.164 depends on their country and on numbering
plans that change. To take mobile or free-form numbers, install `giggsey/libphonenumber-for-php` (the package suggests
it but does not require it) and bind a normaliser of your own under `phone`:

```php
use libphonenumber\NumberParseException;
use libphonenumber\PhoneNumberFormat;
use libphonenumber\PhoneNumberType;
use libphonenumber\PhoneNumberUtil;
use SineMacula\Laravel\Authentication\Contracts\IdentifierNormaliser;

final readonly class MobileNumberNormaliser implements IdentifierNormaliser
{
    public function normalise(string $identifier): ?string
    {
        $numbers = PhoneNumberUtil::getInstance();

        try {
            $number = $numbers->parse($identifier, 'GB'); // the region a number without `+` belongs to
        } catch (NumberParseException) {
            return null;
        }

        $mobile = in_array($numbers->getNumberType($number), [PhoneNumberType::MOBILE, PhoneNumberType::FIXED_LINE_OR_MOBILE], true);

        return $numbers->isValidNumber($number) && $mobile ? $numbers->format($number, PhoneNumberFormat::E164) : null;
    }
}
```

```php
'identifiers' => ['normalisers' => ['email' => EmailNormaliser::class, 'phone' => App\Auth\MobileNumberNormaliser::class]],
```

It must return E.164 (so normalising its own output returns it unchanged), and existing rows must be normalised to it
before a unique index is added, as below.

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
verification reads the identity's row again under a lock (`SELECT ... FOR UPDATE`) and sets `<type>_verified_at` only
when the row's identifier is the proven one byte for byte and still unverified, all in one transaction, so a proof for
one address can never verify another, even when the address changes while the proof is checked to one the column's
collation counts as equal (`Ben@` or `bén@` for `ben@`); it fires no model events and leaves `updated_at` alone. When
an identifier changes, clear its `<type>_verified_at` with it, or change it through
[`Auth::identifierChanges()`](#changing-identifiers), which records the proven one as verified.

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
digest of the identifier in its normal form; it never carries the identifier itself. It stops working when it expires or
when the identifier changes, and it verifies nothing for a guard that is not a JWT guard or an identity that cannot
verify identifiers. `create()` takes the route's own parameters (but not the reserved `guard`, `identity`, `type`,
`purpose`, `hash`, `expires` or `signature`, which the route's path may not use as placeholders either) and an optional
lifetime in minutes (1 to 10080, a week, like the configured one). Consuming a link loads the identity through the
guard's identity provider from the write connection and verifies the identifier; it never signs anyone in. Following it
again reports `already_verified`.

Verify by one-time code with `Auth::codes($guard)`: `sendVerification()` sends a code to the identity's current
identifier of the type, and `verify()` checks it and records the verification:

```php
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Verification\Enums\IdentifierVerification;

// Send it: a code to the signed-in identity's phone number, delivered by your OneTimeCodeSender.
$request = Auth::codes('mobile')->sendVerification(Auth::identity(), 'phone');   // sent, rate_limited or identifier_invalid

// Check it: verified, already_verified or mismatch, or the FailureReason why not.
$result = Auth::codes('mobile')->verify(Auth::identity(), 'phone', $input['code']);

abort_unless(in_array($result, [IdentifierVerification::VERIFIED, IdentifierVerification::ALREADY_VERIFIED], true), 422);
```

A verification code is bound to its purpose, its guard, its identity and the identifier in its normal form, so it
verifies nothing else, signs no one in, and stops working when the identifier changes: `sendVerification()` and
`verify()` read the identifier from the identity they are given (load it from the write connection, as the guard does),
and the delivery job reads the identity again from the write connection and sends nothing once its identifier is no
longer the one the code is bound to. Requests are held to the `code_request` limits and the resend cooldown, and the
code to the same lifetime, attempts and single use as a sign-in code (see [One-time codes](#one-time-codes)). A refused
check returns `invalid_credentials`, `code_expired` or `code_exhausted` as it is (the caller already holds the
identity), and reports it with `AuthenticationFailed` on the `identifier_verification` flow. A right code whose
identifier changed after the identity you passed was loaded is used up and answers `mismatch`, as a link does: nothing
is recorded or reported, and the identity can request a code for its new identifier. An identity with no
identifier of the type, or one its normaliser rejects, is `identifier_invalid`; an identity that cannot verify
identifiers throws a `LogicException`, and a machine identity, which has none to verify, an `InvalidArgumentException`.

`Verification\IdentifierVerifier::verify($guard, $identity, $type, $identifier, $client)` is the step a link or a
one-time code ends in: the proven identifier must be the identity's current one, compared in its normal form. Only
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
`getTenant()` itself should do the same, and give the exception the tenant's class, the name of the attribute its key
refers to and that key (`new TenantUnavailableException($message, Team::class, 'id', $this->team_id)`), as
`ActsAsPrincipal` does, so `tenantDeactivated()` recognises the deleted tenant it names. As with `ProvidesActiveState`,
a principal loaded without the key of an opted-in tenant (a partial select) throws a `LogicException` rather than being
read as acting within no tenant. A polymorphic (`MorphTo`) tenant relation names its model through its type column, so a
principal loaded without that column throws a `LogicException` as well, and one whose type is empty while its key is set
is rejected like a tenant that cannot be loaded. A tenant that does not implement `CanBeActive` is never checked, so a
missing one reads as no tenant, and a `tenant` relation to a model that is not a `Tenant` is not a tenant at all.

Checking the tenant reads `$principal->getTenant()` on every request, so eager-load the tenant in your principal
resolver (or `ResolvesHintedPrincipal`) to avoid a lazy load per request.

## Signing in

A guard binds an identity, the principal it acts as and, for a session, the device it lives on. The `Auth` facade
reads what is bound; `attempt()` signs in with a password and binds the guard without a session; the session service
(`Auth::sessions()`) signs in through any sign-in method (a password, a one-time code, a passkey, or one you register
for SSO and the like) or starts a session for an identity something else verified, creates the device and issues the
first token pair. A sign-in can wait for a further factor or for the identity to choose its principal before the session
starts. Every refusal is a result, never an exception, and is reported with `AuthenticationFailed` (see
[Failure outcomes](#failure-outcomes)).

### The `Auth` facade and `attempt()`

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
Auth::scopes();         // list<string>|null - the credential's scope ceiling (null: no credential limits the request)
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
that runs in the test itself only: a request the test sends through the HTTP kernel, such as
`$this->actingAs($user, 'api')->getJson('/me')`, rebinds the guard to its own request and starts the context over. In
tests, act through `InteractsWithAuthenticationContext` instead (see [Testing](#testing)), whose context survives those
requests.

Sign in with credentials through `attempt()`, optionally pinning the principal and device to act as:

```php
$guard->attempt(['email' => $email, 'password' => $password], $membership, $device);
```

`attempt()` signs in through the password sign-in method and the guard's sign-in policies: the audience policy must
allow the `password` method for the guard, the attempt takes a slot from the sign-in limits of the identifier (the
guard's `sign_in.password_identifier` key of the credentials, whatever else they hold) and of the request's IP address,
and only then are the credentials checked, inside the timebox. The identifier key may hold a string, a `Stringable`, an
integer (a numeric column's value, as a JSON body sends it; it is counted as its string form) or a query closure, or be
left out; anything else (a list of addresses, a float, a boolean, `null`) fails as `invalid_credentials` before any
lookup, so request input passed straight through cannot reach accounts the identifier's limit does not count.
`signIn('password', ...)` takes the same strings, `Stringable`s and integers, and refuses anything else as
`invalid_credentials` without a lookup.
The password check itself is counted against the account it is made for (see [Rate limits](#rate-limits)). After the
password, the identity, the principal and its tenant
must be active, the pins must hold, the audience policy must admit the identity as that principal, the password is
rehashed when its stored hash no longer matches the hasher's algorithm or cost (unless Laravel's
`hashing.rehash_on_login` is off), and the additional-factor policy must not ask for a further factor: `attempt()`
cannot hand out a pending sign-in, so a guard whose policy requires a factor fails it with `additional_factor_required`.
A successful attempt gives its slots back; a failed one keeps them. Every failure fires Laravel's `Failed` and then
`AuthenticationFailed` with a reason (see [Events](#events)). `validate()` checks only the credentials and never
rehashes, as with Laravel's own guards; neither does a bearer request or a refresh, which never see a password.

The pins are verified rather than trusted, because they often come from request input: the principal must be one the
resolver returns for that identifier on the authenticated identity (same class, same identifier) and must belong to that
identity (its `getIdentity()` is the authenticated identity), and the device must be one of the identity's own devices
(through `HasDevices`, looked up the way a bearer `did` is), of this guard (a device of another guard, or of none,
counts as missing), not revoked, with a session that has not ended, and acting as the principal being bound. A pin that
fails either check fails the attempt. `login()` is the trusted entry point: it binds exactly what it is given, so only
pass it a principal and device you have already proven belong to the identity. `setPrincipal()` and `setDevice()` are
trusted binds in the same way: they do not check ownership, activity, revocation or session deadlines, so a principal or
device taken from request input (a header that switches the acting membership, say) must be verified first, as
`attempt()` verifies its pins.

Pinning a principal therefore needs a principal that can report its owner. With `ActsAsPrincipal`, declare the
`identity` relation, as `AppMembership` does above (or override `getIdentityRelationName()`). The owner is read again
from the principal's own stored key, even when Eloquent's strict mode prevents lazy loading, ignoring any identity
relation the resolver already set, and a principal whose owner cannot be read (no relation, or an owner that has been
deleted) fails the attempt.

### Signing in: the session service

Each JWT guard has a session service, `Auth::sessions('api')` (or `Auth::guard('api')->sessions()`), that signs in,
creates the device, issues the first token pair and binds the guard in one call:

```php
use Illuminate\Http\Exceptions\ThrottleRequestsException;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;

// Validating first answers malformed input (a missing field, a list where a
// string belongs) with a 422 rather than a TypeError.
$input = $request->validate([
    'email'         => ['required', 'string'],
    'password'      => ['required', 'string'],
    'client_name'   => ['nullable', 'string'],
    'platform'      => ['nullable', 'string'],
    'refresh_token' => ['nullable', 'string'],
]);

$result = Auth::sessions('api')->signIn(
    'password',
    ['email' => $input['email'], 'password' => $input['password']],
    SignInContext::fromRequest(
        $request,
        clientName: $input['client_name'] ?? null,
        platform: $input['platform'] ?? null,
        refreshToken: $input['refresh_token'] ?? null,
    ),
);

if ($result->isFailed()) {
    // Failed and AuthenticationFailed were dispatched; $result->reason says why.
    if ($result->reason === FailureReason::RATE_LIMITED) {
        // A 429 with Retry-After, as a refused refresh answers, so clients wait.
        throw new ThrottleRequestsException('Too Many Attempts.', null, ['Retry-After' => $result->retryAfter]);
    }

    abort(401);
}

if ($result->requiresFactor()) {
    // No session yet: hand the client the pending token to complete it with.
    return ['pending_token' => $result->pending->token];
}

if ($result->requiresPrincipal()) {
    // No principal named and none by default: the identity chooses one.
    return [
        'choice_token' => $result->choice->token,
        'principals'   => array_map(fn ($principal) => $principal->getPrincipalIdentifier(), $result->choice->principals),
    ];
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
then `AuthenticationFailed` report them, with the reason. A method name that is not registered (exactly: `Password` is
not `password`), a method that refuses with any reason but `invalid_credentials`, a misconfigured model and database
errors still throw. A successful sign-in gives its attempt slots back.

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
rolled back. Do not roll back around a sign-in: the guard stays bound, and unless `rate_limits.connection` names a
connection of its own the sign-in's attempt counts are rolled back too, so it goes uncounted (see
[Rate limits](#rate-limits)). A listener that throws on a bind event fails the
call after the device was committed, so the pair is lost; keep those listeners from throwing or queue them.

A client that signs in again with its current refresh token in the context continues on the same device instead of
creating another: the token proves the client holds that session, even when it has expired. It counts only when it is
the device's current refresh token, validly signed for this guard, for a device the identity owns, of this guard, for
the same principal, and not revoked; anything else simply creates a new device. Continuing a device starts a new session
on it: a new rotation id (the earlier refresh tokens of the device become replays, see [Refresh token
replay](#refresh-token-replay)), both deadlines from now, the method and the client's description recorded, and
`DeviceCreated` not dispatched. If the device changes before it can be continued (a parallel refresh, say), the sign-in
is reconsidered without it: it starts on a new device, or hands out a pending sign-in when the additional-factor policy
now asks for a further factor without the device's trust. The additional-factor policy is told of the device the client
proved, so a factor policy can trust a device it has seen a factor on.

`attempt()` and `login()` remain for code that binds the guard itself; neither creates a device. A session lives on a
device, so the session service signs in only identities that implement `HasDevices`: for any other identity `signIn()`,
`start()` and `complete()` throw a `LogicException` naming its class, since the access token it would issue names a
device the guard could never find again. Access-only guards (identities without `HasDevices`) sign in with `attempt()`
and issue access tokens with `Auth::jwt('api')->issueAccessToken()`.

### Signing in with a one-time code

The package registers `phone_code`, a numeric code sent to a verified phone number, and `email_code`, the same sent to a
verified email address: either signs in with no password, as a primary method or a fallback. Allow it in the guard's
audience, bind a `OneTimeCodeSender` (see [One-time codes](#one-time-codes)), and give the identity a normalised `phone`
or `email` column with `HasVerifiableIdentifiers` (see [Identifiers](#identifiers) and
[Identifier verification](#identifier-verification)). The input carries the identifier under its type's name (`phone`,
`email`) and the code under `code`:

```php
'mobile' => [
    'driver'   => 'jwt',
    'provider' => 'staff',
    'audience' => ['methods' => ['phone_code']],
],
```

Two routes of your own ask for a code and sign in with it, through `Auth::codes()` and the session service:

```php
use SineMacula\Laravel\Authentication\Codes\Enums\CodeRequestStatus;
use SineMacula\Laravel\Authentication\Facades\Auth;

Route::post('/codes', function (Request $request) {
    $input  = $request->validate(['phone' => ['required', 'string']]);
    $result = Auth::codes('mobile')->send('phone_code', ['phone' => $input['phone']]);

    // The same answer whether or not anyone has the number.
    return match ($result->status) {
        CodeRequestStatus::RATE_LIMITED       => response()->json(['message' => 'Too Many Attempts.'], 429, ['Retry-After' => $result->retryAfter]),
        CodeRequestStatus::IDENTIFIER_INVALID => response()->json(['message' => 'Enter a number in international format.'], 422),
        CodeRequestStatus::METHOD_NOT_ALLOWED => abort(403),
        CodeRequestStatus::SENT               => response()->json(['expires_at' => $result->expiresAt->toIso8601String()], 202),
    };
});

Route::post('/sign-in/code', function (Request $request) {
    $input  = $request->validate(['phone' => ['required', 'string'], 'code' => ['required', 'string']]);
    $result = Auth::sessions('mobile')->signIn('phone_code', ['phone' => $input['phone'], 'code' => $input['code']]);

    abort_unless($result->isSignedIn(), 401);

    return ['access_token' => $result->session->tokens->accessToken, 'refresh_token' => $result->session->tokens->refreshToken];
});
```

An email address is used in its normal form throughout: a code requested for `Ben@Example.com` is sent to, bound to and
signs in with `ben@example.com`, however either step spells it, and the sender's message carries the normal form; an
address the `email` normaliser rejects (blank, or not valid UTF-8) is `identifier_invalid`. Everything below applies to
`email_code` as to `phone_code`, with the address for the number.

A code request does nothing that depends on whether anyone has the number. The guard must allow the method
(`method_not_allowed`), the number must be one the `phone` normaliser accepts (`identifier_invalid`), the number and the
IP address must have code requests left (`rate_limited`, with the wait), and no code may have been sent to the number
within the resend cooldown (`rate_limited`, with the seconds left); then a code is issued, for anyone's number, and its
delivery queued. The job alone finds the recipient, when it runs: the active identity the guard's provider returns for
the number that holds exactly that number, reports it verified and is not a machine identity. For anyone else it sends
nothing and says nothing, so the response, the statements run and the time taken are the same for a number no one has.
"Exactly" is decided by the package, not your database: the identity's own identifier, in its normal form, must be
byte for byte the requested one. A lookup matches whatever the column's collation does, and MySQL's default
`utf8mb4_unicode_ci` ignores accents, so `ben@examplé.com` (another domain, which anyone can register) finds the holder
of `ben@example.com`; such an identity neither receives the code nor signs in with it. Each refusal is reported
with `AuthenticationFailed` on the `code_request` flow (an invalid number as `invalid_credentials`).

Signing in, the method brings the number to its normal form and requires a code of exactly `length` digits
(`invalid_credentials` otherwise, nothing counted), looks the identity up (an identity that does not hold exactly that
number, as above, counts as none), counts the check against the account's limit as the password method does, and checks
the code against the one sent to the number on this guard. It checks it whether or not anyone has the number, so a guess
at a number no one has counts against, and locks, its code exactly as one at a known number does. A wrong code, a code
used before, a code for another guard, purpose or number, and the right code for a number no one has are
`invalid_credentials`; an expired code and one that used up its attempts are refused as `code_expired` and
`code_exhausted`, which only `AuthenticationFailed` says: the result says `invalid_credentials`. The right code for an
identity whose number is not verified is `identifier_unverified` (the code proved the number is held, so this tells a
guesser nothing). Then the session service does the rest, as for a password: activity, the principal, the audience
policy, a further factor and the device, which records `phone_code`. The code's attempts are counted on its row, on the
device model's connection, so a transaction you open there and roll back around a sign-in gives the attempt back; the
sign-in limits on `rate_limits.connection` still count it.

Another identifier type signs in by code once it has a normaliser and a column: register a code method for it, and
allow it.

```php
use SineMacula\Laravel\Authentication\Codes\CodeSignIn;
use SineMacula\Laravel\Authentication\Sessions\SignInMethodManager;

$this->app->make(SignInMethodManager::class)->extend('whatsapp_code', fn ($app) => $app->make(CodeSignIn::class, ['type' => 'whatsapp']));
```

### Using passkeys

Each JWT guard has a passkey service, `Auth::passkeys('api')`, for its relying party (see [Passkeys](#passkeys)
under Configuration). Passkeys are usernameless: the browser offers the passkeys it holds for the relying party, the
user verifies (biometrics, a PIN), and the passkey names its owner. Every ceremony is two calls, options and then the
browser's answer: the options carry a single-use challenge stored in `passkey_challenges`, which the answer must use up
within its lifetime, through the same guard, for the same relying party (and, for a registration or a factor, the same
identity), whatever it then proves. The routes and responses are yours.

Allow the method in each guard's audience (`'methods' => ['password', 'passkey']`). A signed-in identity registers a
passkey:

```php
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Passkeys\PasskeySummary;

// POST /passkeys/options, behind auth:api
$identity = Auth::identity();

return Auth::passkeys('api')->registrationOptions($identity, $identity->email, $identity->name);

// POST /passkeys, behind auth:api
$input = $request->validate([
    'challenge'  => ['required', 'string'],
    'credential' => ['required'],
    'name'       => ['nullable', 'string'],
]);

$outcome = Auth::passkeys('api')->register(
    Auth::identity(),
    $input['challenge'],
    $input['credential'],
    $input['name'] ?? null,
);

return $outcome instanceof PasskeySummary
    ? response()->json($outcome, 201)
    : response()->json(['error' => $outcome->value], 422);
```

The options (`CeremonyOptions`: `challenge`, `options`, `expires_at` as JSON) ask for a discoverable credential with
user verification and no attestation, exclude the identity's passkeys, and hand the browser its options in their
WebAuthn JSON form: pass `options` to `PublicKeyCredential.parseCreationOptionsFromJSON()` and
`navigator.credentials.create()`, and post the credential's `toJSON()` back with the `challenge`. Choose the user name
and display name from the identity's own record, never from the request: the browser shows them. Every passkey an
identity registers for a relying party carries the random user handle its passkeys already had when the options were
handed out, or a new random one when it had none, so registrations whose options were handed out before the first one
completed (on two devices, say) may each get their own; every passkey is checked against its own handle. A handle
carries no personal data and does not depend on `app.key`. `register()` answers a `PasskeySummary`, or a
`PasskeyRegistrationFailure`: `challenge_invalid` (not a live registration challenge of this guard for the identity),
`response_invalid` (malformed, or it does not verify: origin, relying party, user presence and verification, challenge,
algorithm, attestation statement) or `already_registered`. The name is stored cleaned and cut to 255 characters. Under
`attestation: none` a browser may still pass an authenticator's own statement through, so the formats the WebAuthn
library checks on its own (`none`, `packed`, `fido-u2f`, `android-key`, `tpm`, `apple`) are accepted for their internal
consistency, but no certificate chain or metadata is evaluated and every passkey is recorded as unattested. A machine
identity holds no passkey (an `InvalidArgumentException`), and passkeys belong to saved Eloquent identities.

Signing in takes options and then the session service:

```php
// POST /sign-in/passkey/options
return Auth::passkeys('api')->signInOptions();

// POST /sign-in/passkey
$result = Auth::sessions('api')->signIn('passkey', $request->only('challenge', 'credential'));
```

`signInOptions()` names no credential, so the browser offers every passkey it holds for the relying party. Anyone may
ask for them and each request writes a challenge, so each is counted against the client's IP address under the guard's
`passkey_options` limit (see [Rate limits](#rate-limits)); past it, a `ThrottleRequestsException` answers `429` with
`Retry-After`. The `passkey` method uses the challenge up, finds the passkey of the guard's relying party the answer
names, loads its owner through the guard's provider as the very model it records, takes a slot of the owner's account
limit, and verifies the assertion: the origin, the relying party, user presence and verification, the signature, the
challenge, and the user handle the passkey was registered under. The session service then decides the rest, as for any
method (see [Signing in: the session service](#signing-in-the-session-service)): no identifier is named, so only the IP
address is limited before the method runs and the verified-identifier requirement does not apply. A challenge the
answer cannot use fails as `passkey_challenge_invalid`, in the result too, since it says nothing about any account (the
client starts again); every other refusal is `invalid_credentials`.

The sign counter guards against a cloned authenticator. With `s` the count stored and `p` the assertion's: `s = 0` and
`p = 0` is accepted and the count stays 0 (most synced passkeys keep no counter); `p > s` is accepted and the count
becomes `p`, with a compare-and-set on `s`, so of two assertions read against one count only one moves it; anything else
(`p <= s` with `s > 0`) is refused as `passkey_counter_regressed`, which only `AuthenticationFailed` says (the result
says `invalid_credentials`). Nothing is written then, so a clone cannot lock the genuine authenticator out; the owner
can remove the passkey. A passkey removed while one of its sign-ins is in flight is refused the same way, with or
without a counter, so no session starts once the removal is committed. A verified passkey records its count, backup
state and last use and dispatches `PasskeyUsed` whether or not the session service then admits its owner: the passkey
was used.

A further-factor package verifies one of an identity's passkeys through the same checks:

```php
// Allows only the identity's passkeys.
$options = Auth::passkeys('api')->factorOptions($identity);

// null once verified, else the reason.
$reason = Auth::passkeys('api')->verifyFactor($identity, $challenge, $credential);
```

`verifyFactor()` answers `null` once the identity's own passkey verified (with `PasskeyUsed`), and otherwise
`passkey_challenge_invalid`, `invalid_credentials` (malformed, not verified, or not the identity's) or
`passkey_counter_regressed`, which the caller already holding the identity may see. It counts nothing and reports no
failure: the factor's outcome is the further-factor package's to limit and report.

`Auth::passkeys('api')->passkeys($identity)` lists the identity's passkeys for the relying party, oldest first, as
`PasskeySummary` (id, name, transports, AAGUID, backup state, created and last used), never the credential id, public
key, user handle or count. `remove($identity, $passkeyId)` removes the identity's passkey of the relying party and
reports `PasskeyRemoved` once committed; it answers whether this call removed it. Finding, listing and removal hold to
the relying party's exact id and the identity's exact type and key, and every ceremony's challenge to its exact
ceremony, guard, relying party and owner, whatever the column's collation counts as equal (`alice` and `Alice` under
MySQL's default `_ci` collations). Removing a passkey removes a way to sign in, but ends no session unless you register
the optional listener:

```php
use Illuminate\Support\Facades\Event;
use SineMacula\Laravel\Authentication\Events\PasskeyRemoved;
use SineMacula\Laravel\Authentication\Listeners\RevokeDevicesOnPasskeyRemoval;

Event::listen(PasskeyRemoved::class, RevokeDevicesOnPasskeyRemoval::class);
```

It ends every session of the identity with `factor_removed`; to keep the current device signed in, call
`Auth::sessions()->factorRemoved($identity, Auth::device())` yourself instead. See `docs/design/passkeys.md`.

### Writing a sign-in method

A sign-in method verifies input the client sends to your sign-in route and answers with the identity it proves, or why
it does not; the session service does everything else (the audience policy, the limits, activity, the principal, a
further factor, the device and the tokens). Use a method for input the package verifies, such as a password, a code
your application issued, or an identity provider's signed assertion the method checks itself. Use `start()` instead
when something outside the session service has already proven the identity, such as an SSO callback your identity
provider's package handles: `start()` runs the same checks after the proof, but no `Attempting`, attempt limit or
timebox, since nothing is guessed there. A method signed in through `signIn()` gets all three. `start()` refuses the
machine credential kinds (`api_key`, `client_credentials`) as the method with an `InvalidArgumentException`, even when
the guard's audience lists them: they authenticate requests and exchanges, never sessions.

```php
use Illuminate\Contracts\Hashing\Hasher;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\SignInMethod;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Sessions\SignInRequest;

final readonly class BadgeSignIn implements SignInMethod
{
    public function __construct(private Hasher $hasher) {}

    public function identifierType(string $guard): ?string
    {
        return 'badge_number';
    }

    public function identifier(string $guard, array $input): ?string
    {
        return is_string($input['badge_number'] ?? null) ? $input['badge_number'] : null;
    }

    public function authenticate(SignInRequest $request): Identity|FailureReason
    {
        $badge    = $this->identifier($request->guard, $request->input);
        $pin      = $request->input['pin'] ?? null;
        $identity = $badge === null ? null : $request->provider->retrieveByCredentials(['badge_number' => $badge]);

        if (! $identity instanceof Identity || ! is_string($pin) || ! $request->reserveAccountAttempt($identity)) {
            return FailureReason::INVALID_CREDENTIALS;
        }

        return $this->hasher->check($pin, $identity->pin_hash) ? $identity : FailureReason::INVALID_CREDENTIALS;
    }
}
```

`identifierType()` names the identifier the method signs in by: the normaliser its limit counts it through, and the
identifier a guard that requires verified identifiers checks. Return `null` for a method that uses no identifier (an
assertion that names the identity itself): then only the IP address is limited and the verified-identifier requirement
does not apply. `identifier()` returns the identifier as the input gives it, for the limits and the failure events,
never to look anyone up. `authenticate()` returns the identity, or `FailureReason::INVALID_CREDENTIALS` for anything the
input did not prove. A method may also answer `identifier_unverified`, but only once its input proved possession of the
identifier (as a one-time code does), and `code_expired`, `code_exhausted`, `passkey_challenge_invalid` or
`passkey_counter_regressed`; `code_expired`, `code_exhausted` and `passkey_counter_regressed` reach the event only, and
the sign-in's result says `invalid_credentials`. Every other reason is the session service's to give, and a method that
returns one throws a `LogicException` (see [Events](#events)). A method must not bind a guard, issue tokens or write
session state, and must hold no state between calls, since the manager keeps one instance per name for the life of the
process. The credential timebox pads every refused sign-in, the method's own work included, to
`timebox.credentials_microseconds`, so a method may answer an unknown identifier at once, as the example does; keep the
method's worst case under that budget, and only a method whose work can take longer needs to do the same work whether or
not the identifier exists.

A method that looks an identity up and then checks a secret calls `$request->reserveAccountAttempt($identity)` before
checking it, and answers `invalid_credentials` without checking when that returns `false` (the account has used up its
attempts); the session service refuses the sign-in then even if the method returns an identity. A lookup can find one
account by many spellings of its identifier, and through every guard whose provider returns it, so only the account's
own count, held to the most permissive limit among those guards, bounds the guesses at its secret, and at a further
factor its sign-in waits for. Reserve before each secret you check: a method that checks two (a password and a PIN, say)
takes two slots. The slots belong to the sign-in: they are all given back when the session starts, or when its pending
sign-in's completion commits. A completion that your transaction rolls back gives nothing back, since the pending
sign-in it used comes back with the rollback and can be completed again. If giving them back fails after the commit,
the error is reported to your exception handler rather than thrown: the session already stands, and a throw would stop
the commit's later callbacks (another session's events, your own `DB::afterCommit()` work) from running. The slots not
given back stay counted.

To unit-test a method, build its request yourself. `new SignInRequest('kiosk', $provider, $input, $client)` allows every
account check; a fifth argument decides them instead, so `fn (Identity $identity): bool => false` gives you a request
whose accounts have used up their attempts, to test the `invalid_credentials` answer.

Register the method under a lower-case name of its own (a letter, then letters, digits or underscores; `extend()`
refuses anything else, the package's own `password`, `phone_code`, `email_code` and `passkey`, and the machine
credential kinds `api_key` and `client_credentials`; see [Extensibility](#extensibility)), from a service provider, and
allow that exact name in each guard's audience:

```php
use SineMacula\Laravel\Authentication\Sessions\SignInMethodManager;

$this->app->make(SignInMethodManager::class)->extend('badge', fn ($app) => $app->make(BadgeSignIn::class));
```

```php
'kiosk' => [
    'driver'   => 'jwt',
    'provider' => 'staff',
    'audience' => ['methods' => ['badge']],
],
```

```php
$result = Auth::sessions('kiosk')->signIn('badge', $request->only('badge_number', 'pin'));
```

### Additional factors

The additional-factor policy (`Contracts\AdditionalFactorPolicy`, by default one that never asks for a factor; an MFA
package or the application binds its own) is asked about every admitted sign-in, from `signIn()` and from `start()`,
with the guard, identity, principal, tenant, method, client, and the device the client proved it holds, if any. When it
requires a further factor, no session starts: the result's `pending` is a `PendingFactor` whose `token` completes the
sign-in once, for this guard, within `sign_in.pending_ttl_seconds` (five minutes by default). The token is opaque (not a
JWT), so it authenticates no request and refreshes nothing; only the digest of its secret is stored, in
`pending_sign_ins`. The sign-in's attempt slots stay taken while it waits, the one its password check took on the
account included, and are given back only when it completes: a pending sign-in that is discarded or expires leaves them
counted, so each guess at a further factor costs a sign-in attempt. With the password method the guesses are therefore
bounded by the account's own count, whichever spelling of the identifier and whichever guard each sign-in used, held to
the most permissive `per_identifier` limit among the guards that check the account (see [Rate limits](#rate-limits)), so
a further factor can be guessed no more often than the password. A method that does not count the account it checks (see
[Writing a sign-in method](#writing-a-sign-in-method)) bounds them by its identifier's and the IP address's limits only.
A sign-in that `start()` holds for a factor took no slots, since nothing was guessed: the external verifier that proved
the identity bounds how often it can be repeated.

The code that verifies the factor looks the pending sign-in up, verifies the factor for its identity and principal, and
only then completes it. Possessing the token proves nothing about the factor: `complete()` is a trusted entry point,
like `start()`.

```php
['pending_token' => $token, 'code' => $code] = $request->validate([
    'pending_token' => ['required', 'string'],
    'code'          => ['required', 'string'],
]);

$sessions = Auth::sessions('api');
$pending  = $sessions->pending($token);

if ($pending === null) {
    abort(401);
}

if (! $factors->verify($pending->identity, $pending->principal, $code)) {
    // One guess per pending sign-in; another needs a new sign-in, which counts
    // against the sign-in limits.
    $sessions->discard($token);

    abort(401);
}

$result = $sessions->complete($token);
```

Holding a sign-in for a factor is its outcome, so it is reported: `AdditionalFactorRequired` carries the guard,
identity, principal, tenant, the device the client proved (if any), the method, the client and the expiry, never the
token, and is dispatched once the pending sign-in is committed (after your transaction, and never if you roll it back).

`discard()` uses a pending sign-in up without starting a session, whatever has changed about its identity since; call it
when the factor fails, so each pending sign-in allows one guess. It returns whether the token named a live pending
sign-in of this guard and, when it did, reports the failure of the sign-in that waited: Laravel's `Failed` and then
`AuthenticationFailed` with `additional_factor_failed`, the method, the discarding request's client and the identity
(when the guard's provider still returns it; no principal). A token that discards nothing reports nothing.

`pending()` never uses the pending sign-in up, and returns `null` for any token that does not name a live one of this
guard whose identity and principal still resolve as it recorded them. `complete()` uses it up whatever the outcome,
with a delete only one completion can make, checks it again in the same transaction (the method still allowed, the
identity, principal and tenant active, and the audience policy admitting them with the identifier type the sign-in
used; the factor policy is not asked again), and starts the session on the device the client proved it holds when that
is unchanged, otherwise on a new one, which records the client the sign-in came from as its creation and the completing
request's client as its last use. The events of a completion, `AuthenticationFailed` included, carry the completing
request's client. A token that completes nothing fails as `pending_invalid`, without saying why.

Pending sign-ins that were never completed expire; schedule their pruning with the rate limit counters' (see
[Rate limits](#rate-limits)).

### Choosing a principal

A sign-in (`signIn()` or `start()`) that names no principal, for an identity whose resolver has no default principal,
waits for the identity to choose one when it may sign in as any: the result `requiresPrincipal()`, and its `choice` is a
`PrincipalChoice` with a single-use `token`, the guard, the identity, the method, the expiry
(`sign_in.pending_ttl_seconds`, as for a factor) and the `principals` it may choose from. Those are the identity's
`principals()`, read on the write connection, that are active, act within an active tenant (or none), and are admitted
by the guard's audience policy (for an identity that is its own principal, the resolver's default).
`Auth::sessions('api')->principals($identity, $identifierType)` lists them the same way; a switch screen passes the
type of identifier its session's sign-in used, `Auth::guard('api')->device()?->getSignInIdentifierType()`, so it lists
only the targets the audience policy lets that session switch to (without a type, the list ignores the identifier and
may hold targets a switch refuses). An identity with none fails as
`principal_unresolved`, as before. The choice itself, and every later look-up of it, is admitted with the identifier
type the sign-in used, as a sign-in naming a principal would be, so a principal your audience policy refuses to that
identifier is neither offered nor listed, and a guard with `require_verified_identifier` offers no choice, and lists no
principal, to an identity whose identifier is unverified: the sign-in fails as `identifier_unverified` with nothing
stored or reported. `attempt()` never waits for a choice.

The choice is stored like a pending factor, in `pending_sign_ins` with `purpose = principal_choice` and no principal,
with the device the client proved it holds (whatever principal that device records) and the sign-in's attempt slots,
which stay taken until a session starts. `PrincipalChoiceRequired` reports it once committed, with the identity, method,
client and that device, never the token or the list.

```php
['choice_token' => $token, 'principal' => $id] = $request->validate([
    'choice_token' => ['required', 'string'],
    'principal'    => ['required', 'string'],
]);

$sessions = Auth::sessions('api');
$choice   = $sessions->choice($token); // null: unknown, expired, used, or not this guard's

$principal = collect($choice?->principals ?? [])
    ->first(fn ($principal) => (string) $principal->getPrincipalIdentifier() === $id);

if ($principal === null) {
    abort(401);
}

$result = $sessions->choose($token, $principal);
```

`choice()` never uses the choice up. `choose()` uses it up whatever the outcome, with a delete only one call can make,
then admits the chosen principal as any sign-in would: the method still allowed, the principal resolved through the
resolver's hinted path as the very one named and the identity's own (`principal_mismatch`), active, in an active tenant,
and admitted by the audience policy with the identifier type the sign-in used. The additional-factor policy is then
asked: a required factor turns the choice into a pending factor for the chosen principal, carrying the same attempt
slots (complete it as above). Otherwise the session starts, on the device the client proved when that device records the
chosen principal and is unchanged, else on a new one, and the slots are given back once committed. A token that
continues no live choice of this guard fails as `pending_invalid`; `pending()` and `complete()` refuse choice tokens,
and `choice()` and `choose()` refuse factor tokens. `discard()` takes either: a discarded choice reports
`AuthenticationFailed` with `principal_choice_abandoned`.

### Enumeration resistance

No response, and no response time, tells a client whether an identifier belongs to anyone. Routes and responses are
yours; what the package guarantees for each method and helper, and what its tests hold it to, is:

| Flow                 | Same outcome for an unknown identifier                                                                                                                                      | Delivery                                  | Timing                                                                                                       |
|----------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-------------------------------------------|--------------------------------------------------------------------------------------------------------------|
| Password sign-in     | `invalid_credentials` for an unknown identifier, a wrong password and a locked account                                                                                      | None                                      | Padded to the credential timebox                                                                             |
| Code request         | A code is issued for any identifier: same status, expiry, cooldown, limits and statements                                                                                   | Queued job (after the response on `sync`) | No identity work at all, so nothing to pad                                                                   |
| Code sign-in         | `invalid_credentials` for an unknown identifier, a wrong, expired, exhausted or used code, and a locked account                                                             | None                                      | Padded to the credential timebox                                                                             |
| Verification by code | Not applicable: the caller holds the identity                                                                                                                               | Queued job (after the response on `sync`) | Not applicable                                                                                               |
| Passkey sign-in      | No identifier to probe: an unknown, foreign or ownerless passkey, a bad signature or user handle, a regressed counter and a locked account all answer `invalid_credentials` | None                                      | Padded to the credential timebox, owner looked up or not; sign-in options do no identity work                |
| API key              | `credential_invalid` for a malformed key, an unknown public part and a wrong secret; the key's status only once the secret verifies                                         | None                                      | No hasher; an unknown public part is checked against a dummy digest, so the work and statements are the same |
| Client credentials   | 401 `invalid_client` with the same body for every client failure (a Basic challenge only to a Basic client); `slow_down` counts the client id as given, when limited        | None                                      | As API key                                                                                                   |

The code request's answer for a number nobody has is `sent`, with the same expiry as any other; only the delivery job
looks the number up, and it sends nothing to an unknown, unverified, inactive or machine identity, or to one that holds
only a look-alike of it. Answer `sent` the same way whatever happens next, and do not tell the client whether a message
went out.

## Refreshing

Refresh with the token the request carries, read through the guard's refresh token transport:

```php
use SineMacula\Laravel\Authentication\Jwt\RefreshResult;

$result = auth()->guard('api')->refreshFromRequest();

if (!$result instanceof RefreshResult) {
    // null: the request carried no refresh token, and nothing was dispatched.
    // A FailureReason: refused, after Failed and AuthenticationFailed with that reason.
    abort(401);
}

return [
    'access_token'  => $result->accessToken,
    'refresh_token' => $result->refreshToken,
];
```

The guard reads the token only from the sources its `refresh_token` settings list: `body` and `header` by default, the
`refresh_token` field of the JSON or form body (never the query string) and the `X-Refresh-Token` header, or the
`cookie` (see [Refresh token cookie](#refresh-token-cookie)). A request that carries a token in more than one of them,
equal or not, is refused as `refresh_token_conflict`: the server never chooses between two tokens, and a request cannot
get past the cookie's cross-site checks by also sending the token another way. A value that is not one non-empty string
is `token_invalid`. A refusal by the transport dispatches `Attempting`, `Failed` and `AuthenticationFailed` (flow
`refresh`) like any failed refresh, without touching a device or counting against a limit; a token the exchange refuses
fails with the exchange's reason, the 429 for `rate_limited` included. The result's `source`
(`RefreshTokenSource::COOKIE`, `BODY` or `HEADER`) says where the token came from, so a refresh read from the cookie can
be answered with a cookie. `Auth::refreshTransport('api')->read($request)` reads a request the same way without
refreshing.

The package defaults are `authentication.refresh_token`; a guard overrides any of them in a `refresh_token` block on its
`config/auth.php` entry, where a key it sets wins, inside `cookie` too:

```php
'api' => [
    'driver'        => 'jwt',
    'provider'      => 'users',
    'refresh_token' => ['sources' => ['header'], 'header' => 'X-App-Refresh'],
],
```

A malformed value or an unknown key fails closed with an `InvalidArgumentException` naming the guard and the key, read
when the guard reads a token. `refresh($refreshToken)` remains for a token your code reads itself and returns the
result or `null`; never pass it a token read from the refresh cookie, which only `refreshFromRequest()` reads with the
cookie's cross-site checks.

A refresh is held to the guard as well as the token. A device the row records for another guard (or for none) fails
with `device_guard_mismatch` and is left alone, even for a token that would be a replay, and a bearer token naming it
is rejected as if the device were missing. The guard's audience policy is asked again on every refresh: the method that
started the session (the device's `sign_in_method`) must still be one the guard allows (`method_not_allowed`; a device
that records none fails too), and the policy must still admit the owner as the principal (`principal_ineligible`).
Neither revokes the device, so the session refreshes again once the policy allows it. Each rotation moves the idle
deadline by the idle lifetime the policy gives the principal's type.

A refresh token is accepted only for the principal its device records. After a switch (see [Switching
principal](#switching-principal)), the refresh token of the principal switched from fails with
`device_principal_mismatch`, even inside the grace window, and the device is left alone; a token presented after the
grace window is a replay, as any rotated token is. A refresh that loses its write to a switch is judged the same way.

Failed refreshes are counted against the token's device and the request's IP address by the bound `AttemptLimiter`;
successful ones are not. Once either count is full, a refresh dispatches `Failed` and `AuthenticationFailed`
(`rate_limited`) without looking the device up, then throws Laravel's `ThrottleRequestsException`, which renders as a
429 with `Retry-After`.

A failure before the stored rotation commits, such as an error while signing the new pair, leaves the presented refresh
token valid for a retry. After the commit, the refresh binds the new context and dispatches `Refreshed` once the
rotation is committed on the device's connection; an exception from a listener on those events loses the new pair, but a
retry with the presented token inside the grace window still gets the current credential (see [Refresh token
replay](#refresh-token-replay)). Keep those listeners from throwing or queue them, so a retry is never needed.

### Refresh token cookie

A browser application can keep its refresh token where its scripts cannot read it, in an `HttpOnly` cookie the API
sets on its own responses. The token lives only in the browser; nothing is stored on the server, so the API stays
stateless. List the cookie as the guard's source and give it the path its routes live under:

```php
'browser' => [
    'driver'        => 'jwt',
    'provider'      => 'users',
    'refresh_token' => [
        'sources' => ['cookie'],
        'cookie'  => ['path' => '/auth'],
    ],
],
```

Put the routes that read the cookie under that path (refresh, a switch of principal, see [Switching
principal](#switching-principal), and sign-in for a browser that proves its device), and set the cookie with the guard's
transport whenever the API hands out a pair:

```php
use Illuminate\Http\Request;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Http\Enums\RefreshTokenSource;
use SineMacula\Laravel\Authentication\Http\PresentedRefreshToken;
use SineMacula\Laravel\Authentication\Jwt\RefreshResult;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;

Route::post('/auth/sign-in', function (Request $request) {
    $transport = Auth::refreshTransport('browser');

    abort_unless($transport->isSameSiteRequest($request), 403);

    // A browser that still holds a refresh cookie proves its device, which the sign-in then continues.
    $presented = $transport->read($request);
    $context   = SignInContext::fromRequest($request, refreshToken: $presented instanceof PresentedRefreshToken ? $presented->token : null);
    $session   = Auth::sessions('browser')->signIn('password', $request->only('email', 'password'), $context)->session;

    abort_if($session === null, 401);

    return response()->json(['access_token' => $session->tokens->accessToken])
        ->withCookie($transport->cookie($session->tokens->refreshToken, $session->device));
});

Route::post('/auth/refresh', function () {
    $guard  = Auth::guard('browser');
    $result = $guard->refreshFromRequest();

    abort_unless($result instanceof RefreshResult && $result->source === RefreshTokenSource::COOKIE, 401);

    return response()->json(['access_token' => $result->accessToken])
        ->withCookie(Auth::refreshTransport('browser')->cookie($result->refreshToken, $guard->device()));
});

Route::post('/logout', function () {
    Auth::guard('browser')->logout();

    return response()->noContent()->withCookie(Auth::refreshTransport('browser')->forgetCookie());
});
```

The cookie is `HttpOnly`, `Secure` and `SameSite=Strict`, named `__Secure-refresh_token` by default, scoped to the
configured `path` and `domain` (`null`, the default, keeps it to the API's host), and expires when the device's session
does, as the refresh token in it does. `forgetCookie()` returns the same cookie already expired; any route may send it,
a logout route outside the cookie's path included, since a path limits where the browser sends a cookie, not which
response may set it. On a guard that reads the cookie, a `__Host-` name is accepted only with the path `/` and no
domain, as browsers require; a guard that reads only the body or a header never sets the cookie, so a package-wide
`__Host-` name does not bind it. Setting or clearing the cookie on a guard that does not list `cookie` throws a
`LogicException`. Names PHP renames when it parses a request are refused, as the token would never be found under
them: a `.` in the cookie or a header name, and a `.`, a space or a bracket in `body_field`.

A browser attaches the cookie by itself, to any request for its path, so a refresh read from it is held to two checks a
cross-site page cannot pass: its `Origin` must be the API's own (the request's scheme and host) or one of
`cookie.allowed_origins` (each exactly `scheme://host[:port]`), and it must carry the `cookie.csrf_header` header
(`X-Requested-With` by default) with a value, which a form or a simple request cannot send; a header a browser sends on
its own (`Content-Type`, `Origin`, any `Sec-` header and the like, also when spelled with `_` for `-`) is refused as the
`csrf_header`. Anything else is `cross_site_request`. A route that sets the cookie must hold its request to the same
checks, the sign-in above all: a cross-site page can auto-submit a form to it with an attacker's credentials, and a
browser keeps a `SameSite=Strict` cookie set by the response to such a top-level navigation, so without the check the
victim's browser would hold the attacker's refresh cookie and its own scripts would then pass the refresh checks inside
the attacker's account. `Auth::refreshTransport('browser')->isSameSiteRequest($request)` is that check, as the sign-in
route above uses it. A script refreshes with:

```js
await fetch('/auth/refresh', {method: 'POST', credentials: 'include', headers: {'X-Requested-With': 'fetch'}});
```

Another host of the same site, such as a marketing site, a subdomain serving user content or one taken over, can plant
a cookie of the same name: a `__Secure-` cookie may name the parent `Domain`, and a browser sends one with a longer
`Path` before the API's own. PHP keeps only the first cookie of a name, so a request that carries the refresh cookie
twice (counted under the name PHP files each one under) is refused as `refresh_token_conflict`, and the server never
refreshes with the planted one. The planted cookie still fails every refresh until it expires, though, and the API
cannot clear it, since `forgetCookie()` names the guard's own domain and path, not the planter's; and a browser that
holds no refresh cookie of its own would send the planted one alone. If you do not trust every host of the site, name
the cookie `__Host-refresh_token` with the path `/`: a browser keeps a `__Host-` cookie only from the API's own host,
with no `Domain`, so no other host can plant one. The cost is that the cookie then rides on every request to the API's
host, not only the routes that read it.

`SameSite=Strict` keeps the cookie from being sent from another site at all, so `allowed_origins` serves origins of
the same site, such as an application on `app.example.com` calling an API on `api.example.com`. For such an origin,
let Laravel's CORS middleware allow credentials only for the origins you list (`supports_credentials` set to `true`
and `allowed_origins` naming them in `config/cors.php`, never `*`). Behind a proxy or load balancer that ends TLS,
configure Laravel's trusted proxies, so the request knows its own scheme and host and the API's own origin matches.

Laravel's `EncryptCookies` middleware, when it runs on these routes, encrypts the cookies a response sets and decrypts
the ones a request sends. The refresh token is already signed, and only the API reads it, so the simplest setup leaves
it out:

```php
->withMiddleware(function (Middleware $middleware) {
    $middleware->encryptCookies(except: ['__Secure-refresh_token']);
})
```

If you keep it encrypted, set and read the cookie on routes that both run `EncryptCookies`, so the value the browser
returns is the one the middleware made; a value it cannot decrypt reaches the guard as an invalid token
(`token_invalid`), and the client signs in again. Routes in `routes/api.php` do not run `EncryptCookies` unless you
add it.

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
  (`revoked_at` and `revoked_reason = rotation_reuse`, both digests cleared), `DeviceRevoked` and `AuthenticationFailed`
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
committed on the device's own connection: at once outside a transaction, so before `Failed` and `AuthenticationFailed`,
and after the commit inside one, so after them; a rolled-back revocation is never reported, and a transaction on another
connection neither delays nor withdraws it. The transaction that Laravel's `DatabaseTransactions` and `RefreshDatabase`
testing traits wrap around each test does not count either, so a test sees `DeviceRevoked` when the application would.
Under PostgreSQL's REPEATABLE READ, a parallel refresh that commits first makes this one fail with a serialization
error, which surfaces as a server error for you to retry.

## Switching principal

An identity that may act as several principals (memberships of several tenants, say) switches the session it is signed
in with to another one, on the same device, proven by the session's refresh token:

```php
use Illuminate\Http\Exceptions\ThrottleRequestsException;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Http\Enums\RefreshTokenSource;

$target = Membership::findOrFail($request->input('membership'));
$result = Auth::sessions('api')->switchPrincipalFromRequest($target);

abort_if($result === null, 401); // no refresh token in the request

if ($result->isFailed()) {
    // AuthenticationFailed was dispatched (flow principal_switch); $result->reason says why.
    if ($result->reason === FailureReason::RATE_LIMITED) {
        // A 429 with Retry-After, as a refused refresh answers, so clients wait.
        throw new ThrottleRequestsException('Too Many Attempts.', null, ['Retry-After' => $result->retryAfter]);
    }

    abort(401);
}

$tokens = $result->session->tokens;

return $result->source === RefreshTokenSource::COOKIE
    ? response()->json(['access_token' => $tokens->accessToken])
        ->withCookie(Auth::refreshTransport('api')->cookie($tokens->refreshToken, $result->session->device))
    : response()->json(['access_token' => $tokens->accessToken, 'refresh_token' => $tokens->refreshToken]);
```

The refresh token proves the session, never an access token: a stolen access token lives minutes and must not mint a
refresh credential. `switchPrincipalFromRequest()` reads it as `refreshFromRequest()` does, through the guard's refresh
token transport, so it comes from the one source the guard allows and a token from the refresh cookie gets the cookie's
cross-site checks; put the switch route under the cookie's path. It returns `null` when the request carries no token,
and a token the transport refuses fails with its reason (`refresh_token_conflict`, `cross_site_request`,
`token_invalid`, reported as an `AuthenticationFailed` of flow `principal_switch`) without the device being touched. The
result's `source` says where the token came from, so a switch read from the cookie answers with the new refresh token
in the cookie, as a refresh does. `switchPrincipal($refreshToken, $target)` remains for a token your code reads itself;
never pass it one read from the refresh cookie.

A switch is judged as a refresh is: counted against the same refresh limits (`rate_limited`, with the wait in the
result's `retryAfter`: unlike `refreshFromRequest()`, which throws the 429 itself, a switch returns its refusal, so
answer it with `Retry-After` as above), the token parsed for this guard, the device found, of this guard, live, and the
rotation id current, or the previous one inside the grace window; any other id is a replay and revokes the device
(`rotation_reuse`). On every path the device's owner must still be returned by the guard's provider and be active, the
target must resolve through the resolver's hinted path as the very principal named, of its class, owned by that identity
(read from the principal's own key, not trusted to the resolver), active, in an active tenant and admitted by the
audience policy, also with the type of identifier the session's sign-in used (which the device records), so a principal
your policy refuses to that identifier cannot be reached by switching to it, the session's sign-in method must still be
allowed, and the additional-factor policy must not ask for a further factor (`additional_factor_required`: sign in again
as the target).

With the current rotation id, the token's principal must be the one the device records (`device_principal_mismatch`).
The switch keeps the session's absolute deadline, held to the target type's absolute lifetime counted from the sign-in
(`session_expired` when that has passed), restarts the idle one under the target's lifetimes, issues both tokens for the
target, then records the target, the switch time (`principal_switched_at`), the rotation and both deadlines in one
compare-and-swap. The access tokens of the principal switched from stop at once, and switching back does not revive them
(see [Device](#device)). A switch to the principal the device already records rotates the credential like a refresh and
reports no switch.

With the previous rotation id inside the grace window, the current credential for the target is handed back, writing
nothing, only when the device records the target and either its last rotation was the switch to it (a lost switch
response, retried) or the token's own principal is the target; anything else is `rotation_conflict`, without revoking,
and the client retries with its current token. When another request changes the device between the switch's read and its
write, the row is read again with a lock and judged once more under the same rules; the swap is never tried twice.

A switch binds the guard to the target (`Authenticated`, `PrincipalAssigned`, `DeviceAuthenticated`, no `Login`) and
dispatches `PrincipalSwitched` once committed on the device's connection, with the new principal and tenant in its
context, and the previous principal as the device recorded it (`previousPrincipalType`, `previousPrincipalId`) and, when
it still resolves for the identity, the principal itself (`previousPrincipal`).

## Signing out and revoking sessions

`Auth::logout()` (or `Auth::guard('api')->logout()`) signs the request's session out through the session service: the
device the guard is bound to is revoked with reason `signed_out`, `DeviceRevoked` reports it once committed, Laravel's
`Logout` follows, and the guard stays signed out for the rest of the request. The session's access and refresh tokens
stop at once. A session without a persisted device (an access-only token) has nothing to revoke and is only forgotten;
a guest request does nothing. `Auth::sessions('api')->signOut()` does the same and returns whether it revoked a device.
`logout()` cannot reach the response, so clear a browser's refresh cookie on it with
`Auth::refreshTransport('api')->forgetCookie()` (see [Refresh token cookie](#refresh-token-cookie)).

The session service also revokes sessions for the application's own screens and flows:

```php
use SineMacula\Laravel\Authentication\Events\Enums\RevocationReason;
use SineMacula\Laravel\Authentication\Facades\Auth;

$sessions = Auth::sessions('api');

// "Sign out of all other devices": every session of the identity, of every guard, but this one.
$sessions->signOutEverywhere(keepCurrentDevice: true);

// A device list's "sign out" button: only the identity's own device is found.
$sessions->revokeDevice(Auth::identity(), $deviceId, RevocationReason::REVOKED);

// An administrator ends every session of an identity, or every session acting as a principal.
$sessions->revokeDevices($identity, RevocationReason::REVOKED, except: null);
$sessions->revokePrincipalDevices($membership, RevocationReason::REVOKED);
```

Each device is revoked by one conditional update that only applies while it is not revoked yet, so every call is
idempotent: the first revocation's time and reason are kept, and of two calls racing for a device only the one that
revoked it reports `DeviceRevoked`. `revokeDevice()` finds the device through the owner's `devices()` relation on the
write connection, so another identity's device is simply not found and the call returns `false`, as it does for an
unknown or already revoked one. `revokeDevices()` covers every device the identity's relation returns, of every guard;
`revokePrincipalDevices()` every device of the configured model that records the principal. Both keep the `except`
device when one is given, return how many devices they revoked, and also end the scope's pending sign-ins (a further
factor or a principal choice waiting to be completed), so a credential issued before the revocation cannot start a
session after it. `revokeDevices()` also cancels the identity's pending identifier changes, of every type and through
every guard: a change link needs no session, so one requested from a session that ends could otherwise still move the
account to an identifier of the requester's (see [Changing identifiers](#changing-identifiers)). `revokeDevice()` and
`revokePrincipalDevices()` leave them, since the identity keeps its other sessions. `signOutEverywhere()` is
`revokeDevices()` for the request's identity with reason
`signed_out_everywhere`; it returns `0` on a guest request, and it leaves the guard bound for the rest of the request
(call `signOut()` as well to end the current session too). With `keepCurrentDevice: true` on a request whose session has
no device (an access-only token), the session is kept by leaving the identity's "tokens valid after" cutoff where it is,
since a device-less token can only be ended through it: every device is still revoked, but the identity's other
device-less tokens keep working too, until they expire.

A bulk revocation first moves the scope's "tokens valid after" cutoff to now, when the identity or principal records one
(`HasTokensValidAfter`), then, in one transaction on the device model's connection, revokes each unrevoked device, read
on the write connection in key order 500 at a time, and deletes the pending sign-ins and, for an identity, its pending
identifier changes. Once that transaction commits,
`DeviceRevoked` reports each device it revoked (with the device's own guard) and then `SignedOutEverywhere` reports the
scope, with the acting guard, the reason, the count (also `0`, so the action itself is recorded), the cutoff it set (or
`null`), and the device it kept. If the device transaction fails, the cutoff it already moved stands: more is cut off,
never less, and calling again finishes the job. One window stays open: a sign-in that has already passed its credential
check when a bulk revocation reads the devices can still create its device afterwards. Closing it would take a lock that
every sign-in and every revocation take on the identity, which the package does not add.

### Listing devices

`devices()` returns one page of an identity's active devices for a "where you're signed in" screen: every session it
holds on any guard that is not revoked and is before both its idle and absolute deadline, most recently used first
(devices never used last), then newest first:

```php
use SineMacula\Laravel\Authentication\Facades\Auth;

Route::middleware('auth:api')->get('/devices', fn () => Auth::sessions('api')->devices(Auth::identity(), perPage: 20));
```

Each item is a `DeviceSummary`, safe to return as it is: the device id (its `did`), guard, sign-in method, client name
and platform, the creation time (for a model with Eloquent timestamps), IP address and user agent, when the session
started (its latest sign-in on that device), the last use and its IP address and user agent, both deadlines, and
`current`, which marks the device the request is authenticated with on that guard. It never holds a refresh digest, the
rotation time, the revocation columns, the owner or the principal, and `toArray()` and JSON use snake_case keys and
ISO-8601 times. A page holds 1 to 100 devices (15 by default; anything else is an `InvalidArgumentException`), and the
page is the request's `page` parameter unless you pass one. The list is read on the write connection through the
identity's `devices()` relation, in two queries (a count and a select), so a device revoked a moment ago is never shown.
An identity that does not implement `HasDevices`, or whose `devices()` relation queries a model that is not an
`EloquentDevice`, is a `LogicException`.

The same rule is a query scope on any model that uses `ActsAsDevice`, for your own queries:

```php
Device::query()->active()->where('guard', 'api')->count();
```

### Revoking on security changes

Call the session service from your own flows when something about an identity's security changes; each ends the
affected sessions as a bulk revocation, with its own reason, moves the scope's cutoff, and ends its pending sign-ins
and, for the four that end an identity's sessions, its pending identifier changes:

| Method                                             | Ends                                       | Reason                  |
|----------------------------------------------------|--------------------------------------------|-------------------------|
| `passwordChanged($identity, ?Device $except)`      | The identity's sessions, but `$except`     | `password_changed`      |
| `passwordReset($identity)`                         | Every session of the identity              | `password_reset`        |
| `factorRemoved($identity, ?Device $except)`        | The identity's sessions, but `$except`     | `factor_removed`        |
| `identityDeactivated($identity)`                   | Every session of the identity              | `identity_deactivated`  |
| `principalDeactivated($principal)`                 | Every session acting as the principal      | `principal_deactivated` |
| `tenantDeactivated($tenant, iterable $principals)` | Every session acting as a listed principal | `tenant_deactivated`    |

Never call `passwordChanged()` for the automatic rehash of a password on sign-in: the password did not change. These
methods end sessions, pending sign-ins and pending identifier changes only. A change or a reset set through
`Auth::passwords()->set()` (see [Setting a password](#setting-a-password)) calls them and also ends the other proofs
that could take the account back without a session: the reset links and codes and the sign-in codes of the identity. A
registration calls none of them and ends only the reset links and codes. A password your own flow saves another way
leaves those proofs as they are.
`factorRemoved()` is the seam a further-factor package calls when an identity removes a factor. Devices record
principals, not tenants, so `tenantDeactivated()` takes the tenant's principals from you: each must act within the
tenant (read on the write connection from the principal as stored, so a `tenant` relation you loaded does not decide and
Eloquent's strict mode does not stop the read), or an `InvalidArgumentException` is thrown before anything is written. A
`CanBeActive` tenant already deleted or soft-deleted still works, since a principal whose `TenantUnavailableException`
names that very tenant (its class and key, as `ActsAsPrincipal` reports it) acts within it, so restoring the tenant
later revives no session; a tenant that does not implement `CanBeActive` reads as no tenant once it cannot be loaded, so
call `tenantDeactivated()` before deleting it; a principal listed twice counts once, and every principal's sessions end
in one device transaction, with one `SignedOutEverywhere` per principal. Deactivation already stops every token at once
through the live activity checks (see [Active-state enforcement](#active-state-enforcement)); revoking makes the end
outlast a reactivation and records why.

Three optional listeners call them for you. Registering one is the opt-in, and each revokes only once the change that
triggered it is committed on the changed model's connection, so a change that is rolled back revokes nothing:

```php
use Illuminate\Auth\Events\PasswordReset;
use Illuminate\Support\Facades\Event;
use SineMacula\Laravel\Authentication\Listeners\RevokeDevicesOnDeactivation;
use SineMacula\Laravel\Authentication\Listeners\RevokeDevicesOnPasswordChange;
use SineMacula\Laravel\Authentication\Listeners\RevokeDevicesOnPasswordReset;

Event::listen(PasswordReset::class, RevokeDevicesOnPasswordReset::class);
User::observe(RevokeDevicesOnPasswordChange::class);
User::observe(RevokeDevicesOnDeactivation::class);
Membership::observe(RevokeDevicesOnDeactivation::class);
```

- `RevokeDevicesOnPasswordReset` answers Laravel's `PasswordReset` (the password broker's) with `passwordReset()`.
- `RevokeDevicesOnPasswordChange` observes an identity model and answers a saved change of its password column with
  `passwordChanged()`, revoking every device, the one the change was made from included; to keep that one, call
  `passwordChanged($identity, Auth::device())` yourself instead. The automatic rehash on sign-in is not a change, and
  the observer ignores it: the package's own sign-ins run it marked, and so do Laravel's guards (`attempt()`,
  `attemptWhen()`, `once()`, as a web login over the same user model does), whose attempt the package follows through
  Laravel's auth events. A save is the rehash only when it re-encodes the password signed in with (both the hash it
  replaces and the hash it saves verify it) and no change of the user's password has run since the rehash or attempt
  began; for an attempt, it must also save the very model instance the attempt validated. So a new password saved before
  the attempt ends (by an `attemptWhen()` callback, say) revokes, and so does any later save of the user, a change back
  to that password or a fresh hash of it through another instance included. An attempt made inside another attempt's
  callback, or the session's user resolved there, leaves the outer attempt's rehash alone; two cases end the outer
  attempt early, so its rehash then revokes: an `Auth::login()` of the very instance it validated inside its callback,
  and a refused inner attempt that validated that same instance (from a provider that caches its users). Users are told
  apart by the row they are stored in (connection, database, table and key), so the same key in another tenant's
  database is another user. Confirming the current password with `validate()` before changing it is not an attempt, so
  the change that follows revokes; so does Laravel's `logoutOtherDevices()`, whose forced rehash exists to sign the
  other sessions out, even while an attempt for the user is open or the package's own rehash runs: the package holds a
  save it takes for a rehash until the request or job ends, and the `OtherDeviceLogout` event that follows a forced
  rehash runs it, so a sign-out after an attempt's rehash in the same request may revoke twice. Only changes saved
  through Eloquent fire model events.
- `RevokeDevicesOnDeactivation` observes a `CanBeActive` identity or principal model and answers an update that turns
  it from active to inactive with `identityDeactivated()` or `principalDeactivated()` (a 2D model is treated as the
  identity). It compares a copy holding the attributes from before the update with the model as it is now, so it suits
  activity held in the model's own attributes (`ProvidesActiveState`); for activity derived from anything else, call
  the method yourself. A tenant has no listener: devices record principals, not tenants, so call
  `tenantDeactivated()` with the tenant's principals. Registering the observer on a model that is neither an identity
  nor a principal throws a `LogicException` when that model is deactivated.

A password reset through Laravel's broker saves the new password through Eloquent before your code fires
`PasswordReset`, so with both password listeners registered the observer revokes every device first, as
`password_changed`, and the reset listener then finds none left to revoke (its `SignedOutEverywhere` reports
`password_reset` with a count of `0`). Register one of them for each flow: the observer alone ends sessions on every
change of password, resets included, as `password_changed`; to record resets as `password_reset`, register the reset
listener and call `passwordChanged()` from your password-change flow instead of registering the observer.

Revocation covers every guard whichever session service acts; the acting guard only names the guard and request the
events report. It is the current default guard when that is a `jwt` guard, else the first `jwt` guard in
`auth.guards`, so a change made on a route guarded by another driver (whose middleware makes that guard the default)
still revokes. To name it, bind the listener's `$guard`:

```php
$this->app->when(RevokeDevicesOnPasswordChange::class)->needs('$guard')->give('api');
```

With no `jwt` guard configured at all, a listener throws an `InvalidArgumentException`.

### Access tokens without a device

An access token issued without a device (access-only mode, see
[Access-only mode](#access-only-mode-no-devices-no-refresh)) has no device to revoke. To end those too, an identity or
principal implements `HasTokensValidAfter`, with the `ProvidesTokensValidAfter` trait over a nullable whole-second
column you add:

```php
Schema::table('users', function (Blueprint $table) {
    $table->dateTime('tokens_valid_after', 0)->nullable();
});
```

```php
use SineMacula\Laravel\Authentication\Concerns\ProvidesTokensValidAfter;
use SineMacula\Laravel\Authentication\Contracts\HasTokensValidAfter;

class User extends Model implements HasTokensValidAfter, Identity, Principal
{
    use ProvidesTokensValidAfter;
}
```

Every bulk revocation of its sessions (including the security-change methods above) then moves its cutoff to the
revocation's second first, except `signOutEverywhere(keepCurrentDevice: true)` from a session without a device, which
keeps the identity's cutoff where it is (see above), and the bearer path rejects a device-less access token whose `iat`
is at or before the identity's or the principal's cutoff (`issued_before_cutoff`). The whole second is cut off, because
a token's whole-second `iat` cannot tell an earlier token from one issued after the call in the same second, so a
device-less token issued in that second is rejected too. Tokens that name a device are not checked against the cutoff
(revoking the device ends them, and the device a sign-out everywhere keeps must keep working). The cutoff only ever
moves forward, with one conditional update on the model's own connection (`invalidateTokensIssuedBefore()`); the column
must be loaded, or reading it throws a `LogicException`, and the column name comes from `getTokensValidAfterName()`.

### Revocation reasons

Every revocation records one of these reasons in the device's `revoked_reason` and in `DeviceRevoked::$reason`
(`RevocationReason`); a bulk revocation reports it in `SignedOutEverywhere::$reason` as well:

| Reason                  | Recorded when                                                                                                               |
|-------------------------|-----------------------------------------------------------------------------------------------------------------------------|
| `signed_out`            | The session signed itself out: `logout()`, `Auth::sessions()->signOut()`                                                    |
| `signed_out_everywhere` | `signOutEverywhere()` ended the identity's sessions                                                                         |
| `revoked`               | The application revoked it: `revokeDevice()`, `revokeDevices()`, `revokePrincipalDevices()`                                 |
| `rotation_reuse`        | A rotated refresh token was replayed, by a refresh or a switch of principal                                                 |
| `password_changed`      | `passwordChanged()`: directly, through `Auth::passwords()->set()` with `CHANGE`, or through `RevokeDevicesOnPasswordChange` |
| `password_reset`        | `passwordReset()`: directly, through a reset or `set()` with `RESET`, or through `RevokeDevicesOnPasswordReset`             |
| `factor_removed`        | `factorRemoved()`, directly or through `RevokeDevicesOnPasskeyRemoval`                                                      |
| `identity_deactivated`  | `identityDeactivated()`, directly or through `RevokeDevicesOnDeactivation`                                                  |
| `principal_deactivated` | `principalDeactivated()`, directly or through `RevokeDevicesOnDeactivation`                                                 |
| `tenant_deactivated`    | `tenantDeactivated()`                                                                                                       |

`revokeDevice()`, `revokeDevices()` and `revokePrincipalDevices()` take the reason as an argument (`REVOKED` in the
examples above); the others set their own.

## Passwords

`Auth::passwords($guard)` is the password service of a `jwt` guard (an `InvalidArgumentException` names any other):
the password policy, and the one call a registration, a change or a reset makes to set a password. Routes, forms and
messages stay yours.

### Password policy

```php
'passwords' => [
    'min_length' => 15,
    'max_length' => 128,
    'letters'    => false,
    'mixed_case' => false,
    'numbers'    => false,
    'symbols'    => false,
    'breached'   => ['when_unavailable' => 'reject'],
    'reset'      => ['link_ttl_seconds' => 3600],
],
```

A new password has at least `min_length` characters (8 to 128) and at most `max_length` (`min_length` to 4096),
counted as Laravel's `min` and `max` rules count them (`mb_strlen`). The default minimum of 15 is NIST SP 800-63B's for
a password used as the only factor; if every sign-in also requires a further factor (see
[Additional factors](#additional-factors)), you may lower it to 8. While Laravel's hashing driver is bcrypt (its
default), which reads only the first 72 bytes and ignores the rest, a password of more than 72 bytes is refused as too
long, and `min_length` may be at most 72; bcrypt also cannot hash a null character, so a password holding one is refused
as `null_character` rather than failing in the hasher. `letters`, `mixed_case`, `numbers` and `symbols` turn on the composition
rules of Laravel's `Password` rule, with its exact expressions; they are off by default, as NIST advises against them.
Each value fails closed with an `InvalidArgumentException` naming the key when a password is first checked, and
`authentication:check` reports it under `[passwords]`.

A password that passes those rules is then given to the bound `BreachedPasswordChecker`, which says whether it is known
from a breach. The package ships no breach service: the default checker, `NoBreachedPasswordCheck`, finds nothing, so
it protects nothing, and NIST expects a check against a blocklist of breached and common passwords. Bind your own:

```php
use App\Auth\BreachRangeChecker;
use SineMacula\Laravel\Authentication\Contracts\BreachedPasswordChecker;

$this->app->singleton(BreachedPasswordChecker::class, BreachRangeChecker::class);
```

```php
use Illuminate\Http\Client\ConnectionException;
use Illuminate\Http\Client\RequestException;
use Illuminate\Support\Facades\Http;
use SineMacula\Laravel\Authentication\Contracts\BreachedPasswordChecker;
use SineMacula\Laravel\Authentication\Exceptions\BreachedPasswordCheckUnavailableException;

// Asks a breach corpus that answers by hash prefix, so the password never leaves the server.
final class BreachRangeChecker implements BreachedPasswordChecker
{
    public function isBreached(#[\SensitiveParameter] string $password): bool
    {
        $hash = strtoupper(sha1($password));

        try {
            $response = Http::timeout(2)->get(config('services.breaches.url') . '/range/' . substr($hash, 0, 5))->throw();
        } catch (ConnectionException|RequestException) {
            throw new BreachedPasswordCheckUnavailableException('The breached-password service did not answer.');
        }

        return str_contains($response->body(), substr($hash, 5) . ':');
    }
}
```

When the checker cannot answer, it throws `BreachedPasswordCheckUnavailableException` (never with the password in the
message): the exception is reported to your exception handler, and `breached.when_unavailable` decides what happens to
the password. Laravel's own breached check, `Password::uncompromised()` over its `UncompromisedVerifier`, is not the
seam: its verifier reports an outage and answers "not breached", so it always fails open and `when_unavailable` could
not hold. `reject` (the default) refuses it as `breach_check_unavailable`, failing closed, so an outage blocks new
passwords rather than letting a breached one through; `allow` lets it through, failing open. Any other exception the
checker throws propagates.

`check($password)` gives the policy's verdict, a `PasswordCheck` whose `violations` list every rule the password breaks
(`passes()` when there is none), as `PasswordViolation` cases: `too_short`, `too_long`, `null_character`, `letters`,
`mixed_case`,
`numbers`, `symbols`, and, only once the others pass, `breached` or `breach_check_unavailable`. `rule()` returns
Laravel's `Password` rule with the same length and composition, for a form request's validation:

```php
use SineMacula\Laravel\Authentication\Facades\Auth;

$request->validate(['password' => ['required', 'confirmed', Auth::passwords('api')->rule()]]);
```

The rule runs no breached check (it does not add `uncompromised()`) and cannot see bcrypt's byte limit or its null
character, so `set()` (or
`check()`) has the last word. It is built from the package's settings, not from `Password::defaults()`: a form that
validates with your own defaults is checked against those, and `set()` still applies the package's policy. The
policy applies only to passwords being set: the automatic rehash of an outdated hash on sign-in re-encodes the password
the identity already has, so an older password shorter than today's minimum still signs in, and is rehashed.

### Setting a password

`set($identity, $password, $flow, ?Device $except = null, ?ClientContext $client = null)` applies the policy, and only
a password that passes is hashed with Laravel's `Hasher` and stored; a password that fails writes nothing and reports
nothing. The result is a `PasswordResult`: `set` (or `isSet()`), the `violations` when it was not, and how many devices
the flow `revoked`. The events report `$client`, or the client of the request the guard is serving, so pass one when
you set a password from a queued job or a console command. The `PasswordFlow` decides what else happens, in one
transaction on the identity's connection:

| Flow           | For                                                       | Ends                                                |
|----------------|-----------------------------------------------------------|-----------------------------------------------------|
| `REGISTRATION` | The first password of an identity your registration makes | No session                                          |
| `CHANGE`       | A signed-in identity replacing its own password           | Every session but `$except`, as `passwordChanged()` |
| `RESET`        | A password set without the old one, after a proof         | Every session, as `passwordReset()`                 |

```php
use SineMacula\Laravel\Authentication\Contracts\AttemptLimiter;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Passwords\Enums\PasswordFlow;
use SineMacula\Laravel\Authentication\RateLimiting\AttemptSubject;
use SineMacula\Laravel\Authentication\RateLimiting\Enums\AttemptFlow;

Route::middleware('auth:api')->put('/password', function (Request $request, AttemptLimiter $limiter) {
    $passwords = Auth::passwords('api');
    $identity  = Auth::identity();

    $request->validate(['current_password' => 'required', 'password' => ['required', 'confirmed', $passwords->rule()]]);

    $slot = $limiter->acquire(new AttemptSubject('api', AttemptFlow::SIGN_IN, $identity->email, 'email', $request->ip()));

    if (!$slot->granted()) {
        return response()->json(['message' => 'Too many attempts.'], 429)->header('Retry-After', (string) $slot->retryAfter);
    }

    if (!Auth::guard('api')->validate(['email' => $identity->email, 'password' => $request->input('current_password')])) {
        return response()->json(['message' => 'The current password is wrong.'], 422);
    }

    $limiter->release($slot);

    $result = $passwords->set($identity, $request->input('password'), PasswordFlow::CHANGE, Auth::device());

    return $result->isSet()
        ? response()->noContent()
        : response()->json(['violations' => array_map(fn ($violation) => $violation->value, $result->violations)], 422);
});
```

`set()` is a trusted call, as `login()` is: you decide that the identity may have the password, and you choose the flow
on the server, never from input, because a registration ends no session. Ask for a recent reauthentication before a
change, as above, so a stolen session cannot change the password and keep itself signed in. `validate()` checks the
password inside the guard's credential timebox but counts no attempt, so the route takes a slot of the guard's `sign_in`
limits from the bound `AttemptLimiter` first, as a sign-in's password does, counted in the database for the identifier
and the IP address, and gives it back once the password is right. A change ends every session of the identity, through
every guard, but the device in `$except` (the request's own device, to keep it signed in; `null` ends them all); a reset
ends every session. Both move the identity's "tokens valid after" cutoff when it keeps one and end its pending sign-ins
(see [Revoking on security changes](#revoking-on-security-changes)), and report each revoked device with `DeviceRevoked`
and then `SignedOutEverywhere`. `$except` is for a change only. Whatever the flow, the same transaction invalidates every
password reset link and code still waiting for the identity's identifiers, through every guard whose provider returns
the identity (see [Password reset](#password-reset)): a link or code someone else obtained before cannot take the
account back once its owner has set a new password. A change or a reset also invalidates the sign-in codes waiting for
those identifiers, which would open a session after the ones it ended, and cancels every identifier change the identity
has pending (see [Changing identifiers](#changing-identifiers)); a registration ends no session and leaves them.
The identifiers are those its row holds, read again inside the
transaction, so a model you loaded with only some columns, or before its identifier changed, outdates them all. A
guard whose provider reads another table binds its links and codes to the identities there, so they are left alone.

A stored identity gets one query-builder update of its password column (and `updated_at` when the model keeps
timestamps) on its own row, without its scopes: nothing else you changed on the model is saved or discarded, and no
model event fires, so an observer neither cancels the write nor revokes again behind it (`RevokeDevicesOnPasswordChange`
does not undo the device a change kept). The model then holds the new hash. Only a registration may set the password of
an identity not stored yet, which is then inserted with `save()`; a model event that cancels that save throws a
`LogicException`. A registration sets only a first password: given a stored identity, it updates the row only while its
password column is `null` or empty, in the same statement, and throws a `LogicException` otherwise, since replacing a
password without ending any session would be a change that leaves a stolen session signed in. So does a change or a
reset of an identity not stored, or one whose row is gone, and an identity that is not an Eloquent model; a non-human
identity (`MachineIdentity`) has no password and throws an `InvalidArgumentException`.

`PasswordSet` reports the password set, with the flow, once the transaction commits on the identity's connection, and
never for one rolled back; its context names the guard, the client and the identity, and, for a change, the device kept.
Called inside a transaction of yours, the hash, the cutoff and the revocations are part of it, and every event waits for
its commit. When the device model lives on another connection than the identity, the devices are revoked in their own
transaction, which commits inside the identity's: a failure after it leaves the devices revoked and the password
unchanged, so more is ended, never less, and calling again finishes the job. The automatic rehash on sign-in never
fires `PasswordSet`.

### Password reset

A reset proves control of an identifier with a link's token or a one-time code, then sets the new password and ends
every session of the identity, through every guard, in one transaction. The application owns the routes, the forms and
the messages:

```php
use Illuminate\Http\Request;
use SineMacula\Laravel\Authentication\Codes\Enums\CodeRequestStatus;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Passwords\Enums\ResetStatus;

Route::post('/password/forgot', function (Request $request) {
    $answer = Auth::passwords('api')->sendResetLink($request->only('email'));

    return $answer->status === CodeRequestStatus::RATE_LIMITED
        ? response()->json(['message' => 'Too many requests.'], 429)->header('Retry-After', (string) $answer->retryAfter)
        : response()->json(['message' => 'If the address is registered, a link is on its way.'], 202);
});

Route::post('/password/reset', function (Request $request) {
    $result = Auth::passwords('api')->reset($request->only('email', 'token', 'password'));

    return match ($result->status) {
        ResetStatus::RESET             => response()->noContent(),
        ResetStatus::PASSWORD_REJECTED => response()->json(['violations' => array_map(fn ($v) => $v->value, $result->violations)], 422),
        ResetStatus::RATE_LIMITED      => response()->json(['message' => 'Too many attempts.'], 429)->header('Retry-After', (string) $result->retryAfter),
        ResetStatus::INVALID           => response()->json(['message' => 'The link is invalid or has expired.'], 422),
    };
});
```

`sendResetLink($input, ?ClientContext $client = null)` sends a link to the identifier the input names under the guard's
password identifier (`email` unless the guard sets another, see [Sign-in](#sign-in)); `sendResetCode($type, $input)`
sends a code to the identifier the input names under `$type` (`phone`, say), which must have a registered normaliser
(see [Identifiers](#identifiers)). Both do the same work for every identifier, so the answer, the statements and the
time are the same whether or not anyone holds it: the guard must allow the `password` method (`method_not_allowed`
otherwise), the identifier must be one its type's normaliser accepts (`identifier_invalid`), the identifier, in normal
form, and the IP address must have requests left under the `password_reset_request` limits (`rate_limited`, counted on
every request and never given back), and no link or code may have been issued for it within the codes'
`resend_cooldown_seconds` (`rate_limited` with the seconds left). Then a token or a code is issued for the identifier,
whoever holds it, and its delivery queued (see [One-time codes](#one-time-codes) for the delivery queue): the answer is
a `CodeRequest`, `sent` with when it expires. A link request answers with the code requests' type as well (`CodeRequest`
and `Codes\Enums\CodeRequestStatus`, as the route above imports): a reset link's token is issued and limited by the same
engine as a code, and the answer has the same four statuses. A newer link or code replaces the one before, which stops
working at once. No identity is looked up during the request. Refusals are reported by `AuthenticationFailed` with the
flow `password_reset`.

The queued job alone decides, later, who receives it: the identity the guard's provider finds by the identifier, read on
the write connection, that is not a `MachineIdentity`, is active, holds exactly that identifier (its own, in normal form,
compared byte for byte, through `HasVerifiableIdentifiers` when it implements it and otherwise the model attribute named
after the type, so an account found only by a look-alike the column's collation matches gets nothing), and, when the
guard requires verified identifiers and the identity can report them, has it verified. Anyone else, or no one, is sent
nothing, and nothing says so. The job sends nothing for a token or code that was used, replaced or has expired since.

A link's token is 32 random bytes, base64url-encoded (43 characters), that works once for
`passwords.reset.link_ttl_seconds` (300 to 86400, an hour by default); a reset code is a one-time code of the
`authentication.codes` length, lifetime and attempts. Both live in the codes' table, stored only as a keyed hash, bound
to the guard, the identifier's type and normal form, and their purpose, so a token never checks as a code, a reset code
never signs anyone in, and neither works through another guard. Codes are delivered through your `OneTimeCodeSender`
with the purpose `CodePurpose::PASSWORD_RESET`. Links are delivered through the bound `PasswordResetLinkSender`. The
default, `NotifyingResetLinkSender`, sends Laravel's own `ResetPassword` notification through the identity's
`sendPasswordResetNotification($token)` (`CanResetPassword`), so its `createUrlUsing()` and `toMailUsing()` hooks shape
the link and the mail. That notification links with the identity's email address and no guard, so serve one reset route
per guard; it states the expiry of `auth.passwords.<broker>.expire`, so keep that in step with `link_ttl_seconds`. While
it is bound, a guard whose password identifier is not `email` is refused a link with an `InvalidArgumentException`
before anything is counted (`authentication:check` warns about it), and an identity that does not implement
`CanResetPassword` fails the delivery job with a `LogicException`. Bind your own sender to word the message, carry the
guard or reach another identifier:

```php
use SineMacula\Laravel\Authentication\Contracts\PasswordResetLinkSender;
use SineMacula\Laravel\Authentication\Passwords\PasswordResetLink;

final class ResetLinkMailer implements PasswordResetLinkSender
{
    public function send(PasswordResetLink $message): void
    {
        // $message->token() is in clear: put it only in the link, never in a log.
        $url = url("/{$message->guard}/password/reset?token={$message->token()}&{$message->type}=" . urlencode($message->identifier));

        Mail::to($message->identifier)->send(new ResetLinkMail($url, $message->expiresAt));
    }
}

$this->app->singleton(PasswordResetLinkSender::class, ResetLinkMailer::class);
```

`reset($input, ?ClientContext $client = null)` takes the identifier under the guard's password identifier, the `token`
and the new `password`; `resetWithCode($type, $input)` the identifier under `$type`, the `code` and the `password`. The
identifier as given and the IP address are counted under the `password_reset` limits before anything else, so a flood of
guesses never reaches the hasher or your breached-password checker; a reset that succeeds gives its slots back. The rest
runs inside the guard's credential timebox (see [Credential validation timing](#credential-validation-timing)): a
missing or malformed identifier, token, code or password is `invalid`; a password the policy rejects is
`password_rejected` with its violations, and spends nothing; then the identity is looked up and, in one transaction, the
token or code is checked whatever the identity, a code counting its attempt as a sign-in does. The transaction locks the
identity's row before it touches the proof, as a password change does, so a reset and a change of the password or of an
identifier racing on one identity wait for each other instead of failing. A refused proof is `invalid` (an expired or
exhausted one included) and its attempt stays counted; a proof accepted for no identity, or one the job would not have
sent to, is `invalid` and stays unspent; a proof accepted for an eligible identity is spent with the new password in the
same transaction, set as `set()` sets it with `PasswordFlow::RESET` (see [Setting a password](#setting-a-password)):
every session of the identity ended, its cutoff moved, its pending sign-ins and identifier changes ended, every other
reset link and code and every sign-in code for its identifiers invalidated, through every guard whose provider returns
it, and `PasswordSet` reported once that commits. Only a reset returns before the timebox ends. The result is a
`ResetResult`: `reset` with how many devices were `revoked`, `invalid`, `rate_limited` with `retryAfter`, or
`password_rejected` with `violations`. `AuthenticationFailed` (flow `password_reset`) says why a reset failed:
`rate_limited`, `invalid_credentials`, `code_expired`, `code_exhausted`, `link_expired`, `machine_identity`,
`identity_inactive` or `identifier_unverified`; the result never does. A reset signs no one in and verifies no
identifier.

Spending the proof with the password and the revocation needs one transaction, so the identity must live on the device
model's connection (which the codes' table shares): a guard whose provider's model is on another throws a
`LogicException` naming both connections from a request for a link or code and from a reset, before anything is counted
or issued, and `authentication:check` warns about it. A provider whose configuration names no model (a custom
`Auth::provider()` driver) cannot be checked in advance: its identity is checked once a reset's proof is accepted, so
only someone holding a valid link or code ever sees the refusal, and the proof stays unspent. Of two
resets with one token or code exactly one resets; a reset that loses to a newer link or code is `invalid`; and any
failure after the proof is accepted (or a transaction of yours rolled back around the call) undoes the proof, the
password, the cutoff and the revocations together.

The package does not use Laravel's password broker, and does not dispatch Laravel's `PasswordReset` event (in Laravel
that is your controller's). The broker answers differently for an unknown address, sends inline, can spend one token
twice, reads its tokens from a replica, keys tokens by email address only and limits per address only; adapting it would
mean replacing every behaviour it has (see `docs/design/passwords.md`). If you keep Laravel's broker instead,
`RevokeDevicesOnPasswordReset` still answers its `PasswordReset`; do not combine the two flows.

## Changing identifiers

`Auth::identifierChanges($guard)` changes an identity's email address or phone number once the new one is proven, and
keeps the current one until then. A change is requested, then confirmed by a one-time code sent to the new identifier or
by a signed link the application sends there; the confirmation replaces the identifier, records the new one as
verified, and tells the old one. The application owns the routes, the messages and their delivery.

The identity implements `HasChangeableIdentifiers` (it extends `HasVerifiableIdentifiers`); the
`ProvidesIdentifierVerification` trait already implements it from the identifier's column and `<type>_verified_at`, so
the model only declares it. The application binds an `IdentifierChangeNotifier`, which tells the old identifier: no
change is requested or confirmed while none is bound. The notice says whether the old identifier was verified when the
change was requested (`previousVerified`): one never verified, such as an address mistyped at registration, may belong
to a stranger, whom a notice would tell that the account exists and, if it named the new identifier, where its owner
now is. The package queues the notice either way and leaves that choice to the notifier; the one below sends nothing to
an unverified address and names only part of the new one.

```php
use Illuminate\Support\Str;
use SineMacula\Laravel\Authentication\Contracts\HasChangeableIdentifiers;
use SineMacula\Laravel\Authentication\Contracts\IdentifierChangeNotifier;
use SineMacula\Laravel\Authentication\IdentifierChanges\IdentifierChangeNotice;

class User extends Model implements HasChangeableIdentifiers, Identity, Principal
{
    use ActsAsPrincipal, Authenticatable, ProvidesIdentifierVerification;
}

final class MailIdentifierChangeNotifier implements IdentifierChangeNotifier
{
    public function notify(IdentifierChangeNotice $notice): void
    {
        // Never verified, the old address may be a stranger's: tell it nothing.
        if (!$notice->previousVerified) {
            return;
        }

        // $notice->previous is the destination; name only part of the new address.
        Mail::to($notice->previous)->send(new EmailAddressChanged(Str::mask($notice->identifier, '*', 2, -6), $notice->changedAt));
    }
}

// In a service provider's register():
$this->app->singleton(IdentifierChangeNotifier::class, MailIdentifierChangeNotifier::class);
```

**Uniqueness.** Give the identifier's column a unique index on the stored, normalised value (the `NormalisedIdentifier`
cast stores it so; see [Identifiers](#identifiers)), and a composite one with the tenant's key for identifiers unique per
tenant. A confirmation checks first that the guard's identity provider finds no other identity holding the new
identifier, but only the index decides a race between two confirmations of one value: the one that loses is refused as
`taken`, inside a savepoint, so the change, its proof and any transaction you hold stay usable. Without the index the
check is best effort and a race can leave two identities with one identifier.

**Recent authentication.** A request carries a `Sessions\Reauthentication`, the proof that the identity authenticated
recently: within `identifier_changes.recent_authentication_seconds` (900 by default), from the second it names, and
never from the future.

- `Reauthentication::device($device)`: the session the change is made from. Read again on the write connection, it
  must be one of the identity's own live sessions of the guard (not revoked, deadlines not passed), signed in within
  the window. A refresh or a principal switch does not renew it; a fresh sign-in does.
- `Reauthentication::password($password)`: the identity's current password, checked in the guard's credential timebox
  against the identity read again through the guard's provider. It counts against the identity's account and the IP
  address under the `sign_in` limits, and a correct one is given back. A guard whose audience does not allow the
  `password` method takes no password as proof (`reauthentication_required`, nothing counted).
- `Reauthentication::confirmedAt($at)`: a further factor, or another proof your code verified, at `$at`. It is trusted,
  as `start()` is: never build it from a time the client sent.

An identity that signs in only with codes or passkeys reauthenticates by signing in again on the device it changes from.
A token with no device (in [access-only mode](#access-only-mode-no-devices-no-refresh), or any access token without a
`did`) has no session to offer, so `Auth::device()` is `null` there and the request must ask for another proof. The
first route below takes the password whenever one is sent, so a session signed in longer ago than the window can
confirm it instead of signing in again, and the device's recent sign-in otherwise.

**Requesting.** `requestByCode()` sends a code to the new identifier, delivered after commit by a queued job through
your `OneTimeCodeSender` with the purpose `change_identifier` (the message's `identifier` is the new one);
`requestByLink()` signs a link to your named route instead, which `link()` returns for you to send to the new identifier
(and only there: never return it to the client). The new identifier must be one the type's normaliser accepts and not the
current one; whether another identity holds it is not checked here, so the answer says nothing about it. Requests are
limited by `rate_limits.identifier_change`, counted on the new identifier, on the identity and on the IP address.

```php
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\IdentifierChanges\Enums\IdentifierChangeRequestStatus;
use SineMacula\Laravel\Authentication\Sessions\Reauthentication;

Route::middleware('auth:api')->post('/email/change', function (Request $request) {
    $input  = $request->validate(['email' => ['required', 'email'], 'password' => ['nullable', 'string']]);
    $device = Auth::device();
    $proof  = match (true) {
        isset($input['password']) => Reauthentication::password($input['password']),
        $device !== null          => Reauthentication::device($device),
        default                   => null,
    };

    if ($proof === null) {
        return response()->json(['message' => 'Confirm your password.'], 403);
    }

    $result = Auth::identifierChanges('api')->requestByCode(Auth::identity(), 'email', $input['email'], $proof);

    return match ($result->status) {
        IdentifierChangeRequestStatus::SENT                      => response()->json(['expires_at' => $result->expiresAt->toIso8601String()], 202),
        IdentifierChangeRequestStatus::RATE_LIMITED              => response()->json([], 429, ['Retry-After' => $result->retryAfter]),
        IdentifierChangeRequestStatus::REAUTHENTICATION_REQUIRED => response()->json(['message' => 'Confirm your password, or sign in again.'], 403),
        IdentifierChangeRequestStatus::IDENTIFIER_INVALID,
        IdentifierChangeRequestStatus::IDENTIFIER_UNCHANGED      => response()->json(['message' => 'Enter a new email address.'], 422),
    };
});

Route::middleware('auth:api')->post('/email/change/link', function (Request $request) {
    $input  = $request->validate(['email' => ['required', 'email'], 'password' => ['required', 'string']]);
    $result = Auth::identifierChanges('api')->requestByLink(Auth::identity(), 'email', $input['email'], Reauthentication::password($input['password']), 'email.change.confirm');

    if ($result->isSent()) {
        Mail::to($input['email'])->send(new ConfirmNewEmailAddress($result->link()));
    }

    return response()->json(['status' => $result->status->value], $result->isSent() ? 202 : 422);
});
```

| Status                      | When                                                                                                  |
|-----------------------------|-------------------------------------------------------------------------------------------------------|
| `sent`                      | The change waits for its proof until `expiresAt`                                                      |
| `rate_limited`              | The `identifier_change` limits, or a password proof's `sign_in` limits, are used up                   |
| `reauthentication_required` | The proof shows no recent authentication, the password is wrong, or the guard does not take passwords |
| `identifier_invalid`        | The type's normaliser rejects the new identifier                                                      |
| `identifier_unchanged`      | The new identifier, in its normal form, is the identity's current one                                 |

One change waits per identity and type, in `identifier_changes.table`: a newer request, through any guard, replaces it,
so the code and the link of an earlier one stop working at once. It waits `identifier_changes.ttl_seconds` (3600 by
default), and a change proven by code no longer than its code works (`codes.ttl_seconds`). `pending($identity, $type)`
reports the change waiting through this guard (its new identifier and times) and `cancel($identity, $type)` drops it.
Ending the identity's sessions in bulk drops every change it has waiting, of each type and through each guard, in the
same transaction: `signOutEverywhere()`, `revokeDevices()` and the security-change methods that end an identity's
sessions (see [Revoking on security changes](#revoking-on-security-changes)), so also a change or a reset of the
password through `Auth::passwords()->set()`, a reset by link or code, and the listeners that call them. A link needs no
session, so one requested from a session that ended could otherwise still move the account to an address of the
requester's. Revoking one device, ending a principal's sessions and a registration keep them.
Prune expired changes with `php artisan model:prune --model="SineMacula\Laravel\Authentication\Models\IdentifierChange"`.

**Confirming.** `confirmByCode($identity, $type, $code)` takes the code; `confirmByLink($request)` takes the request to
the link's address, which needs no session (the link names the identity, signed). Each acts only on a change requested
through the same guard. Let the link's `GET` only show a confirmation, and confirm from its form: mail scanners and link
previews fetch links no one clicked, and a change confirmed by such a fetch (a mistyped address that reaches a
stranger's scanned mailbox, say) would make the stranger's address the one password resets go to. The form posts back
to the same signed address, query included, and `confirmByLink()` reads the signature from it. Neither confirms a
change for an identity that is not active (`CanBeActive`, see [Active-state enforcement](#active-state-enforcement)):
the link needs no session, so no guard has checked it, and an account suspended after the request keeps its identifier.
The answer is `invalid`, reported as `identity_inactive`, before anything is counted.

```php
use SineMacula\Laravel\Authentication\IdentifierChanges\Enums\IdentifierChangeOutcome;

Route::middleware('auth:api')->post('/email/change/confirm', function (Request $request) {
    $input = $request->validate(['code' => ['required', 'string']]);

    return match (Auth::identifierChanges('api')->confirmByCode(Auth::identity(), 'email', $input['code'])) {
        IdentifierChangeOutcome::CHANGED => response()->noContent(),
        IdentifierChangeOutcome::TAKEN   => response()->json(['message' => 'That address is in use.'], 409),
        default                          => response()->json(['message' => 'That code does not work.'], 422),
    };
});

Route::get('/email/change/link/confirm', function (Request $request) {
    // A page whose form posts to $request->fullUrl(), so following the link changes nothing by itself.
    return view('email.confirm-change', ['action' => $request->fullUrl()]);
})->name('email.change.confirm');

Route::post('/email/change/link/confirm', function (Request $request) {
    return Auth::identifierChanges('api')->confirmByLink($request) === IdentifierChangeOutcome::CHANGED
        ? response()->noContent()
        : abort(403);
});
```

| Outcome     | When                                                                                                                                      |
|-------------|-------------------------------------------------------------------------------------------------------------------------------------------|
| `changed`   | The identifier was replaced by the new one, recorded as verified                                                                          |
| `invalid`   | No change of this guard waits, a newer request or another confirmation won, the proof does not match, or the identifier changed meanwhile |
| `expired`   | The change, its code or its link has expired                                                                                              |
| `exhausted` | The code used up its attempts; request the change again                                                                                   |
| `taken`     | Another identity holds the new identifier; the proof is not used up                                                                       |

A confirmation locks the identity's row, reads the change, checks the proof and makes the change in one transaction on
the identity's connection (the row lock comes first, as in a password change or reset, so they wait for each other), so
the identity must be stored on the device model's connection, where the codes and the pending changes are kept: as for a
password reset, any other identity throws a `LogicException` naming both connections before anything is counted, and
`authentication:check` warns about its guard. A wrong code's attempt is kept; a change refused once its proof is
accepted (`taken`, an identifier changed meanwhile, a database error, or a transaction you roll back) rolls back whole,
so the proof is not spent. The same transaction invalidates, for every `jwt` guard whose provider returns the identity
and for both the old identifier and the new one, the sign-in, password reset and reset link codes waiting for it, and
the identity's verification codes; a verification link for the old identifier stops working by itself, since it carries
that identifier's digest. A guard whose provider reads another table binds its codes to the identities there, which keep
them.

Once the change commits, `IdentifierChanged` is dispatched and, when the identity had an identifier of the type, the
notice to the old one is queued on the delivery queue (`delivery.queue`). The change stands if the notice fails: the job
fails and the queue's retries apply. The new identifier was proven and the request recently authenticated, so rolling
the change back on a mail outage would block the owner while protecting nothing the proof did not. The identity's
sessions are not revoked: changing an identifier is not a security change of its own; end them with `signOutEverywhere()`
if your application wants that.

Every refusal is reported by `AuthenticationFailed` on the `identifier_change` flow, not concealed, since the caller
holds the identity: `reauthentication_required`, `rate_limited` (with `retryAfter`), `invalid_credentials`,
`code_expired`, `link_expired`, `code_exhausted` or `identifier_taken`; a request's event carries the new identifier as
given. `IdentifierChangeRequested` (type, new identifier, expiry) and `IdentifierChanged` (type, previous and new
identifiers, time) carry the identifiers as strings, so a queued audit listener needs no query back. A machine identity
has no identifiers to change, so every method throws an `InvalidArgumentException` for one; an identity that is not an
Eloquent model implementing `HasChangeableIdentifiers`, a type with no registered normaliser, malformed settings, an
unbound notifier or a link route whose parameters or placeholders take a name the link sets (`guard`, `identity`, `type`,
`purpose`, `request`, `hash`, `expires`, `signature`) throw before anything is counted or written, and
`authentication:check` reports the settings (`[identifier_changes]`).

## Machine credentials

### Non-human identities

An API client or a service account is an identity of its own type: implement `Contracts\MachineIdentity` on its model
(a marker that extends `Identity`). A non-human identity has no password, no interactive sign-in, no device and no
refresh; it authenticates only with a credential issued to it, each bound to one principal in one tenant. The package
enforces this at every entry point that verifies something:

| Entry point                                                        | A non-human identity is                                      |
|--------------------------------------------------------------------|--------------------------------------------------------------|
| A password check (`signIn('password')`, `attempt()`, `validate()`) | refused as `invalid_credentials`, no hash computed, no count |
| Any other sign-in method, `start()`, `complete()`, `choose()`      | refused at admission as `machine_identity`                   |
| A refresh or a switch of principal on a device it owns             | refused as `machine_identity`                                |
| A session's access token (`jwt` guard) naming it                   | refused as `machine_identity`                                |
| `Auth::jwt()->issueAccessToken()` / `issueRefreshToken()`          | refused with a `LogicException`                              |
| An `api_key` guard's `attempt()`                                   | refused as `method_not_allowed`: machines do not sign in     |
| A one-time code for sign-in                                        | never delivered; one it holds anyway is refused at admission |
| `Auth::codes()->sendVerification()` / `verify()`                   | refused with an `InvalidArgumentException`                   |
| Registering, listing or removing passkeys, or a passkey factor     | refused with an `InvalidArgumentException`: it holds none    |
| `Auth::identifierChanges()`, every method                          | refused with an `InvalidArgumentException`: it has none      |

The trusted binds stay trusted: `login()`, `setUser()` and `authenticateAs()` (and so Laravel's `actingAs()` in tests)
bind a machine as given, limited to no scope (`Auth::scopes()` is `[]`), since the caller has proven it;
`authenticateAs()` limits it to the scopes it is given instead, when it is given some.

### Credential scopes

A credential issued to a machine (an API key, or the access token a client credentials exchange hands out) carries
scopes: the most its bearer may do. The package carries them and never interprets them. A scope is an opaque string
(`invoices:read`, `https://api.example.test/reports`), an RFC 6749 scope token: printable ASCII other than space, `"`
and `\`, at most 255 bytes, kept as an ordered list without duplicates and written as one space-separated string in a
token's `scope` claim. That string may be at most 8,192 bytes: a longer list is refused with an `InvalidScopeException`
when the key is issued, so it is always stored whole. A client credentials token carries the list in its claims, so one
granting a long list can outgrow a proxy's limit on a request header line (8 KB under nginx's and Apache's defaults,
which a token reaches once its list passes about 5,800 bytes); keep the scopes a client asks for short, or raise that
limit. Scopes are a ceiling, never a permission: authorization computes the principal's permissions and intersects them
with the credential's scopes, so a scope grants nothing the principal could not already do.

`Auth::scopes()` (and `scopes()` on a package guard) reports them for the request:

| The request authenticated with                                   | `Auth::scopes()`         |
|------------------------------------------------------------------|--------------------------|
| A human identity's session token, or a trusted bind of a human   | `null`: no ceiling       |
| An API key, or a client credentials access token                 | the granted list         |
| A non-human identity bound without a credential (`login()`, ...) | `[]`: limited to nothing |
| Nothing, or a guard that is not the package's                    | `null`                   |

`[]` and `null` differ: `[]` is a credential that grants no scope, `null` is no credential limit at all. A
`MachineIdentity` is never left without a ceiling, so binding one through the trusted `login()`, `setUser()` or
`authenticateAs()` (Laravel's `actingAs()` in tests, say) gives it `[]`; `authenticateAs($identity, $principal, $device,
$scopes)` gives it the scopes named instead (a test acting as a machine with scopes, say; see [Testing](#testing)), and
refuses scopes for a human identity with an `InvalidArgumentException`. The scopes are also in every event's context
(`$event->context->scopes`), with the credential's id in `credentialId`.

Scopes are checked when a credential is issued: each must be a well-formed scope token, and the bound
`ScopeRegistry` may reject any of them for the principal on the guard. The default, `AcceptAnyScope`, accepts every
well-formed scope; an authorization package binds its own so keys can only carry scopes that name real permissions:

```php
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\ScopeRegistry;

final class PermissionScopes implements ScopeRegistry
{
    public function rejected(string $guard, Principal $principal, array $scopes): array
    {
        return array_values(array_diff($scopes, Permission::names()));
    }
}

$this->app->singleton(ScopeRegistry::class, PermissionScopes::class);
```

Any answer but `[]` refuses the credential, whatever it names: a scope given (named in the exception), or a pattern or a
form of its own (every scope given is named then). A malformed or rejected scope throws
`Exceptions\InvalidScopeException` (an `InvalidArgumentException`) naming the offending scopes in `$exception->scopes`:
issuing a credential is a trusted, programmatic action, so this is the caller's error, not a failed authentication. A
credential's scopes are fixed for its life.

### API keys

An API key authenticates a non-human identity, a model that implements `Contracts\MachineIdentity`, as one of its
principals on one guard. Issue keys through the guard's key service, `Auth::apiKeys($guard)`, for an `api_key` guard
(whose requests present the key) or a `jwt` guard (whose client credentials exchange takes it, see
[Client credentials](#client-credentials)):

```php
use SineMacula\Laravel\Authentication\Facades\Auth;

$issued = Auth::apiKeys('machine')->issue(
    identity: $client,                 // a MachineIdentity
    principal: $client,                // the principal the key acts as (the client itself in 2D)
    scopes: ['invoices:read'],
    name: 'Billing sync',
    expiresAt: now()->addYear(),       // optional; never expires without it
);

$issued->key();    // ak_k3j9x0m2p8q4r7t1_9fJ2kL8mN3pQ7rS1tV5wX0yZ4aB6cD8eF2gH4iJ6 - show it once
$issued->summary;  // ApiKeySummary: id, public id, guard, name, scopes, expiry, last use, rotation, revocation
```

A key is `<prefix>_<public>_<secret>`: the configured prefix (`ak` by default), 16 random lower-case letters or digits,
and a 40-character random secret. Only `<prefix>_<public>` (the summary's `publicId`) and the SHA-256 digest of the
secret are stored, so the key is shown once and cannot be shown again; a secret of about 238 bits needs no password hash
to resist guessing. `IssuedApiKey` holds the key as a `SensitiveParameterValue`, so no dump of it (`dump()`, `print_r`,
`var_export`) shows the key, and serialising it throws. The principal must be one the identity acts as on the guard
(resolved through the guard's principal resolver, as a pinned principal is) and one the guard's audience admits; the key
records the identity, the principal and the principal's tenant, each by type and identifier, and the guard, and
authenticates only as them, on that guard. A tenant's type is its morph class, or its class name when it is not an
Eloquent model, so a tenant of another type that shares the identifier is not the recorded one. A malformed or past
expiry, a principal the identity does not act as or the audience does not admit, a name that is empty, longer than 255
characters, not valid UTF-8 or holds a NUL byte, and a malformed or rejected scope (see
[Credential scopes](#credential-scopes)) are each an `InvalidArgumentException`: issuing is a trusted, programmatic
action.

A request presents the key as a bearer credential, `Authorization: Bearer <key>`, on a route the guard protects
(`auth:machine`). The guard reads the key's public part with one indexed lookup on the write connection, compares the
digest of the secret in constant time, and then requires, in order:

| Check                                                                         | Failure reason              |
|-------------------------------------------------------------------------------|-----------------------------|
| the key is in form, its public part names a key, and the secret is that key's | `credential_invalid`        |
| the key was issued for this guard                                             | `credential_guard_mismatch` |
| it is not revoked                                                             | `credential_revoked`        |
| it has not expired (from the second its expiry names)                         | `credential_expired`        |
| the guard's audience lists `api_key` in `methods`                             | `method_not_allowed`        |
| the provider returns exactly the owner the key records                        | `identity_unknown`          |
| the owner is a `MachineIdentity`                                              | `credential_invalid`        |
| the owner is active                                                           | `identity_inactive`         |
| the principal resolves exactly to the one the key records                     | `principal_mismatch`        |
| the principal is active                                                       | `principal_inactive`        |
| its tenant, if any, is active                                                 | `tenant_inactive`           |
| the principal and its tenant are, by type and identifier, the ones recorded   | `principal_mismatch`        |
| the guard's audience admits the principal                                     | `principal_ineligible`      |

A malformed key, an unknown public part and a wrong secret are refused alike, and an unknown public part is compared
against a fixed digest so it costs the same as a wrong secret. A refused key dispatches one `AuthenticationFailed` (flow
`api_key`, naming the key once one was found) and nothing else; an accepted key binds the owner and principal with the
key's scopes (`Auth::scopes()`) as an authentication, not a sign-in: only `Authenticated` and `PrincipalAssigned` fire,
with method `api_key`, the key's id in `credentialId` and its scopes. Keys carry no device and no refresh. The key's
last use is recorded at most once per `last_used_throttle_seconds`, with one conditional update. The guard counts no
attempts: a secret this long cannot be guessed, and a write per refused request would cost the hot path more than it
protects, so throttle the routes for that. A machine has no interactive sign-in: the guard's `attempt()` always fails
(`method_not_allowed`) and checks nothing. `Auth::guard('machine')->validate(['api_key' => $key])` says whether a key
would authenticate, binding and dispatching nothing.

Every other operation names the principal the key must belong to, and treats a key of another principal or guard as
absent, even one whose guard, type or identifier the column's collation counts as equal (`alice` and `Alice` under
MySQL's default `_ci` collations). These are privileged operations: authorise your caller to manage that principal's
keys first, since the package decides no permission.

```php
$keys = Auth::apiKeys('machine');

$keys->keys($principal);                       // list<ApiKeySummary>, newest first, revoked and rotated included
$keys->find($principal, $keyId);               // ?ApiKeySummary
$keys->revoke($principal, $keyId);             // whether this call revoked it; it stops working at once
$keys->rotate($principal, $keyId, overlapSeconds: 3600, expiresAt: now()->addYear()); // ?IssuedApiKey
```

A summary is safe to return from a route as it is: `toArray()` and its JSON use snake_case keys and ISO-8601 times, and
neither holds the secret or its digest.

Rotating issues a replacement with the same guard, owner, principal, tenant, name and scopes (held to the scope registry
again), but not the same expiry: the replacement expires at the `expiresAt` you pass, and never without one, so pass it
when you rotate a key that expires, or the replacement will not. The rotation ends the replaced key once the overlap
passes (`rotation_overlap_seconds` by default, at most `max_rotation_overlap_seconds`), or at its own expiry when that
comes sooner; both keys work during the overlap, and the replaced one then fails as `credential_expired`. Only a live
key that has not been rotated rotates: `null` otherwise, and of two concurrent rotations only one replaces the key. A
key's scopes are fixed for its life; to change them, issue a new key and revoke the old one. `ApiKeyIssued`,
`ApiKeyRotated` (with `previousKeyId`) and `ApiKeyRevoked` report each change once it is committed on the key's own
connection, never the key or its digest.

Schedule pruning of keys revoked or expired more than `prune_after_days` ago:

```php
$schedule->command('model:prune', ['--model' => [\SineMacula\Laravel\Authentication\Models\ApiKey::class]])->daily();
```

### Client credentials

The OAuth 2.0 client credentials grant (RFC 6749 section 4.4) exchanges a machine's API key for a short-lived access
token of a `jwt` guard. The key is issued on that guard (`Auth::apiKeys('m2m')->issue(...)`): its public part is the
OAuth `client_id` and its secret the `client_secret`, so a key is either presented to an `api_key` guard or exchanged on
a `jwt` guard, never both, and rotating a key gives its client a new id. The guard's audience lists the grant:

```php
'm2m' => [
    'driver'   => 'jwt',
    'provider' => 'clients',
    'audience' => ['methods' => ['client_credentials']],
],
```

Routes stay yours; the exchange reads the request and answers in RFC 6749's shapes:

```php
use SineMacula\Laravel\Authentication\Facades\Auth;

Route::post('/oauth/token', fn () => Auth::clientCredentials('m2m')->fromRequest());
```

`fromRequest()` reads a form-encoded POST: `grant_type=client_credentials`, an optional `scope` (space-separated), and
the client authenticated with HTTP Basic (`client_id:client_secret`, each form-url-encoded) or with `client_id` and
`client_secret` in the body, never both. A parameter in the query string, given twice or not a string is refused
rather than ignored, so a credential in a URL never works. `exchange($clientId, $clientSecret, $scope)` does the same
for a client id and secret your code read itself. The result is `Responsable`, answered with `Cache-Control: no-store`
and `Pragma: no-cache`, or read with `isGranted()`, `accessToken`, `expiresIn`, `scopes`, `error` and `reason`. Its
`toArray()` and JSON form are the response body alone, so `reason`, which only your code and the event should see, never
reaches a client however you encode the result:

| Outcome                                                                                  | Response                       |
|------------------------------------------------------------------------------------------|--------------------------------|
| Granted                                                                                  | 200, the token (below)         |
| Not a POST or not form-encoded; a parameter in the query, repeated or not a string       | 400 `invalid_request`          |
| No `grant_type`; Basic and body credentials together                                     | 400 `invalid_request`          |
| A `grant_type` other than `client_credentials`                                           | 400 `unsupported_grant_type`   |
| No client authentication, malformed Basic, an unknown client or a wrong secret           | 401 `invalid_client`           |
| A revoked, expired or another guard's key; its owner unknown, not a machine or inactive  | 401 `invalid_client`           |
| Its principal or tenant no longer the key's, or inactive                                 | 401 `invalid_client`           |
| The guard's audience does not list `client_credentials`, or does not admit the principal | 400 `unauthorized_client`      |
| A scope that is malformed or not granted to the key                                      | 400 `invalid_scope`            |
| The IP address (or, when you limit it, the client id) used up its failures               | 429 `slow_down`, `Retry-After` |

A granted response is `{"access_token": "...", "token_type": "Bearer", "expires_in": 900, "scope": "invoices:read"}`,
without `scope` when the token grants none (RFC 6749 has no empty scope value; the token's own `scope` claim is then
`""`); `invalid_client` carries `WWW-Authenticate: Basic` for a client that used Basic. `slow_down` is not an RFC 6749
error but a registered OAuth one (RFC 8628), used because RFC 6749 defines no rate-limit error. Only failures to
authenticate the client count against the `client_credentials` limits (100 per IP address a minute by default), and each
is answered alike. Failures are not counted per client id by default: a client id is not a secret (RFC 6749 section
2.2), so a limit on it would let anyone who knows it hold the real client back from any address, while against a
40-character random secret it protects nothing. Set `rate_limits.client_credentials.per_identifier` only if you accept
that. No scope asks for every scope the key grants; otherwise the token grants exactly those asked for. Every failure
dispatches `AuthenticationFailed` (flow `client_credentials`, the client id when it is a key's public part in form, else
none, so a whole key or a secret sent as the id never reaches a listener, and the key once found) and a grant
`ClientCredentialsGranted`, with the key and the scopes granted.

The token is an access token of the guard with no device, the key's id in `cid` and its scopes in `scope`; it lives
the guard's access lifetime for the principal's type, never past the key's expiry, and no refresh token is issued. On
every request the bearer path reads its key by primary key (one query more than any device-less token) and requires it
to be the guard's (`credential_invalid`), not revoked (`credential_revoked`) and not expired (`credential_expired`);
the subject must be a machine (`credential_invalid`), and the key's owner, principal and tenant must still be what
loaded (`principal_mismatch`, `credential_invalid`). Revoking the key, or the end of its rotation's overlap, so ends
its tokens at the next request. A request with such a token binds with method `client_credentials`, the key in
`credentialId` and `Auth::scopes()` the token's scopes.

## Failure outcomes

A refused sign-in, request, refresh or exchange is a result, never an exception: the caller gets what the flow's API
returns, and `AuthenticationFailed` reports it with the flow (`$event->flow`), a `FailureReason` (`$event->reason`) and
the context. Exceptions are for misconfiguration (an `InvalidArgumentException` or a `LogicException` naming the setting
or the model) and for server errors, such as a database error, which propagate. What each flow answers, and the
reasons its event can carry (each reason's meaning is in [Events](#events)):

| Flow                      | Entry points                                                                                          | The caller sees                                                                                                                                                                                                                                                                                                                                                                          | Reasons on the event                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
|---------------------------|-------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `sign_in`                 | `attempt()`; `Auth::sessions()->signIn()`, `start()`, `complete()`, `choose()`, `discard()`           | `attempt()`: `false`. The session service: a `SignInResult` whose `isFailed()`, `reason` and, for `rate_limited`, `retryAfter` say why; `discard()`: whether it discarded a pending sign-in                                                                                                                                                                                              | `invalid_credentials`, `method_not_allowed`, `rate_limited`, `identity_unknown`, `identity_inactive`, `machine_identity`, `principal_unresolved`, `principal_mismatch`, `principal_inactive`, `tenant_inactive`, `principal_ineligible`, `identifier_unverified`, `device_mismatch` and `additional_factor_required` (`attempt()`), `additional_factor_failed`, `principal_choice_abandoned`, `pending_invalid`, `passkey_challenge_invalid`; on the event only: `account_rate_limited`, `code_expired`, `code_exhausted`, `passkey_counter_regressed` |
| `bearer`                  | A request through `auth:<jwt guard>`, or `Auth::user()` and the accessors on one                      | `401 {"message": "Unauthenticated."}` from the `auth` middleware; `Auth::user()` is `null`                                                                                                                                                                                                                                                                                               | `token_invalid`, `credential_invalid`, `credential_revoked` and `credential_expired` (a client credentials token), `identity_unknown`, `machine_identity`, `identity_inactive`, `principal_mismatch`, `principal_inactive`, `tenant_inactive`, `issued_before_cutoff` (a token without a device), `device_unknown`, `device_guard_mismatch`, `device_revoked`, `session_expired`, `device_principal_mismatch`                                                                                                                                          |
| `refresh`                 | `refreshFromRequest()`, `refresh()`                                                                   | `refreshFromRequest()`: the `FailureReason` (`null` when the request carries no token); `refresh()`: `null`; `rate_limited`: a `ThrottleRequestsException`, 429 with `Retry-After`                                                                                                                                                                                                       | `token_invalid`, `refresh_token_conflict`, `cross_site_request`, `rate_limited`, `device_unknown`, `device_guard_mismatch`, `device_revoked`, `session_expired`, `refresh_key_missing`, `rotation_reuse` (the device is revoked), `rotation_conflict`, `device_principal_mismatch`, `identity_unknown`, `machine_identity`, `identity_inactive`, `principal_unresolved`, `principal_mismatch`, `principal_inactive`, `tenant_inactive`, `method_not_allowed`, `principal_ineligible`                                                                   |
| `principal_switch`        | `Auth::sessions()->switchPrincipalFromRequest()`, `switchPrincipal()`                                 | A `SwitchResult` whose `isFailed()`, `reason` and, for `rate_limited`, `retryAfter` say why (`null` from `switchPrincipalFromRequest()` when the request carries no token)                                                                                                                                                                                                               | Those of `refresh`, with `rate_limited` returned rather than thrown, and `additional_factor_required`                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| `api_key`                 | A request through `auth:<api_key guard>`                                                              | `401 {"message": "Unauthenticated."}` from the `auth` middleware; the guard's `attempt()` is `false` and reports `method_not_allowed` on the `sign_in` flow                                                                                                                                                                                                                              | `credential_invalid`, `credential_guard_mismatch`, `credential_revoked`, `credential_expired`, `method_not_allowed`, `identity_unknown`, `identity_inactive`, `principal_mismatch`, `principal_inactive`, `tenant_inactive`, `principal_ineligible`                                                                                                                                                                                                                                                                                                    |
| `client_credentials`      | `Auth::clientCredentials()->fromRequest()`, `exchange()`                                              | A `ClientCredentialsResult` answering RFC 6749's `invalid_request`, `unsupported_grant_type`, `invalid_client`, `unauthorized_client`, `invalid_scope`, or `slow_down` (see [Client credentials](#client-credentials))                                                                                                                                                                   | `invalid_credentials` (a request refused before a client was found), `method_not_allowed`, `rate_limited`, every reason of `api_key`, `scope_invalid`                                                                                                                                                                                                                                                                                                                                                                                                  |
| `code_request`            | `Auth::codes()->send()`, `sendVerification()`                                                         | A `CodeRequest` whose `status` is `sent`, `rate_limited` (with `retryAfter`), `method_not_allowed` or `identifier_invalid`; the same for an identifier no one holds                                                                                                                                                                                                                      | `method_not_allowed` (`send()`), `invalid_credentials` (the result's `identifier_invalid`), `rate_limited`                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| `identifier_verification` | `Auth::codes()->verify()`                                                                             | The `FailureReason` itself, since the caller holds the identity, or `IdentifierVerification::MISMATCH` when the identifier changed meanwhile (nothing reported)                                                                                                                                                                                                                          | `invalid_credentials`, `code_expired`, `code_exhausted`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| `password_reset`          | `Auth::passwords()->sendResetLink()`, `sendResetCode()`, `reset()`, `resetWithCode()`                 | A request: a `CodeRequest` as for a code (`sent`, `rate_limited` with `retryAfter`, `method_not_allowed`, `identifier_invalid`), the same for an identifier no one holds. A reset: a `ResetResult` whose `status` is `reset`, `invalid`, `rate_limited` (with `retryAfter`) or `password_rejected` (with the `violations`, reported by no event) (see [Password reset](#password-reset)) | A request: `method_not_allowed`, `invalid_credentials` (the result's `identifier_invalid`), `rate_limited`. A reset: `rate_limited`, `invalid_credentials`, `machine_identity`, `identity_inactive`, `identifier_unverified`; on the event only: `code_expired`, `code_exhausted`, `link_expired`                                                                                                                                                                                                                                                      |
| `identifier_change`       | `Auth::identifierChanges()->requestByCode()`, `requestByLink()`, `confirmByCode()`, `confirmByLink()` | A request: an `IdentifierChangeRequest` whose `status` is `sent`, `rate_limited` (with `retryAfter`), `reauthentication_required`, `identifier_invalid` or `identifier_unchanged`. A confirmation: an `IdentifierChangeOutcome`, `changed`, `invalid`, `expired`, `exhausted` or `taken` (see [Changing identifiers](#changing-identifiers))                                             | `reauthentication_required`, `rate_limited`, `invalid_credentials` (an invalid or unchanged identifier, a wrong code or link, a change replaced or lost), `code_expired`, `link_expired`, `code_exhausted`, `identifier_taken`, `identity_inactive` (a confirmation for an identity that is not active), none of them concealed                                                                                                                                                                                                                        |

The concealed reasons (`FailureReason::isConcealed()`: `account_rate_limited`, `code_expired`, `code_exhausted`,
`link_expired` and `passkey_counter_regressed`) reach only the event in a sign-in and a password reset: their results
say `invalid_credentials` and `invalid`, with no wait, so the answer reveals neither that an account exists nor that a
code or link was requested for it. The flows whose caller already holds the identity, verification by code and an
identifier change, tell the caller (`code_expired`, an `expired` or `exhausted` outcome). A sign-in method may answer
only `invalid_credentials`, `identifier_unverified`, `code_expired`, `code_exhausted`, `passkey_challenge_invalid` and
`passkey_counter_regressed` (`FailureReason::isSignInMethodReason()`); every other reason is the session service's to
give.

## Suite integration

The package authenticates; its siblings decide everything else, each through a seam here, and none is required. Every
seam has a default that works alone.

### Further factors (`laravel-mfa`)

- Bind `Contracts\AdditionalFactorPolicy` (the default, `NeverRequireAdditionalFactor`, never asks). It is asked about
  every admitted sign-in, from `signIn()` and `start()`, and again on a switch of principal, with the guard, identity,
  principal, tenant, method, client and the device the client proved (see [Additional factors](#additional-factors)).
- When it asks for a factor, the sign-in waits: `SignInResult::requiresFactor()` and its `PendingFactor` token, then
  `Auth::sessions()->pending()`, `complete()` or `discard()` once the factor is verified or fails. `attempt()` cannot
  wait, so it fails as `additional_factor_required`.
- A factor removed ends the identity's other sessions: `Auth::sessions()->factorRemoved($identity, Auth::device())`.
- Passkeys verify as a factor through `Auth::passkeys()->factorOptions($identity)` and `verifyFactor()`, which count and
  report nothing: the factor's outcome is the factor package's to limit and report.
- Factor state is the factor package's, keyed by the device id (`Auth::device()?->getDeviceIdentifier()`, the `did`
  every session token carries); the device records none.
- A factor the factor package has just verified proves a recent authentication before an identifier change:
  `Reauthentication::confirmedAt($verifiedAt)` (see [Changing identifiers](#changing-identifiers)).
- When every sign-in requires a further factor, a password is no longer the only factor, and `passwords.min_length`
  may be lowered from 15 to 8, as NIST SP 800-63B allows (see [Password policy](#password-policy)).

### Authorization (`laravel-authorization`)

- `Auth::principal()`, `Auth::tenant()` and `Auth::type()` are the subject an authorization decision is about.
- `Auth::scopes()` is the ceiling the request's credential grants: `null` for a human's session, which no credential
  limits, the granted list for an API key or a client credentials token, and `[]` for a machine bound without one.
  Intersect the principal's permissions with it; a scope never grants anything by itself (see
  [Credential scopes](#credential-scopes)).
- Bind `Contracts\ScopeRegistry` to hold the scopes a credential is issued with to real permissions (the default,
  `AcceptAnyScope`, accepts any well-formed scope).

### Single sign-on (`laravel-sso`)

- When the identity provider's callback has proven the identity, start the session with
  `Auth::sessions($guard)->start($identity, $principal, 'sso', $context)`: the guard's audience must list the method
  name, the identity is reloaded through the guard's provider, activity, the audience policy and the additional-factor
  policy all apply, and no attempt limit or timebox does, since nothing is guessed. No registration is needed.
- For an assertion the package should verify itself, implement `Contracts\SignInMethod`, register it with
  `SignInMethodManager::extend()` and sign in through `signIn()`, which adds the limits and the timebox (see
  [Writing a sign-in method](#writing-a-sign-in-method)).
- Either way the device records the method, so the guard's audience can stop allowing it and its sessions stop
  refreshing.

### Audit (`laravel-audit-log`)

- Every package event implements `Contracts\AuthenticationEvent` and carries one `Events\EventContext`, so one listener
  records them all: the guard, the client, snapshots of the identity, principal, tenant and device identifiers, the
  method, and the credential and its scopes, never a secret (see [Events](#events)).
- Events that report a write are dispatched once it commits on the written row's connection, and never for a rolled-back
  one, so a queued audit listener records only what happened.

## Configuration

The package's settings live in the published `config/authentication.php`, under `authentication.`. A guard overrides
the ones marked per guard in its own `config/auth.php` entry, in a block named after the first part of the key (`jwt`,
`audience`, `rate_limits`, `refresh_token`, `passkeys` for the relying party, and `sign_in` for the password
identifier), where a key it sets wins. A value that is malformed or out of range fails closed, naming the key (and the
guard), when it is first used, and `php artisan authentication:check` reports it before a deploy (see
[Checking the configuration](#checking-the-configuration)).

| Key                                                 | Default                                                                      | Env                                                               | Per guard | See                                                           |
|-----------------------------------------------------|------------------------------------------------------------------------------|-------------------------------------------------------------------|-----------|---------------------------------------------------------------|
| `device.model`                                      | `Device::class`                                                              | `AUTHENTICATION_DEVICE_MODEL`                                     |           | [Device](#device)                                             |
| `device.table`                                      | `devices`                                                                    | `AUTHENTICATION_DEVICE_TABLE`                                     |           | [Device](#device)                                             |
| `device.last_used_throttle_seconds`                 | `60`                                                                         | `AUTHENTICATION_DEVICE_LAST_USED_THROTTLE_SECONDS`                |           | [Device](#device)                                             |
| `device.prune_after_days`                           | `30`                                                                         | `AUTHENTICATION_DEVICE_PRUNE_AFTER_DAYS`                          |           | [Pruning](#pruning)                                           |
| `sign_in.password_identifier`                       | `email`                                                                      | `AUTHENTICATION_SIGN_IN_PASSWORD_IDENTIFIER`                      | yes       | [Sign-in](#sign-in)                                           |
| `sign_in.pending_table`                             | `pending_sign_ins`                                                           | `AUTHENTICATION_SIGN_IN_PENDING_TABLE`                            |           | [Sign-in](#sign-in)                                           |
| `sign_in.pending_ttl_seconds`                       | `300`                                                                        | `AUTHENTICATION_SIGN_IN_PENDING_TTL_SECONDS`                      |           | [Sign-in](#sign-in)                                           |
| `timebox.credentials_microseconds`                  | `400000`                                                                     | `AUTHENTICATION_TIMEBOX_CREDENTIALS_US`                           |           | [Credential validation timing](#credential-validation-timing) |
| `events.redacted_credential_keys`                   | `[]`                                                                         |                                                                   |           | [Events](#events)                                             |
| `jwt.keys`                                          | `['default' => env('AUTHENTICATION_JWT_KEY')]`                               |                                                                   | yes       | [Key rotation](#key-rotation)                                 |
| `jwt.active_kid`                                    | `default`                                                                    | `AUTHENTICATION_JWT_ACTIVE_KID`                                   | yes       | [Key rotation](#key-rotation)                                 |
| `jwt.algorithm`                                     | `HS256`                                                                      | `AUTHENTICATION_JWT_ALGORITHM`                                    | yes       | [Per-guard JWT configuration](#per-guard-jwt-configuration)   |
| `jwt.access_ttl_minutes`                            | `5`                                                                          | `AUTHENTICATION_JWT_ACCESS_TTL_MINUTES`                           | yes       | [Token and session lifetimes](#token-and-session-lifetimes)   |
| `jwt.refresh_idle_ttl_minutes`                      | `129600`                                                                     | `AUTHENTICATION_JWT_REFRESH_IDLE_TTL_MINUTES`                     | yes       | [Token and session lifetimes](#token-and-session-lifetimes)   |
| `jwt.refresh_absolute_ttl_minutes`                  | `259200`                                                                     | `AUTHENTICATION_JWT_REFRESH_ABSOLUTE_TTL_MINUTES`                 | yes       | [Token and session lifetimes](#token-and-session-lifetimes)   |
| `jwt.refresh_grace_seconds`                         | `30`                                                                         | `AUTHENTICATION_JWT_REFRESH_GRACE_SECONDS`                        | yes       | [Refresh token replay](#refresh-token-replay)                 |
| `jwt.leeway_seconds`                                | `30`                                                                         | `AUTHENTICATION_JWT_LEEWAY_SECONDS`                               | yes       | [Token and session lifetimes](#token-and-session-lifetimes)   |
| `jwt.issuer`                                        | `null`                                                                       | `AUTHENTICATION_JWT_ISSUER`                                       | yes       | [Per-guard JWT configuration](#per-guard-jwt-configuration)   |
| `jwt.audience`                                      | `null`                                                                       | `AUTHENTICATION_JWT_AUDIENCE`                                     | yes       | [Per-guard JWT configuration](#per-guard-jwt-configuration)   |
| `audience.methods`                                  | `['password']`                                                               |                                                                   | yes       | [Audiences](#audiences)                                       |
| `audience.principal_types`                          | `null`                                                                       |                                                                   | yes       | [Audiences](#audiences)                                       |
| `audience.require_verified_identifier`              | `false`                                                                      |                                                                   | yes       | [Audiences](#audiences)                                       |
| `identifiers.normalisers`                           | `['email' => EmailNormaliser::class, 'phone' => E164PhoneNormaliser::class]` |                                                                   |           | [Identifiers](#identifiers)                                   |
| `rate_limits.table`                                 | `rate_limits`                                                                | `AUTHENTICATION_RATE_LIMITS_TABLE`                                |           | [Rate limits](#rate-limits)                                   |
| `rate_limits.connection`                            | `null`                                                                       | `AUTHENTICATION_RATE_LIMITS_CONNECTION`                           |           | [Rate limits](#rate-limits)                                   |
| `rate_limits.sign_in.per_identifier`                | 5 per 300 s                                                                  |                                                                   | yes       | [Rate limits](#rate-limits)                                   |
| `rate_limits.sign_in.per_ip`                        | 50 per 300 s                                                                 |                                                                   | yes       | [Rate limits](#rate-limits)                                   |
| `rate_limits.refresh.per_identifier`                | 10 per 60 s                                                                  |                                                                   | yes       | [Rate limits](#rate-limits)                                   |
| `rate_limits.refresh.per_ip`                        | 100 per 60 s                                                                 |                                                                   | yes       | [Rate limits](#rate-limits)                                   |
| `rate_limits.code_request.per_identifier`           | 5 per 3600 s                                                                 |                                                                   | yes       | [Rate limits](#rate-limits)                                   |
| `rate_limits.code_request.per_ip`                   | 50 per 3600 s                                                                |                                                                   | yes       | [Rate limits](#rate-limits)                                   |
| `rate_limits.passkey_options.per_identifier`        | `null`                                                                       |                                                                   | yes       | [Rate limits](#rate-limits)                                   |
| `rate_limits.passkey_options.per_ip`                | 100 per 300 s                                                                |                                                                   | yes       | [Rate limits](#rate-limits)                                   |
| `rate_limits.client_credentials.per_identifier`     | `null`                                                                       |                                                                   | yes       | [Rate limits](#rate-limits)                                   |
| `rate_limits.client_credentials.per_ip`             | 100 per 60 s                                                                 |                                                                   | yes       | [Rate limits](#rate-limits)                                   |
| `rate_limits.password_reset_request.per_identifier` | 5 per 3600 s                                                                 |                                                                   | yes       | [Rate limits](#rate-limits)                                   |
| `rate_limits.password_reset_request.per_ip`         | 50 per 3600 s                                                                |                                                                   | yes       | [Rate limits](#rate-limits)                                   |
| `rate_limits.password_reset.per_identifier`         | 10 per 900 s                                                                 |                                                                   | yes       | [Rate limits](#rate-limits)                                   |
| `rate_limits.password_reset.per_ip`                 | 50 per 900 s                                                                 |                                                                   | yes       | [Rate limits](#rate-limits)                                   |
| `rate_limits.identifier_change.per_identifier`      | 5 per 3600 s                                                                 |                                                                   | yes       | [Rate limits](#rate-limits)                                   |
| `rate_limits.identifier_change.per_ip`              | 50 per 3600 s                                                                |                                                                   | yes       | [Rate limits](#rate-limits)                                   |
| `refresh_token.sources`                             | `['body', 'header']`                                                         |                                                                   | yes       | [Refreshing](#refreshing)                                     |
| `refresh_token.body_field`                          | `refresh_token`                                                              |                                                                   | yes       | [Refreshing](#refreshing)                                     |
| `refresh_token.header`                              | `X-Refresh-Token`                                                            |                                                                   | yes       | [Refreshing](#refreshing)                                     |
| `refresh_token.cookie.name`                         | `__Secure-refresh_token`                                                     |                                                                   | yes       | [Refresh token cookie](#refresh-token-cookie)                 |
| `refresh_token.cookie.path`                         | `null`                                                                       |                                                                   | yes       | [Refresh token cookie](#refresh-token-cookie)                 |
| `refresh_token.cookie.domain`                       | `null`                                                                       |                                                                   | yes       | [Refresh token cookie](#refresh-token-cookie)                 |
| `refresh_token.cookie.allowed_origins`              | `[]`                                                                         |                                                                   | yes       | [Refresh token cookie](#refresh-token-cookie)                 |
| `refresh_token.cookie.csrf_header`                  | `X-Requested-With`                                                           |                                                                   | yes       | [Refresh token cookie](#refresh-token-cookie)                 |
| `api_keys.table`                                    | `api_keys`                                                                   | `AUTHENTICATION_API_KEYS_TABLE`                                   |           | [API key settings](#api-key-settings)                         |
| `api_keys.prefix`                                   | `ak`                                                                         | `AUTHENTICATION_API_KEYS_PREFIX`                                  |           | [API key settings](#api-key-settings)                         |
| `api_keys.rotation_overlap_seconds`                 | `86400`                                                                      | `AUTHENTICATION_API_KEYS_ROTATION_OVERLAP_SECONDS`                |           | [API key settings](#api-key-settings)                         |
| `api_keys.max_rotation_overlap_seconds`             | `604800`                                                                     | `AUTHENTICATION_API_KEYS_MAX_ROTATION_OVERLAP_SECONDS`            |           | [API key settings](#api-key-settings)                         |
| `api_keys.last_used_throttle_seconds`               | `60`                                                                         | `AUTHENTICATION_API_KEYS_LAST_USED_THROTTLE_SECONDS`              |           | [API key settings](#api-key-settings)                         |
| `api_keys.prune_after_days`                         | `30`                                                                         | `AUTHENTICATION_API_KEYS_PRUNE_AFTER_DAYS`                        |           | [API key settings](#api-key-settings)                         |
| `verification.link_ttl_minutes`                     | `60`                                                                         | `AUTHENTICATION_VERIFICATION_LINK_TTL_MINUTES`                    |           | [Identifier verification](#identifier-verification)           |
| `passwords.min_length`                              | `15`                                                                         | `AUTHENTICATION_PASSWORDS_MIN_LENGTH`                             |           | [Password policy](#password-policy)                           |
| `passwords.max_length`                              | `128`                                                                        | `AUTHENTICATION_PASSWORDS_MAX_LENGTH`                             |           | [Password policy](#password-policy)                           |
| `passwords.letters`                                 | `false`                                                                      |                                                                   |           | [Password policy](#password-policy)                           |
| `passwords.mixed_case`                              | `false`                                                                      |                                                                   |           | [Password policy](#password-policy)                           |
| `passwords.numbers`                                 | `false`                                                                      |                                                                   |           | [Password policy](#password-policy)                           |
| `passwords.symbols`                                 | `false`                                                                      |                                                                   |           | [Password policy](#password-policy)                           |
| `passwords.breached.when_unavailable`               | `reject`                                                                     | `AUTHENTICATION_PASSWORDS_BREACHED_WHEN_UNAVAILABLE`              |           | [Password policy](#password-policy)                           |
| `passwords.reset.link_ttl_seconds`                  | `3600`                                                                       | `AUTHENTICATION_PASSWORDS_RESET_LINK_TTL_SECONDS`                 |           | [Password reset](#password-reset)                             |
| `identifier_changes.table`                          | `identifier_changes`                                                         | `AUTHENTICATION_IDENTIFIER_CHANGES_TABLE`                         |           | [Changing identifiers](#changing-identifiers)                 |
| `identifier_changes.ttl_seconds`                    | `3600`                                                                       | `AUTHENTICATION_IDENTIFIER_CHANGES_TTL_SECONDS`                   |           | [Changing identifiers](#changing-identifiers)                 |
| `identifier_changes.recent_authentication_seconds`  | `900`                                                                        | `AUTHENTICATION_IDENTIFIER_CHANGES_RECENT_AUTHENTICATION_SECONDS` |           | [Changing identifiers](#changing-identifiers)                 |
| `codes.table`                                       | `one_time_codes`                                                             | `AUTHENTICATION_CODES_TABLE`                                      |           | [One-time codes](#one-time-codes)                             |
| `codes.key`                                         | `null`                                                                       | `AUTHENTICATION_CODES_KEY`                                        |           | [One-time codes](#one-time-codes)                             |
| `codes.length`                                      | `6`                                                                          | `AUTHENTICATION_CODES_LENGTH`                                     |           | [One-time codes](#one-time-codes)                             |
| `codes.ttl_seconds`                                 | `600`                                                                        | `AUTHENTICATION_CODES_TTL_SECONDS`                                |           | [One-time codes](#one-time-codes)                             |
| `codes.max_attempts`                                | `5`                                                                          | `AUTHENTICATION_CODES_MAX_ATTEMPTS`                               |           | [One-time codes](#one-time-codes)                             |
| `codes.resend_cooldown_seconds`                     | `60`                                                                         | `AUTHENTICATION_CODES_RESEND_COOLDOWN_SECONDS`                    |           | [One-time codes](#one-time-codes)                             |
| `delivery.queue.connection`                         | `null`                                                                       | `AUTHENTICATION_DELIVERY_QUEUE_CONNECTION`                        |           | [One-time codes](#one-time-codes)                             |
| `delivery.queue.name`                               | `null`                                                                       | `AUTHENTICATION_DELIVERY_QUEUE`                                   |           | [One-time codes](#one-time-codes)                             |
| `passkeys.table`                                    | `passkeys`                                                                   | `AUTHENTICATION_PASSKEYS_TABLE`                                   |           | [Passkeys](#passkeys)                                         |
| `passkeys.challenges_table`                         | `passkey_challenges`                                                         | `AUTHENTICATION_PASSKEYS_CHALLENGES_TABLE`                        |           | [Passkeys](#passkeys)                                         |
| `passkeys.challenge_ttl_seconds`                    | `300`                                                                        | `AUTHENTICATION_PASSKEYS_CHALLENGE_TTL_SECONDS`                   |           | [Passkeys](#passkeys)                                         |
| `passkeys.relying_party.id`                         | `null`                                                                       | `AUTHENTICATION_PASSKEYS_RP_ID`                                   | yes       | [Passkeys](#passkeys)                                         |
| `passkeys.relying_party.name`                       | `env('APP_NAME')`                                                            | `APP_NAME`                                                        | yes       | [Passkeys](#passkeys)                                         |
| `passkeys.relying_party.origins`                    | `[]`                                                                         |                                                                   | yes       | [Passkeys](#passkeys)                                         |

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
with `identity_unknown`. Every field in the package `jwt` block is overridable (`keys`, `active_kid`,
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

| Key                           | Default        | Meaning                                                                                                                                                                  |
|-------------------------------|----------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `methods`                     | `['password']` | The sign-in methods that may start the guard's sessions, and the machine credentials (`api_key`, `client_credentials`) it accepts (a non-empty list of lower-case names) |
| `principal_types`             | `null`         | `null` admits any principal; a non-empty list admits only principals of those types                                                                                      |
| `require_verified_identifier` | `false`        | Refuse a sign-in with an identifier the identity has not verified                                                                                                        |

A principal's type is its own or its tenant's (see [Principal type](#principal-type)); with a list, a principal without
a type is refused. The session layer asks the guard before it issues anything: a sign-in with a method the guard does
not list fails with `method_not_allowed`, and a principal whose type it does not admit with `principal_ineligible`, at
sign-in and again on every refresh, so a valid credential for one audience cannot open or keep a session in another.
With `require_verified_identifier`, a sign-in that used an identifier (an email address for the password method) fails
with `identifier_unverified` unless the identity reports that identifier verified (see [Identifier
verification](#identifier-verification)); sign-ins that used no identifier, such as SSO through `start()`, and refreshes
are not gated, since the external provider or the existing session vouches for them. The check is made before any
principal is resolved, so an unverified identifier gets `identifier_unverified` whether or not the identity has a
principal yet, and the answer cannot tell whether it has been invited anywhere. A switch of principal is held to the
identifier type its session's sign-in used, which the device records.

A guard key that is present wins, `null` included, so a guard can admit any principal although the package default
lists types; a guard `audience` entry of `null` means no overrides. Nothing falls back to a literal: a key missing from
both blocks, a value of the wrong shape, an empty list, or a key the policy does not know fails closed with an
`InvalidArgumentException` naming the guard and the key the first time the guard's policy is used. The policy is
`Contracts\AudiencePolicy`, bound to `Audience\GuardAudiencePolicy`; bind your own implementation to decide differently.
Its `admitIdentifier()` is the check every sign-in makes before any principal is resolved, so a policy of your own keeps
the guarantee above only by deciding verification there, for the identity as a whole; one that wraps the package's
policy delegates `admitIdentifier()` to it like the other methods. A refusal from `admit()` comes only once a principal
resolves, so an identity with none would get `principal_unresolved` instead. A policy of your own decides the session's
deadlines through `lifetimes()`, while an access token's lifetime still comes from the guard's `jwt.by_principal_type`
configuration (capped at the session's end). See `docs/design/audience-policy.md` for every point where the policy is
enforced.

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

The published `authentication.php` config controls the device model, table, how often a device's last use is written,
and how long a device whose session ended is kept before pruning:

```php
'device' => [
    'model'                      => SineMacula\Laravel\Authentication\Models\Device::class,
    'table'                      => 'devices',
    'last_used_throttle_seconds' => 60,
    'prune_after_days'           => 30,
],
```

A device is one signed-in session. The shipped migration creates these columns:

| Column                                                 | Holds                                                  |
|--------------------------------------------------------|--------------------------------------------------------|
| `id`                                                   | UUID v7 primary key, carried in every token as `did`   |
| `authenticatable_type`, `authenticatable_id`           | The owning identity (required)                         |
| `principal_type`, `principal_id`                       | The principal the session acts as (any key type)       |
| `principal_switched_at`                                | When the session last switched its principal           |
| `guard`, `sign_in_method`                              | The guard and sign-in method that created it           |
| `sign_in_identifier_type`                              | The type of identifier that sign-in used, if any       |
| `client_name`, `platform`                              | What the client calls itself (`Work laptop`, `macOS`)  |
| `created_ip`, `created_user_agent`                     | The client at sign-in                                  |
| `last_used_at`, `last_used_ip`, `last_used_user_agent` | The client at the last use                             |
| `refresh_key`, `previous_refresh_key`                  | Digests of the current and previous rotation ids       |
| `refresh_rotated_at`                                   | When the current rotation id replaced the previous one |
| `signed_in_at`                                         | When the session started (required)                    |
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
every column when it creates a device (see [Signing in](#signing-in-the-session-service)); `getGuard()`,
`getSignInMethod()` and `getSignInIdentifierType()` read the guard, method and type of identifier it recorded. The
bearer path and refresh honour a device only for the guard it records, refresh only while that guard still allows the
method it records, and a switch of principal admits its target with the identifier type it records (`null` for a
sign-in that used none, which is held to no type), so a device written outside the session service must record all
three.

Subclass the model or swap `device.model` entirely - custom models must implement the `EloquentDevice` contract. A
device's identifier is always its primary key: tokens carry it in `did`, and the bearer path and refresh find the device
by primary key, whatever the key column is called. Other column names come from the contract's accessors
(`getRefreshKeyName()`, `getRevokedAtName()`, and so on); the shipped migration creates the default names, so a model
that renames a column needs its own migration.

A device with `revoked_at` set is rejected everywhere: an access token naming it fails exactly as if the device were
missing, and its refresh token fails with `device_revoked`. Revoking a device therefore ends its session at once rather
than when its access tokens expire. Revocation marks the row, with the time and a reason in `revoked_reason`, and clears
both refresh digests; it never deletes the row (pruning does, later). The package revokes a device when its session
signs out, when the application revokes it or signs an identity or principal out everywhere (see [Signing out and
revoking sessions](#signing-out-and-revoking-sessions)), and when the refresh exchange detects a replay. Revoking is
idempotent, so a device that is already revoked keeps its first revocation, and `DeviceRevoked` reports each revocation
the package makes. A device whose session has ended, past its idle or absolute deadline, is rejected the same way on the
bearer path and as a sign-in pin, and fails refresh with `session_expired` (see [Token and session
lifetimes](#token-and-session-lifetimes)). An access token that names a device is accepted only for the principal the
device's session records (`principal_type`, `principal_id`), and only when it was issued no earlier than the second of
the session's last principal switch (`principal_switched_at`); otherwise it fails with `device_principal_mismatch`. A
switch therefore ends the access tokens of the principal it switched from at once, and switching back does not revive
the ones issued before it. A device that records no principal accepts no token, and a device pinned on `attempt()` must
record the principal being bound. Both checks read the row already loaded, with no extra query. `ActsAsDevice` reads any
stored timestamp as a value, with or without a `datetime` cast on the column, and throws a `LogicException` when the
device was loaded without one of its refresh or revocation state columns (both digests, the rotation time, the session's
start, the principal switch time, both deadlines, and the revocation time) or without the sign-in's identifier type
(`sign_in_identifier_type`), for example through a `devices()` relation or a global scope that selects other columns,
so a partial select is reported instead of being read as a device that is not revoked, has no deadline, or whose
sign-in used no identifier.

### Sign-in

```php
'sign_in' => [
    'password_identifier' => 'email',
    'pending_table'       => 'pending_sign_ins',
    'pending_ttl_seconds' => 300,
],
```

The password sign-in method looks identities up by `password_identifier`, which is also the identifier type the
attempt limits count and a guard that requires verified identifiers checks. A guard whose identities are found by
another column names its own, and that is the one `signIn('password', ...)` and `attempt()` use on it:

```php
'guards' => [
    'staff' => [
        'driver'   => 'jwt',
        'provider' => 'staff',
        'sign_in'  => ['password_identifier' => 'username'],
    ],
],
```

Either must be a lower-case column name (a letter, then letters, digits, or underscores) that does not contain
`password`; anything else, or any other key in a guard's `sign_in` block, fails with an `InvalidArgumentException`
when a password sign-in runs. A sign-in that needs a further factor waits in `pending_table`
(on the device model's connection) for at most `pending_ttl_seconds`, an integer from 30 to 3600 (see
[Additional factors](#additional-factors)).

### One-time codes

```php
'codes' => [
    'table'                   => 'one_time_codes',
    'key'                     => env('AUTHENTICATION_CODES_KEY'),
    'length'                  => 6,
    'ttl_seconds'             => 600,
    'max_attempts'            => 5,
    'resend_cooldown_seconds' => 60,
],

'delivery' => [
    'queue' => ['connection' => null, 'name' => null],
],
```

The `phone_code` and `email_code` sign-in methods and verification by code (see
[Signing in with a one-time code](#signing-in-with-a-one-time-code)) send a code of `length` digits (6 to 10), drawn
uniformly with `random_int()`, that works once, for `ttl_seconds` (60 to 3600), and for at most `max_attempts` checks (1
to 20); after that it is locked until another is requested. Another code for the same number may be requested
`resend_cooldown_seconds` (0 to `ttl_seconds`) after the last, and replaces it at once: the earlier code stops working.
Each number is an integer, or a digit string as `env()` returns one; anything else fails closed with an
`InvalidArgumentException` naming the key when a code is first issued, and `authentication:check` reports it. The
settings are global, not per guard.

Codes live in `table` (`authentication-migrations` creates `one_time_codes`), on the device model's connection, one row
per binding: the purpose (a sign-in, a verification, a password reset code or link, or an identifier change), the guard,
the identifier's type and normal form and, for a verification or a change, the identity. The row is stored under an
HMAC-SHA256 of that binding and holds the code only as an HMAC-SHA256 of the binding, a random id for the issuance and
the code, each with its own key derived from `key` (at least 32 bytes) or, when `key` is not set, from `app.key`. A code
has a few million values at most, so a plain hash of it could be reversed by anyone who reads the table (from a backup
or a replica, say); a keyed one cannot without the key, and the table holds neither a code nor an identifier. Rotating
the key, or `app.key` when it is the source, only invalidates the codes outstanding. A shorter `key` fails closed.

A code is delivered by a queued job, `ShouldBeEncrypted` so its payload (which carries the code and the number) is
encrypted with `app.key` on the queue, pushed to `delivery.queue.connection` and `delivery.queue.name` (`null` for your
defaults; every job the package queues, password reset deliveries included, uses them) once the code is committed on its
connection. Delivery is never part of the request: on Laravel's `sync` driver, which would run
the job during its dispatch, it is dispatched after the response instead, in the application's terminating callbacks
(and in a console command, when it ends); if you turn after-response dispatching off
(`Bus::withoutDispatchingAfterResponses()`), Laravel runs it at once. A `failover` connection that lists a `sync` one
(directly or through another `failover`) would run the job during its dispatch whenever the connections before it
fail, so the job is pushed to it in the terminating callbacks instead: a worker-backed connection still gets it, and a
fall back to `sync` runs it after the response. Run a worker in production: `authentication:check` warns when a `jwt`
guard is configured and the delivery connection is `sync`, or a `failover` that can fall back to `sync`. Bind your
gateway as the sender, from a service provider (the package ships none: a sign-in code's job fails with a
`BindingResolutionException` without one, and `authentication:check` reports a guard that allows a code method with no
sender bound; a password reset code or an identifier change by code throws a `LogicException` before anything is
counted):

```php
use App\Auth\SmsCodeSender;
use SineMacula\Laravel\Authentication\Contracts\OneTimeCodeSender;

$this->app->bind(OneTimeCodeSender::class, SmsCodeSender::class);
```

```php
use Illuminate\Support\Facades\Mail;
use SineMacula\Laravel\Authentication\Codes\OneTimeCodeMessage;
use SineMacula\Laravel\Authentication\Contracts\OneTimeCodeSender;

final class SmsCodeSender implements OneTimeCodeSender
{
    public function __construct(private SmsGateway $sms) {}

    public function send(OneTimeCodeMessage $message): void
    {
        // $message->identifier is the recipient's own number or address; $message->code is in clear: never log it.
        match ($message->type) {
            'phone' => $this->sms->send($message->identifier, "Your code is {$message->code}."),
            'email' => Mail::to($message->identifier)->send(new CodeMail($message->code, $message->expiresAt)),
        };
    }
}
```

The message also carries the guard, the purpose (`CodePurpose::SIGN_IN` or `VERIFY_IDENTIFIER`, to word it) and the
recipient identity.

A sender that throws fails the job, and your queue's retry policy applies; a retry checks the code first, so a code
that expired or was replaced is never sent. Requests for codes are limited by the `code_request` rate limits (see
[Rate limits](#rate-limits)). Expired codes stay in the table until they are pruned: schedule `model:prune` with
`Models\OneTimeCode` beside the others (see [Pruning devices](#pruning)).

### Passkeys

```php
'passkeys' => [
    'table'                 => 'passkeys',
    'challenges_table'      => 'passkey_challenges',
    'challenge_ttl_seconds' => 300,

    'relying_party' => [
        'id'      => env('AUTHENTICATION_PASSKEYS_RP_ID'),   // e.g. example.com
        'name'    => env('APP_NAME'),
        'origins' => [],                                      // e.g. ['https://app.example.com']
    ],
],
```

Passkeys belong to a WebAuthn relying party. Every guard that uses passkeys needs one: the package's `relying_party`,
with any of its keys overridden in a `passkeys` block on the guard's `config/auth.php` entry, where a key that is
present wins:

```php
'guards' => [
    'console' => [
        'driver'   => 'jwt',
        'provider' => 'users',
        'audience' => ['methods' => ['password', 'passkey']],
        'passkeys' => ['id' => 'console.example.com', 'origins' => ['https://console.example.com']],
    ],
],
```

`id` is the relying party id, a lower-case host name (not an IP address); every passkey registered through the guard is
scoped to it, and a guard only ever sees the passkeys of its own id, so guards that share an id share their passkeys.
`name` is what the browser shows, by default `app.name`. `origins` lists the exact origins the ceremonies may run on,
each `https://host[:port]`, or `http://localhost[:port]` for development, in lower case, with a host that is the id or a
subdomain of it; a ceremony from any other origin, or framed in another site (whether the browser reports the
top-level origin or only that the ceremony is cross-origin), is refused. The package does not consult
the public suffix list, so never name a public suffix (`co.uk`, say) as the id. Anything else, or an unknown key, fails
closed with an `InvalidArgumentException` naming the guard and the key when the guard's passkeys are first used, and
`authentication:check` reports it for every guard whose audience allows `passkey` or that sets a `passkeys` block.

A challenge lives `challenge_ttl_seconds` (30 to 600, five minutes by default), which is also the `timeout` the options
give the browser. Both tables live on the device model's connection; prune expired challenges with `model:prune` (see
[Pruning devices](#pruning)). Passkeys are not pruned: one lasts until its owner removes it. The algorithms
offered are ES256, EdDSA (when PHP's sodium extension is loaded, as it is by default) and RS256.

### Rate limits

Sign-in, requests for one-time codes, password resets, identifier changes and refresh are limited per identifier and per
IP address; requests for passkey
sign-in options and client credentials exchanges per IP address (an exchange per client id too, only when you opt in).
Every limit is counted in the database on the write connection, so the limits hold across servers and do not depend on
a cache. Publish the migration with the others (`authentication-migrations` creates
`rate_limits`), then set limits in the package `rate_limits` block or a guard's own `rate_limits` block:

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

| Flow                     | Scope            | Default             | Counts                                                                                                         |
|--------------------------|------------------|---------------------|----------------------------------------------------------------------------------------------------------------|
| `sign_in`                | `per_identifier` | 5 per 300 seconds   | Every attempt for the identifier, and every secret a method checks against an account; a success is given back |
| `sign_in`                | `per_ip`         | 50 per 300 seconds  | Every attempt from the IP address; a success is given back                                                     |
| `refresh`                | `per_identifier` | 10 per 60 seconds   | Failed refreshes of the device                                                                                 |
| `refresh`                | `per_ip`         | 100 per 60 seconds  | Failed refreshes from the IP address                                                                           |
| `code_request`           | `per_identifier` | 5 per 3600 seconds  | Every request for a one-time code to the identifier, sent or not; never given back                             |
| `code_request`           | `per_ip`         | 50 per 3600 seconds | Every request for a one-time code from the IP address; never given back                                        |
| `passkey_options`        | `per_ip`         | 100 per 300 seconds | Every request for passkey sign-in options from the IP address; never given back                                |
| `client_credentials`     | `per_identifier` | Off                 | When set: exchanges refused for the client's credentials or identity, by client id as given                    |
| `client_credentials`     | `per_ip`         | 100 per 60 seconds  | Exchanges refused for the client's credentials or identity from the IP address                                 |
| `password_reset_request` | `per_identifier` | 5 per 3600 seconds  | Every request for a reset link or code to the identifier, held or not; never given back                        |
| `password_reset_request` | `per_ip`         | 50 per 3600 seconds | Every request for a reset link or code from the IP address; never given back                                   |
| `password_reset`         | `per_identifier` | 10 per 900 seconds  | Every reset submission naming the identifier, before anything is checked; a success is given back              |
| `password_reset`         | `per_ip`         | 50 per 900 seconds  | Every reset submission from the IP address, before anything is checked; a success is given back                |
| `identifier_change`      | `per_identifier` | 5 per 3600 seconds  | Every change request to the new identifier, and every one the identity's account makes; never given back       |
| `identifier_change`      | `per_ip`         | 50 per 3600 seconds | Every change request from the IP address; never given back                                                     |

Each limit is `['max' => ..., 'decay_seconds' => ...]`: at most `max` attempts (at least 1) in each window of
`decay_seconds` (1 to 86400), or `null` for none. Windows are aligned to the clock (a 300-second window runs from
12:00:00 to 12:05:00), so, as with any fixed window, up to twice `max` attempts can fall within `decay_seconds` across a
boundary. A counter started before `decay_seconds` changed keeps its window until that window ends, so a change neither
forgives the attempts already counted nor gives a slot back to the wrong window. A guard scope that is present wins,
`null` included; a flow set to `null` turns both of its limits off; a scope the guard leaves out is the package's. A
malformed limit, a missing one, or an unknown key fails closed with an `InvalidArgumentException` naming the guard and
the key, as does a `passkey_options.per_identifier` other than `null`: a request for passkey sign-in options names no
identifier, so such a limit could never apply.

A sign-in guesses a secret, so it reserves its slots before the method runs: a refused sign-in fails with
`rate_limited` and a wait in seconds, without checking the password, and a successful one gives its own slots back.
Earlier failures are not forgiven: they count until their window ends, so concurrent attempts can never exceed `max`.
When the IP address's limit is full, the slot just taken for the identifier is given back.

The password method also counts every password it checks against the account it checks it for, under the guard's
`per_identifier` limit, and holds that slot with the sign-in's own: it is given back only when the sign-in starts its
session (a pending sign-in keeps it until it completes), so a correct password that goes on to fail, or to wait for a
further factor, still counts. A lookup can find one account by many spellings of its identifier (a column collation that
ignores accents, widths or invisible characters, as MySQL's default `utf8mb4_unicode_ci` does, a query closure in
`attempt()`, another column), and through every guard whose provider returns it, so the account keeps one count
whichever guard checks it. An Eloquent identity's account is the row it is stored in (its connection, that connection's
database, its table and its key), so two model classes over one table (an `Admin` model over the users table, say) count
the same account once, and the same key in another tenant's database is another account; any other identity's account is
its class and auth identifier. Each guard holds that one count to its own `per_identifier` limit, so the guesses at an
account's password are bounded by the most permissive limit among the guards that check it: at most the largest `max` in
each window of the shortest `decay_seconds`, whichever spelling and guard each guess uses. A guard with a looser limit
therefore raises the bound for every guard, while a stricter one only stops its own sign-ins sooner, and guards with the
same limit allow no more guesses together than one alone. A guard whose `per_identifier` is `null` neither checks nor
counts the account, so it adds guesses of its own. Once an account has no attempts left, its password is not checked
until the window ends, and the sign-in fails as `invalid_credentials`, as a wrong password would, so the refusal does
not reveal that the account exists. Only your own listeners are told why: `AuthenticationFailed` carries
`account_rate_limited` and the wait, so a lockout notice or a SIEM can tell a locked account from a wrong password. A
refresh cannot guess a secret (its tokens are signed and its rotation ids random), so it counts only its failures, per
device and per IP address, and a successful refresh costs one read. A refresh refused for its failures answers `429`
with a `Retry-After` header. A request for a one-time code costs a message whoever has the number, so every request for a
valid number counts, whether a code is sent or the resend cooldown holds it back, and no slot is given back; the number
is counted in its normal form, whether or not anyone has it.

Identifiers are counted in their canonical form, through the normaliser of their type when one is registered (see
[Identifiers](#identifiers)), so every casing of an address shares one counter, and otherwise trimmed and lower-cased.
IP addresses are counted canonically too: an IPv6 client is counted by its /64 network, the block a single client is
usually given, so it cannot spread its attempts over its own addresses. An IPv6 address that carries an IPv4 client's
address, IPv4-mapped (`::ffff:0:0/96`) or translated through the NAT64 well-known prefix (`64:ff9b::/96`), shares that
IPv4 address's counter. A translator on a network-specific prefix (such as `64:ff9b:1::/48`, or your own) puts every
IPv4 client it serves into one /64 counter: resolve the client's own address before the request reaches the guard, with
Laravel's trusted proxies, so the limits see each client apart. The table holds only keyed digests (HMAC-SHA256, under a
key derived from `app.key`) of what each counter counts: the guard, flow, scope and identifier or IP address, or, for an
account, the flow and the account, without the guard. An IP address, an identifier or an account id is easy to guess, so
a plain digest of one could be reversed by anyone who reads the table (from a backup or a replica, say); a keyed one
cannot without your application key. Rotating `app.key` starts every counter afresh, and with no `app.key` the limiter
fails closed with an `InvalidArgumentException`. Every change to a count is one statement the database applies
atomically. A database error propagates as a server error: a limiter that cannot count lets nothing through. The one
exception is giving back a completed further factor's slots after its commit, which is reported instead (see
[Writing a sign-in method](#writing-a-sign-in-method)).

> **Transactions:** the counters live on `rate_limits.connection`, the default connection when `null`. Counts written on
> the same connection as a transaction you open around a sign-in are rolled back with it, so a sign-in that your code
> rolls back is not counted, and attempts made that way are not limited. If you wrap sign-ins in transactions you may
> roll back, point `rate_limits.connection` at a connection of its own (a second connection to the same database will
> do).

Ended windows stay in the table until they are pruned, as do pending sign-ins that were never completed (see
[Additional factors](#additional-factors)). Schedule Laravel's pruning command with both models, and the device model,
as shown in [Pruning devices](#pruning).

### API key settings

```php
'api_keys' => [
    'table'                        => env('AUTHENTICATION_API_KEYS_TABLE', 'api_keys'),
    'prefix'                       => env('AUTHENTICATION_API_KEYS_PREFIX', 'ak'),
    'rotation_overlap_seconds'     => env('AUTHENTICATION_API_KEYS_ROTATION_OVERLAP_SECONDS', 86400),
    'max_rotation_overlap_seconds' => env('AUTHENTICATION_API_KEYS_MAX_ROTATION_OVERLAP_SECONDS', 604800),
    'last_used_throttle_seconds'   => env('AUTHENTICATION_API_KEYS_LAST_USED_THROTTLE_SECONDS', 60),
    'prune_after_days'             => env('AUTHENTICATION_API_KEYS_PRUNE_AFTER_DAYS', 30),
],
```

Keys live in `table`, on the device model's connection. `prefix` (a lower-case letter, then up to 15 lower-case letters
or digits) starts every new key, so your keys are recognisable in logs and to secret scanners; changing it leaves
existing keys working. A rotation keeps the replaced key working for `rotation_overlap_seconds` unless it names its own
overlap, never beyond `max_rotation_overlap_seconds` (at most 30 days). A key's last use is recorded at most once per
`last_used_throttle_seconds` (0 to 86400; 0 records every use), and `model:prune` deletes keys revoked or expired more
than `prune_after_days` ago (0 to 3650). Each number is an integer, or a digit string as `env()` returns one; anything
else fails closed when it is used, and `authentication:check` reports it.

### Credential validation timing

`attempt()` and `validate()` wrap credential checks in a constant-time `Timebox` to prevent timing side-channels, and the
session service's `signIn()` runs its sign-in method and the checks after it in the same budget, as do a password reset
submission and the password check of `Reauthentication::password()` before an identifier change:

```php
'timebox' => [
    'credentials_microseconds' => 400000,
],
```

Must exceed the worst-case hasher cost. Only a check that succeeds returns before the budget ends, and only for itself:
every check a guard makes waits out the full budget again when it fails, however many succeeded before it on the same
guard (one guard serves a whole request, command or queue worker).

## Events

| Event                                             | Fired when                                                               |
|---------------------------------------------------|--------------------------------------------------------------------------|
| `Illuminate\Auth\Events\Attempting`               | A sign-in or refresh starts (never a bearer request)                     |
| `Illuminate\Auth\Events\Validated`                | A sign-in or refresh is about to bind context                            |
| `Illuminate\Auth\Events\Authenticated`            | Identity bound to the guard, bearer requests included                    |
| `Illuminate\Auth\Events\Login`                    | A sign-in or refresh bound the guard                                     |
| `Illuminate\Auth\Events\Failed`                   | A sign-in or refresh was rejected (never a bearer token)                 |
| `Illuminate\Auth\Events\Logout`                   | `logout()` or `signOut()` ended a signed-in request                      |
| `SineMacula\...\Events\PrincipalAssigned`         | Principal resolved and bound                                             |
| `SineMacula\...\Events\DeviceAuthenticated`       | Device hydrated and bound; listeners may persist metadata                |
| `SineMacula\...\Events\Refreshed`                 | Refresh exchange completed, once committed                               |
| `SineMacula\...\Events\DeviceRevoked`             | The package revoked a device, once committed; with reason                |
| `SineMacula\...\Events\SignedOutEverywhere`       | A bulk revocation ended a scope's sessions, once committed               |
| `SineMacula\...\Events\DeviceCreated`             | The session service created a device, once committed                     |
| `SineMacula\...\Events\SignedIn`                  | A session started or was refreshed, once committed                       |
| `SineMacula\...\Events\AdditionalFactorRequired`  | A sign-in waits for a further factor, once committed                     |
| `SineMacula\...\Events\PrincipalChoiceRequired`   | A sign-in waits for a choice of principal, once committed                |
| `SineMacula\...\Events\PrincipalSwitched`         | A session switched its principal, once committed                         |
| `SineMacula\...\Events\IdentifierVerified`        | An identifier was verified (after commit); carries type                  |
| `SineMacula\...\Events\PasswordSet`               | A password was set or reset, once committed; with flow                   |
| `SineMacula\...\Events\IdentifierChangeRequested` | A change of identifier waits for its proof, once committed               |
| `SineMacula\...\Events\IdentifierChanged`         | An identifier was replaced by a proven one, once committed               |
| `SineMacula\...\Events\PasskeyAdded`              | A passkey was registered, once committed                                 |
| `SineMacula\...\Events\PasskeyUsed`               | A passkey's assertion was verified, once committed                       |
| `SineMacula\...\Events\PasskeyRemoved`            | A passkey was removed, once committed                                    |
| `SineMacula\...\Events\ApiKeyIssued`              | An API key was issued, once committed                                    |
| `SineMacula\...\Events\ApiKeyRotated`             | An API key was rotated, once committed; previous key id                  |
| `SineMacula\...\Events\ApiKeyRevoked`             | An API key was revoked, once committed                                   |
| `SineMacula\...\Events\ClientCredentialsGranted`  | A client credentials exchange issued an access token                     |
| `SineMacula\...\Events\AuthenticationFailed`      | Any sign-in, refresh, switch, bearer, key, code, reset or change failure |

The credentials on `Attempting` and `Failed` never include a password: every key whose name contains `password`
(case-insensitive), such as `password`, `current_password`, or `password_confirmation`, is removed before the event is
dispatched, and the identifier is kept for throttling and audit listeners. To remove more keys, list name fragments in
the published config:

```php
'events' => [
    'redacted_credential_keys' => ['secret', 'code'],
],
```

Every package event implements `SineMacula\...\Contracts\AuthenticationEvent` and carries one `EventContext` in
`$event->context` (also `$event->context()`), so one listener takes them all and attributes each the same way:

```php
use Illuminate\Support\Facades\Event;
use SineMacula\Laravel\Authentication\Contracts\AuthenticationEvent;

Event::listen(AuthenticationEvent::class, function (AuthenticationEvent $event): void {
    $context = $event->context();

    AuditLog::record(
        event: $event::class,
        guard: $context->guard,
        identity: $context->identityId,
        principal: [$context->principalType, $context->principalId],
        tenant: $context->tenantId,
        device: $context->deviceId,
        method: $context->method,
        credential: $context->credentialId,
        scopes: $context->scopes,
        ip: $context->client->ip,
        userAgent: $context->client->userAgent,
    );
});
```

The context holds the guard, the client of the request being served (IP address and user agent, cleaned as the device
columns are), and as much as the event's flow established of the identity, the principal, the tenant it acts within, the
device and the sign-in method (for a device's events, the method its session records), and the credential (an API key or
a passkey) in `credentialId` with the scopes it grants in `scopes` (`null` for a human identity's session, which no
credential limits); what was not established is `null`. It also snapshots, when the event is built, the identity's auth
identifier (`identityId`), the principal's recorded type and identifier (`principalType`, `principalId`), and the
tenant's and the device's identifiers (`tenantId`, `deviceId`, which keeps the device id a token named even when no
device was found). An event about a device row itself (every `DeviceRevoked`, and a refresh or switch refused on the
row's own state before its owner was read, such as a revoked or ended device or a replay) names the owner and principal
the row records in `identityId`, `principalType` and `principalId` when the flow did not load them; a device records no
tenant, so a revocation's `tenantId` is known only when the tenant's deactivation or the request's own session is why.
Other events name only what they hold, even when they carry a device: an identity's `SignedOutEverywhere`,
`PrincipalChoiceRequired` and a switch refused for its target have no principal. The snapshots, the client, the method
and the other values are fixed facts that survive a queue unchanged. The models are live references: a synchronous
listener gets the package's own instances, and a queued listener gets them re-fetched in their state when it runs, as
Laravel's `SerializesModels` does, or a `ModelNotFoundException` when one was deleted meanwhile (a pruned device, say).
Audit sinks should record the snapshots. No event carries a token, a digest, a password or any other secret. An event
that reports a write is dispatched once the write is committed on the written row's own connection: at once when it has
no open transaction, on its commit otherwise, and never when it is rolled back; a transaction on another connection
neither delays nor withdraws it.

A request's bearer token authenticates; it is not a sign-in. It dispatches only Laravel's `Authenticated` and the
package's `PrincipalAssigned` and `DeviceAuthenticated`, and a rejected token only `AuthenticationFailed`, once per
request: never `Attempting`, `Validated`, `Login` or `Failed`, so a listener on those records sign-ins, not requests. A
request without a token dispatches nothing.

`Login` and `SignedIn` report real sign-ins: a session the session service started (`signIn()`, `start()` or
`complete()`), with the method that proved who signed in, and a refresh, which renews the session on its device and
dispatches `Refreshed` and then `SignedIn` with `$refresh` set and the method the device's session records. `attempt()`
starts no session and never dispatches `SignedIn`: Laravel's `Login` reports its sign-ins, and code that calls `start()`
after `attempt()` reports the sign-in once. `DeviceCreated` precedes `SignedIn` for a new device
(`SignedIn::$deviceCreated`). A sign-in the additional-factor policy holds for a further factor dispatches
`AdditionalFactorRequired` instead, once committed: from `signIn()` it answers the sign-in's `Attempting`, and from
`start()`, which dispatches no `Attempting`, it is the only event. Completing it dispatches `SignedIn`, and discarding
it `AuthenticationFailed` with `additional_factor_failed`. A sign-in that waits for a choice of principal dispatches
`PrincipalChoiceRequired` the same way; choosing starts the session (or a pending factor) as above, and discarding the
choice dispatches `AuthenticationFailed` with `principal_choice_abandoned`. A switch of principal is no sign-in: it
dispatches `PrincipalSwitched`, and no `Login` or `SignedIn`.

`AuthenticationFailed` reports every failed sign-in, refresh, switch of principal, bearer token, API key, client
credentials exchange, request for a one-time code, verification by code, password reset request or submission, and
identifier change request or confirmation, after Laravel's `Failed` where that fires, with the flow
(`AuthenticationFlow`: `sign_in`, `refresh`, `bearer`, `principal_switch`, `api_key`, `client_credentials`,
`code_request`, `identifier_verification`, `password_reset`, `identifier_change`; see [Failure
outcomes](#failure-outcomes) for what each answers), a `FailureReason`, the identifier a sign-in's input named (as
given), and the wait for `rate_limited` and `account_rate_limited`. Its context carries the identity only once a sign-in
method verified it, a refresh reloaded the device's owner or a token's subject was found (a wrong password or an unknown
identifier carries none), the principal and tenant once resolved, and the device once found, else the `did` a token
named. A bearer token is checked in this order, so its reason is the first that applies: `token_invalid`, for a client
credentials token `credential_invalid`, `credential_revoked` and `credential_expired`, then `identity_unknown`,
`machine_identity`, `identity_inactive`, `principal_mismatch`, `principal_inactive`, `tenant_inactive`, then for a token
that names no device `issued_before_cutoff`, and for one that names a device `device_unknown`, `device_guard_mismatch`,
`device_revoked`, `session_expired`, `device_principal_mismatch`. It says why a sign-in failed even where the client is
not told: a refusal by the account's own limit is `account_rate_limited` on the event, while the sign-in's result says
`invalid_credentials`:

| Reason                       | Meaning                                                                           |
|------------------------------|-----------------------------------------------------------------------------------|
| `invalid_credentials`        | The sign-in method did not accept the input                                       |
| `method_not_allowed`         | The guard does not allow the sign-in method, or no longer the session's           |
| `rate_limited`               | The identifier, device or IP address used up its attempts for now                 |
| `account_rate_limited`       | The account used up its attempts; event only, not on the result                   |
| `identity_unknown`           | The guard's provider does not return the identity or device owner                 |
| `identity_inactive`          | The identity reported inactive                                                    |
| `principal_unresolved`       | No principal could be resolved for the identity                                   |
| `principal_mismatch`         | The requested principal (or a token's `pid`) is not the identity's                |
| `principal_inactive`         | The principal reported inactive                                                   |
| `tenant_inactive`            | The principal's tenant inactive, or opted in and missing                          |
| `principal_ineligible`       | The guard's audience policy does not admit the identity as principal              |
| `identifier_unverified`      | The guard requires a verified identifier and it is not                            |
| `device_mismatch`            | The pinned device is not a live device of the identity and principal              |
| `additional_factor_required` | A further factor is required, which only `signIn()` can ask                       |
| `additional_factor_failed`   | A pending sign-in was discarded: its further factor failed                        |
| `principal_choice_abandoned` | A choice of principal was discarded                                               |
| `pending_invalid`            | The pending sign-in is unknown, expired, used, or not this guard's                |
| `token_invalid`              | Decode, expiry, missing claim, typ, guard, iss, aud                               |
| `issued_before_cutoff`       | Device-less token issued at or before a "tokens valid after" time                 |
| `device_unknown`             | Device id is not a device key or names no device                                  |
| `device_guard_mismatch`      | Device is another guard's (or none's); not revoked                                |
| `device_revoked`             | Device row marked revoked                                                         |
| `session_expired`            | Device's idle or absolute deadline reached, or unset                              |
| `device_principal_mismatch`  | Device acts as another principal, or switched since the token's issue             |
| `rotation_reuse`             | Rotated refresh token replayed; device revoked                                    |
| `rotation_conflict`          | Device changed during the refresh; retry                                          |
| `refresh_key_missing`        | Device holds no refresh credential                                                |
| `refresh_token_conflict`     | The request carried a refresh token in more than one source                       |
| `cross_site_request`         | A cookie refresh token without an allowed origin and the custom header            |
| `code_expired`               | The one-time code expired; event only, not on a sign-in's result                  |
| `code_exhausted`             | The code used up its attempts; event only, not on a sign-in's result              |
| `passkey_challenge_invalid`  | The passkey challenge is unknown, expired, used, or another ceremony's            |
| `passkey_counter_regressed`  | The passkey's sign counter did not advance; event only, not on result             |
| `machine_identity`           | A non-human identity tried a sign-in, a session, a refresh or a switch            |
| `credential_invalid`         | API key or client credential malformed, unknown, wrong, or not a machine's        |
| `credential_revoked`         | The API key or client credential is revoked                                       |
| `credential_expired`         | It expired, a rotated key's overlap included                                      |
| `credential_guard_mismatch`  | It was issued for another guard                                                   |
| `scope_invalid`              | A requested scope is malformed or not granted to the credential                   |
| `reauthentication_required`  | An identifier change without a recent authentication, or with a wrong password    |
| `identifier_taken`           | The new identifier is held by another identity, or the unique index refused it    |
| `link_expired`               | The reset or change link's token has expired; event only, not on a reset's result |

A sign-in method may answer only `invalid_credentials`, `identifier_unverified` (once its input proved possession of the
identifier), `code_expired`, `code_exhausted`, `passkey_challenge_invalid` and `passkey_counter_regressed`; every other
reason is the session service's to give. `account_rate_limited`, `code_expired`, `code_exhausted` and
`passkey_counter_regressed` are on the event only: the sign-in's result says `invalid_credentials`. A code request
refused because its number is not one is reported as `invalid_credentials`, while its result says `identifier_invalid`.

## Operations

Running the package in production: where its reads go, what a long-running process keeps between requests and jobs,
rotating signing keys, pruning the rows sessions and credentials leave behind, and checking the configuration before a
deploy.

### Read replicas

Every read that decides authentication - the identity, the principal and the tenant it acts within, and the device with
its guard, sign-in method, refresh digests, rotation time, session deadlines and revocation state - goes to the write
connection, even when the database connection has `read` and `write` hosts. A replica can lag behind a revocation, a
deactivation, a refresh rotation, or an ended session, and a lookup it served could admit a credential the primary has
already rejected.

The package pins the lookups it makes, including the relations the identity, principal and device models eager-load
(`$with`), on whichever connection those relations live (a tenant in a separate landlord database, say). Code you plug
in carries the same obligation:

- a custom `IdentityProvider`, a `ModelProvider` subclass that builds its own query, or a custom `PrincipalResolver`
  must read from the write connection, including the relations its results eager-load;
- `resolveDefaultPrincipal()`, `resolveHintedPrincipal()`, `devices()` and, when `ModelProvider` checks a password,
  `getAuthPassword()` already run inside `WriteConnection::during()` for the identity, `getTenant()` for the principal,
  `isActive()` for the model it belongs to, and a device's guard, sign-in method, refresh state, session deadlines and
  revocation for the device: every model read made there, on any connection, goes to that connection's writer, and so
  does a query-builder read on the model's own connection. A query-builder or `DB` read on another connection, or made
  by a principal or identity that is not an Eloquent model, must pin itself.

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

### Long-running processes

One application can serve many requests (Octane) or run many queued jobs (a queue worker), so nothing one of them binds
may reach the next. Each request rebinds Laravel's `request`, which resets every package guard already resolved: the
identity, principal and device it bound, and whether it has resolved the request, so the next request authenticates from
its own token or not at all. A queue worker forgets only scoped instances between jobs, so the package resets its guards
when each job a worker runs starts (on `JobProcessing`, through `AuthManager::forgetGuardState()`): a guard a job signs
in with `login()` or `setUser()` is signed out again for the next job. Only jobs a worker runs are reset: a job on the
`sync` connection (the `sync` driver, or `dispatchSync()` whatever the default connection) runs inside the request that
dispatched it and leaves its guards as they are, so a session the request just started stays bound and a request that
signed out stays signed out. A dispatcher or principal resolver swapped in after a guard resolved (`Event::fake()`, a
rebinding of `PrincipalResolver`) reaches the guard, its refresh exchange and its session service (and, through it, a
switch of principal and the revocations), which read the guard's collaborators each time they run. The package's
singletons hold configuration only: the token service factory memoises each guard's signing configuration, not any
identity's data, and the mark the password-change listener reads during an automatic rehash is scoped, so it starts
empty for each request and each job a worker runs. No package class keeps a request, an identity or a token in a static
property. The sign-in methods you register are kept for the life of the process as well, so they must hold no state
between calls (see [Writing a sign-in method](#writing-a-sign-in-method)), and so must a factor or audience policy you
bind as a singleton.

### Key Rotation

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

### Pruning

Rows whose use has ended stay in their tables until Laravel's `model:prune` deletes them, each model in chunks of one
conditional `DELETE` that reads nothing:

| Model                     | Pruned once                                                                           |
|---------------------------|---------------------------------------------------------------------------------------|
| `Models\Device`           | its session has been over (revoked, or past a deadline) for `device.prune_after_days` |
| `Models\PendingSignIn`    | it has expired                                                                        |
| `Models\RateLimit`        | its window has ended                                                                  |
| `Models\OneTimeCode`      | it has expired                                                                        |
| `Models\PasskeyChallenge` | it has expired                                                                        |
| `Models\ApiKey`           | it was revoked or expired more than `api_keys.prune_after_days` ago                   |
| `Models\IdentifierChange` | it has expired                                                                        |

Passkeys are never pruned: one lasts until its owner removes it.

Revoked and ended devices are kept for audit: a device is pruned once its session has been over for
`device.prune_after_days` (default 30, from 0 to 3650), counted from when it was revoked or passed its idle or absolute
deadline, whichever came first, never from when it was created, so a long session is kept as long after it ends as a
short one. With 0, a device is pruned from the second its session ends. The value must be an integer, or a digit string
as `env()` returns one; anything else fails with an `InvalidArgumentException` when pruning runs. Each chunk is one
conditional `DELETE`, and nothing is read.

The package's models live outside your application's `app/Models`, so name them when you schedule the command:

```php
use Illuminate\Support\Facades\Schedule;
use SineMacula\Laravel\Authentication\Models\ApiKey;
use SineMacula\Laravel\Authentication\Models\Device;
use SineMacula\Laravel\Authentication\Models\IdentifierChange;
use SineMacula\Laravel\Authentication\Models\OneTimeCode;
use SineMacula\Laravel\Authentication\Models\PasskeyChallenge;
use SineMacula\Laravel\Authentication\Models\PendingSignIn;
use SineMacula\Laravel\Authentication\Models\RateLimit;

Schedule::command('model:prune', [
    '--model' => [
        Device::class,
        PendingSignIn::class,
        RateLimit::class,
        OneTimeCode::class,
        PasskeyChallenge::class,
        ApiKey::class,
        IdentifierChange::class,
    ],
])->hourly();
```

A custom device model opts in with the `PrunesDevices` trait alone (it brings Laravel's `MassPrunable` with it, and
using `MassPrunable` beside it is a PHP trait collision), and pruning reads its columns from the `EloquentDevice` name
accessors; schedule it under its own class name. Run `php artisan model:prune --model="App\Models\Device" --pretend` to
see how many devices would go. Pruning changes nothing about authentication: a pruned device's tokens fail as an unknown
device, exactly as they already failed once it was revoked or ended. Queued listeners of an event about a device that
has since been pruned cannot re-fetch it (see [Events](#events)).

Before a token's `did` is looked up, it is checked against the device model's primary key: a UUID for `HasUuids`, a
ULID for `HasUlids`, an integer for an integer key, and a non-empty string otherwise. A `did` that cannot be a key is
treated as an unknown device without a query. A model whose key has some other format implements `ValidatesDeviceKey`
to describe it. Database errors are never read as an unknown device: they propagate as server errors.

### Checking the configuration

`php artisan authentication:check` resolves every `jwt` and `api_key` guard's settings the way the guard would and exits
`1` when any is wrong, `0` otherwise, for a deploy pipeline or a readiness probe. It checks each `jwt` guard's token
service (keys, active kid, algorithm, key lengths, lifetimes, those per principal type included, leeway, issuer and
audience), that its provider resolves to an `IdentityProvider`, its `principal_resolver` override, its audience settings
when the package's `AudiencePolicy` is bound, the rate limits of every flow, the password identifier, the refresh token
transport and, when its audience allows `passkey` or it sets a `passkeys` block, its passkey relying party; each
`api_key` guard's provider, `principal_resolver` override, audience settings (which must allow `api_key`) and rate
limits; and, for the whole package, the configured device model and pruning retention
(`authentication.device.prune_after_days`, otherwise checked only when `model:prune` runs), the pending sign-in lifetime
(`authentication.sign_in.pending_ttl_seconds`, otherwise checked only when a sign-in waits for a further factor or a
choice of principal), the password policy settings (`authentication.passwords`), the one-time code settings and key
(`authentication.codes`) and a bound `OneTimeCodeSender` when any guard allows a code sign-in method (`phone_code`,
`email_code`, or a `CodeSignIn` you registered), the delivery queue (`authentication.delivery.queue`), the passkey
challenge lifetime (`authentication.passkeys.challenge_ttl_seconds`), the API key settings (`authentication.api_keys`)
and the identifier change settings (`authentication.identifier_changes`). Every check runs, so one run lists every
problem, each as `[<guard>] <message>` (`[device]` for the device model and retention, `[sign_in]` for the pending
lifetime, `[passwords]` for the password policy, `[codes]` for the code settings and sender, `[delivery]` for the
delivery queue, `[passkeys]` for the challenge lifetime, `[api_keys]` for the API key settings, `[identifier_changes]`
for the identifier change settings), and a subject without one as `[<guard>] OK`. Delivery on a `sync` queue connection,
or on a `failover` one that can fall back to `sync`, while any `jwt` guard is configured (any of them may send codes,
reset links and codes, or identifier change codes and notices), is a `[delivery]` warning that leaves the exit code
alone, as is a `jwt` guard whose password resets or identifier changes would refuse to run: its
provider's model on another connection than the device model, or, for resets, a password identifier other than `email`
while Laravel's notification is the reset link sender (see [Password reset](#password-reset)). Only the named guards are
checked with `--guard=api --guard=admin`; a named guard that is not configured, or neither a `jwt` nor an `api_key`
guard, is a problem. The command reads configuration only: it opens no database connection and never prints a key. The
package does not run these checks at boot; a misconfiguration otherwise surfaces when a guard first uses the setting.

## Testing

### Acting as an identity, principal or device

Use `Testing\Concerns\InteractsWithAuthenticationContext` in a Laravel (or Testbench) test case to act on a package
guard (`jwt` or `api_key`). Unlike Laravel's `actingAs()`, the context also authenticates every request the test then
sends through the HTTP kernel:

```php
use SineMacula\Laravel\Authentication\Testing\Concerns\InteractsWithAuthenticationContext;

final class ProfileTest extends TestCase
{
    use InteractsWithAuthenticationContext;

    public function testTheProfileShowsTheMembership(): void
    {
        $this->actingAsPrincipal($membership, guard: 'api')
            ->getJson('/me')
            ->assertOk();

        $this->assertBoundIdentity($user)
            ->assertBoundPrincipal($membership)
            ->assertBoundTenant($tenant)
            ->assertBoundDevice(null)
            ->assertBoundScopes(null);
    }
}
```

| Method                                                                  | What it does                                                                                              |
|-------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------|
| `actingAsIdentity($identity, ?$principal, ?$device, ?$scopes, ?$guard)` | Acts as the identity, as the principal given or the resolver's default, on the device given or none       |
| `actingAsPrincipal($principal, ?$device, ?$scopes, ?$guard)`            | Acts as the principal, for the identity its `getIdentity()` returns                                       |
| `actingOnDevice($device, ?$guard)`                                      | Acts on a device's session: its owner, the principal it records and the guard it records                  |
| `stopActing(?$guard)`                                                   | Ends acting: signed out for the rest of the request, and the next request uses its own credential, if any |
| `assertBoundIdentity()`, `Principal()`, `Tenant()`, `Device()`          | What the guard has bound: `null` for nothing, otherwise the same class with the same identifier           |
| `assertBoundScopes(?array $scopes)`                                     | The scopes, exactly and in order: `null` for no ceiling (a human's session), `[]` for none (a machine)    |
| `assertBoundType(?string $type)`                                        | The principal's type: its own, else its tenant's                                                          |

`actingAsIdentity()` without a principal throws an `InvalidArgumentException` when the identity has no default one, as
`setUser()` does. `actingOnDevice()` finds the owner through the guard's provider and the principal through the guard's
resolver, and throws an `InvalidArgumentException` when either is not found or when a guard is named that the device
does not record.

Every method takes the guard last and uses the default guard when it is left out; acting makes the guard the default,
as `actingAs()` does. The context is bound through the guard's trusted `authenticateAs()`, so nothing is checked: a
test can act as a revoked device, an inactive principal or a machine, which is limited to the scopes given (`[]`, none,
when the test names none), as if its credential granted them, so a test of a scope-gated route needs no real API key
(`$this->actingAsIdentity($client, scopes: ['orders:read'], guard: 'api_keys')`); scopes for a human identity throw an
`InvalidArgumentException`. Each request
the test sends fires `Authenticated`, `PrincipalAssigned` and, with a device, `DeviceAuthenticated` (which records the
device's use), as a bearer request does, and a context acted as wins over a credential the request carries.

Acting on a guard ends with `stopActing()`, when the request signs out (Laravel's `Logout` for the guard, which
`Auth::logout()`, `Auth::sessions()->signOut()` and a sign-out endpoint dispatch), or when the test acts on that guard
again; each guard keeps its own context. With `Logout` faked (`Event::fake()` without a list of events fakes it) the
helpers cannot see a sign-out, so call `stopActing()`. `Auth::forgetGuards()` creates new guards, which are not acted
on until the test acts again. A queued job a worker runs (`queue:work`, or a
`Worker` in the test) still starts signed out, as in production, and the next request is acted as again.

### Fakes

Each fake binds a fresh instance in place of the package's or the application's binding with `fake()` (in the
application's container, or in the one given) and keeps what it is given instead of delivering it, so a test reads it
back: the readers below take an optional filter, `count()` counts everything, and `forget()` clears it.

| Fake                                   | Stands in for              | Reads back                                                                                                              |
|----------------------------------------|----------------------------|-------------------------------------------------------------------------------------------------------------------------|
| `Testing\FakeOneTimeCodeSender`        | `OneTimeCodeSender`        | `sent()`, `hasSent()`; `lastCodeFor($identifier, ?CodePurpose $purpose)`: the last code sent to the identifier          |
| `Testing\FakeIdentifierChangeNotifier` | `IdentifierChangeNotifier` | `sent()`, `hasSent()`; `noticesFor($identity)`: the notices about the identity's changes                                |
| `Testing\FakeBreachedPasswordChecker`  | `BreachedPasswordChecker`  | `checked()`, `hasChecked()`: the passwords it was asked about; `unavailable()` makes it throw as a service that is down |
| `Testing\FakePasswordResetLinkSender`  | `PasswordResetLinkSender`  | `sent()`, `hasSent()`; `lastTokenFor($identifier)`: the token last sent to the identifier                               |

`FakeOneTimeCodeSender::fake()` keeps every message instead of delivering it, so a test reads the code a request sent
and signs in with it:

```php
use SineMacula\Laravel\Authentication\Testing\FakeOneTimeCodeSender;

$sender = FakeOneTimeCodeSender::fake();

$this->postJson('/codes', ['phone' => '+447700900123'])->assertAccepted();

$code = $sender->lastCodeFor('+447700900123');   // the number as delivered, in E.164

$this->postJson('/sign-in/code', ['phone' => '+447700900123', 'code' => $code])->assertOk();
```

The message arrives when the delivery job runs: on a `sync` queue connection once the response is sent (a test's HTTP
request ends with it; call `$this->app->terminate()` after calling the service directly), on a faked queue when the test
runs the pushed job.

`Testing\FakeIdentifierChangeNotifier` does the same for the notices of changed identifiers:
`FakeIdentifierChangeNotifier::fake()` binds a fresh one and returns it, `noticesFor($identity)` lists the notices about
that identity's changes, and `sent()`, `hasSent()`, `count()` and `forget()` work as the sender fake's do. A notice
arrives when its queued job runs, as a code does.

`Testing\FakeBreachedPasswordChecker` stands in for your breached-password checker: `fake(['password123'])` binds a
fresh one that finds exactly those passwords breached, `unavailable()` makes it throw
`BreachedPasswordCheckUnavailableException` as a service that is down would (and `unavailable(false)` lets it answer
again), and it keeps every password it was asked about, so a test can tell whether a request reached the breached check
at all. `checked()` and `hasChecked()` take an optional filter, `count()` counts them, and `forget()` clears them:

```php
use SineMacula\Laravel\Authentication\Testing\FakeBreachedPasswordChecker;

$checker = FakeBreachedPasswordChecker::fake(['password123password']);

$this->putJson('/password', [...])->assertUnprocessable()->assertJson(['violations' => ['breached']]);

$checker->unavailable();   // fails closed: `breach_check_unavailable`, unless `when_unavailable` is `allow`
```

`Testing\FakePasswordResetLinkSender` stands in for the reset link sender: `fake()` binds a fresh one and returns it,
and it keeps every link instead of delivering it, so a test reads the token a request sent and resets with it.
`lastTokenFor($identifier)` is the token last sent to the identifier as delivered (in normal form); `sent()` and
`hasSent()` take an optional filter over the links, `count()` counts them, and `forget()` clears them. A reset code
arrives in `FakeOneTimeCodeSender`, read with `lastCodeFor($identifier, CodePurpose::PASSWORD_RESET)`:

```php
use SineMacula\Laravel\Authentication\Testing\FakePasswordResetLinkSender;

$links = FakePasswordResetLinkSender::fake();

$this->postJson('/password/forgot', ['email' => 'ada@example.test'])->assertAccepted();

$token = $links->lastTokenFor('ada@example.test');

$this->postJson('/password/reset', ['email' => 'ada@example.test', 'token' => $token, 'password' => 'a new passphrase'])->assertNoContent();
```

### Running the package's tests

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

## Extensibility

Concrete classes in this package are `final` except `AuthManager` (the package's subclass of Laravel's manager), the
shipped `Models\Device` model, and the extension points noted below. Extension is through **composition and DI**, not
inheritance:

| Extension point                   | How                                                                                                              |
|-----------------------------------|------------------------------------------------------------------------------------------------------------------|
| Custom identity / principal model | Implement `Identity`, `Principal` (and optional capability interfaces)                                           |
| Custom device model               | Implement `EloquentDevice`, use the `ActsAsDevice` trait (and `PrunesDevices` to be pruned)                      |
| Ending device-less access tokens  | Implement `HasTokensValidAfter` on the identity or principal, or use `ProvidesTokensValidAfter`                  |
| Custom principal resolution       | Implement `PrincipalResolver`, bind per-guard or globally                                                        |
| Custom identity retrieval         | Subclass `ModelProvider` (non-final)                                                                             |
| Custom `auth` middleware          | Subclass `Http\Middleware\Authenticate` (non-final)                                                              |
| Guard and provider drivers        | Register them with `Auth::extend()` / `Auth::provider()` as usual: the package's manager inherits them           |
| Guard-scoped JWT settings         | Override `jwt.*` keys in `auth.guards.<name>.jwt`                                                                |
| Sign-in methods                   | Implement `SignInMethod`, register it with `SignInMethodManager::extend()` under a name the package does not use |
| Additional factors (MFA)          | Bind your own `AdditionalFactorPolicy` in the container; call `factorRemoved()` when a factor is removed         |
| Passkeys as a further factor      | Call `Auth::passkeys()->factorOptions()` and `verifyFactor()` from your further-factor package                   |
| Audience decisions                | Implement `AudiencePolicy` and bind it in the container                                                          |
| Attempt limits                    | Implement `AttemptLimiter` and bind it in the container                                                          |
| Identifier normal forms           | Implement `IdentifierNormaliser`, register it by type in the config                                              |
| One-time code delivery            | Implement `OneTimeCodeSender` and bind it in the container                                                       |
| Breached-password checks          | Implement `BreachedPasswordChecker` and bind it in the container                                                 |
| Password reset links              | Implement `PasswordResetLinkSender` and bind it in the container                                                 |
| Identifier change notices         | Implement `IdentifierChangeNotifier` and bind it in the container                                                |
| Code sign-in for another type     | Register `CodeSignIn` for the type with `SignInMethodManager::extend()`                                          |
| Credential scope validation       | Implement `ScopeRegistry` and bind it in the container                                                           |

The `password` method is the package's own: `attempt()`, `validate()` and the password rehash use it directly, so
`extend('password', ...)` throws an `InvalidArgumentException` rather than replace it for `signIn()` alone. Register a
different password scheme under a name of its own and allow that name in the guard's audience. The package's other
methods (`phone_code`, `email_code` and `passkey`) are reserved the same way, as are `api_key` and `client_credentials`,
which an audience lists for machine credentials and which never resolve to a sign-in method. Names are lower case
(a letter, then letters, digits or underscores), and a method resolves only by the exact name it was registered under,
so one method never has a second spelling for a guard to allow or a device to record.

An `AttemptLimiter` of your own counts a subject's `account` in one counter that every guard shares, held to each
guard's `per_identifier` limit (and not counted where that limit is `null`), as well as the identifier's and the IP
address's counters of the guard. Without that, the account bounds under [Rate limits](#rate-limits) and
[Additional factors](#additional-factors) do not hold: a limiter keyed only by guard, identifier and IP address (one
built on Laravel's `RateLimiter`, say) lets every spelling of an identifier, and every guard, guess an account's password
and its further factor anew. It records in each granted reservation's `windows` everything its `release()` needs to give
the slots back (string keys and values), and gives them back from the windows alone. A sign-in that waits for a further
factor stores the windows of each reservation it holds and, when it completes, gives each back through a reservation
rebuilt from its own windows, whose subject carries the guard, the flow, the identifier type and the IP address but no
identifier or account. Two reservations may record the same key (a method that checks two secrets reserves the account
twice), and each is given back.

`AbstractGuard` is not final and may be extended for entirely new guard types.

The package replaces Laravel's `auth` manager with its own subclass when it boots, after every service provider has
registered, and carries over the guard and provider drivers registered on the manager it replaces
(`AuthManager::inheritDriversFrom()`), so `Auth::extend()` and `Auth::provider()` calls made in your providers'
`register()` keep working.

## Design Notes

The sections above are the adoption guide. The security and lifecycle contracts behind them, for maintainers and
reviewers, live in `docs/design/`:

- `docs/design/guard-lifecycle-and-events.md`
- `docs/design/event-model.md`
- `docs/design/refresh-rotation-and-replay.md`
- `docs/design/refresh-token-transport.md`
- `docs/design/fail-closed-pid-did.md`
- `docs/design/access-only-mode.md`
- `docs/design/guard-bound-tokens.md`
- `docs/design/session-service.md`
- `docs/design/device-lifecycle.md`
- `docs/design/principal-choice-and-switch.md`
- `docs/design/audience-policy.md`
- `docs/design/one-time-codes.md`
- `docs/design/passkeys.md`
- `docs/design/machine-credentials.md`
- `docs/design/passwords.md`
- `docs/design/identifier-changes.md`
- `docs/design/testing-helpers.md`

## Requirements

- PHP ^8.3 (extensions: hash, mbstring, openssl; sodium, bundled with PHP, for EdDSA passkeys)
- Laravel ^12.40 || ^13.3

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
