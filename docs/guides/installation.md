# Installation

```bash
composer require sinemacula/laravel-authentication
```

Publish the config and the migrations (the `devices`, `pending_sign_ins`, `rate_limits`, `one_time_codes`, `passkeys`,
`passkey_challenges`, `api_keys` and `identifier_changes` tables, created on the storage connection: the default
connection unless `authentication.storage.connection` names another, see [Storage](configuration.md#storage)), then
migrate:

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
tokens. Every token carries its kid in the JWT header. See [Key Rotation](operations.md#key-rotation) for adding keys.

Every key must be at least as long as the algorithm's digest: 32 bytes for `HS256` (the default), 48 for `HS384`,
and 64 for `HS512`. `openssl rand -base64 48` prints a 64-character value that satisfies all three. Generate every
key this way rather than writing or copying one by hand.

The package fails closed when a JWT guard or `Auth::jwt(...)` service is resolved with an empty key map, a missing,
empty, or too-short key, or an `active_kid` that is not in the map.

## Guards and providers

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
(see [API keys](machine-credentials.md#api-keys)):

```php
'guards' => [
    'machine' => [
        'driver'   => 'api_key',
        'provider' => 'clients',
        'audience' => ['methods' => ['api_key']],
    ],
],
```

## Unauthenticated requests

A guest on a route that only package guards protect (`auth:api`, or `auth` when the default guard is a package guard)
gets `401` with `{"message": "Unauthenticated."}`, whatever its `Accept` header. The guards are stateless, so there
is no login page to redirect to, and an API without a `login` route no longer answers browser-style requests with a
server error. Laravel's own guards keep their guest redirect, and so does a route that also accepts one of them
(`auth:web,api`).

The package binds its `SineMacula\Laravel\Authentication\Http\Middleware\Authenticate` in place of Laravel's `auth`
middleware and registers the `401` as an exception-handler render callback, after any your application registers for
`AuthenticationException`. If your application aliases its own `auth` middleware, extend the package's class.

## Access-only mode (no devices, no refresh)

Device tracking and refresh are opt-in. For simple backends or short-lived session flows (non-human clients use
[machine credentials](machine-credentials.md) instead):

1. Do not implement `HasDevices` on your identity model.
2. Issue access tokens with `Auth::jwt('api')->issueAccessToken($identity, $principal, null)`.
3. Do not call `$guard->refresh(...)` or start sessions through the session service (`signIn()`, `start()`), which
   throws a `LogicException` for an identity without `HasDevices`. Clients re-authenticate when the access token
   expires. To end an identity's tokens before they expire, give the identity (or the principal) a "tokens valid after"
   time (below): the session service's revocation methods (`revokeDevices()`, `signOutEverywhere()`,
   `passwordChanged()` and the other security changes, `principalDeactivated()`, `revokePrincipalDevices()`) move it,
   and need none of the package's tables for such an identity, except `identifier_changes` for one that implements
   `HasChangeableIdentifiers`, whose pending changes they cancel, or call `invalidateTokensIssuedBefore()` yourself.

`Auth::device()` returns `null` in this mode; the rest of the contextual surface works normally. Such a token has no
device to revoke, so an identity or principal model that implements `HasTokensValidAfter` ends them instead: a token
whose `iat` is at or before either one's `getTokensValidAfter()` is rejected (`issued_before_cutoff`), counted in whole
seconds, so a token issued in the cutoff's own second is rejected too. Tokens that name a device are not held to it.
Bearer requests need none of the package's tables. A guard that signs in with `attempt()` counts its attempts in the
`rate_limits` table (see [Rate limits](configuration.md#rate-limits)), so publish and run the migrations for it, or set
the guard's `rate_limits.sign_in` to `null`; the `devices` and `pending_sign_ins` tables then stay empty. See
`docs/design/access-only-mode.md`.
