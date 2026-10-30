# Configuration

The package's settings live in the published `config/authentication.php`, under `authentication.`. A guard overrides
the ones marked per guard in its own `config/auth.php` entry, in a block named after the first part of the key (`jwt`,
`audience`, `rate_limits`, `refresh_token`, `passkeys` for the relying party, and `sign_in` for the password
identifier), where a key it sets wins. A value that is malformed or out of range fails closed, naming the key (and the
guard), when it is first used, and `php artisan authentication:check` reports it before a deploy (see
[Checking the configuration](operations.md#checking-the-configuration)).

| Key                                                 | Default                                                                      | Env                                                               | Per guard | See                                                                   |
|-----------------------------------------------------|------------------------------------------------------------------------------|-------------------------------------------------------------------|-----------|-----------------------------------------------------------------------|
| `storage.connection`                                | `null`                                                                       | `AUTHENTICATION_STORAGE_CONNECTION`                               |           | [Storage](#storage)                                                   |
| `device.model`                                      | `Device::class`                                                              | `AUTHENTICATION_DEVICE_MODEL`                                     |           | [Device](#device)                                                     |
| `device.table`                                      | `devices`                                                                    | `AUTHENTICATION_DEVICE_TABLE`                                     |           | [Device](#device)                                                     |
| `device.last_used_throttle_seconds`                 | `60`                                                                         | `AUTHENTICATION_DEVICE_LAST_USED_THROTTLE_SECONDS`                |           | [Device](#device)                                                     |
| `device.prune_after_days`                           | `30`                                                                         | `AUTHENTICATION_DEVICE_PRUNE_AFTER_DAYS`                          |           | [Pruning](operations.md#pruning)                                      |
| `sign_in.password_identifier`                       | `email`                                                                      | `AUTHENTICATION_SIGN_IN_PASSWORD_IDENTIFIER`                      | yes       | [Sign-in](#sign-in)                                                   |
| `sign_in.pending_table`                             | `pending_sign_ins`                                                           | `AUTHENTICATION_SIGN_IN_PENDING_TABLE`                            |           | [Sign-in](#sign-in)                                                   |
| `sign_in.pending_ttl_seconds`                       | `300`                                                                        | `AUTHENTICATION_SIGN_IN_PENDING_TTL_SECONDS`                      |           | [Sign-in](#sign-in)                                                   |
| `timebox.credentials_microseconds`                  | `400000`                                                                     | `AUTHENTICATION_TIMEBOX_CREDENTIALS_US`                           |           | [Credential validation timing](#credential-validation-timing)         |
| `events.redacted_credential_keys`                   | `[]`                                                                         |                                                                   |           | [Events](events.md#events)                                            |
| `jwt.keys`                                          | `['default' => env('AUTHENTICATION_JWT_KEY')]`                               |                                                                   | yes       | [Key rotation](operations.md#key-rotation)                            |
| `jwt.active_kid`                                    | `default`                                                                    | `AUTHENTICATION_JWT_ACTIVE_KID`                                   | yes       | [Key rotation](operations.md#key-rotation)                            |
| `jwt.algorithm`                                     | `HS256`                                                                      | `AUTHENTICATION_JWT_ALGORITHM`                                    | yes       | [Per-guard JWT configuration](#per-guard-jwt-configuration)           |
| `jwt.access_ttl_minutes`                            | `5`                                                                          | `AUTHENTICATION_JWT_ACCESS_TTL_MINUTES`                           | yes       | [Token and session lifetimes](#token-and-session-lifetimes)           |
| `jwt.refresh_idle_ttl_minutes`                      | `129600`                                                                     | `AUTHENTICATION_JWT_REFRESH_IDLE_TTL_MINUTES`                     | yes       | [Token and session lifetimes](#token-and-session-lifetimes)           |
| `jwt.refresh_absolute_ttl_minutes`                  | `259200`                                                                     | `AUTHENTICATION_JWT_REFRESH_ABSOLUTE_TTL_MINUTES`                 | yes       | [Token and session lifetimes](#token-and-session-lifetimes)           |
| `jwt.refresh_grace_seconds`                         | `30`                                                                         | `AUTHENTICATION_JWT_REFRESH_GRACE_SECONDS`                        | yes       | [Refresh token replay](refreshing.md#refresh-token-replay)            |
| `jwt.leeway_seconds`                                | `30`                                                                         | `AUTHENTICATION_JWT_LEEWAY_SECONDS`                               | yes       | [Token and session lifetimes](#token-and-session-lifetimes)           |
| `jwt.issuer`                                        | `null`                                                                       | `AUTHENTICATION_JWT_ISSUER`                                       | yes       | [Per-guard JWT configuration](#per-guard-jwt-configuration)           |
| `jwt.audience`                                      | `null`                                                                       | `AUTHENTICATION_JWT_AUDIENCE`                                     | yes       | [Per-guard JWT configuration](#per-guard-jwt-configuration)           |
| `audience.methods`                                  | `['password']`                                                               |                                                                   | yes       | [Audiences](#audiences)                                               |
| `audience.principal_types`                          | `null`                                                                       |                                                                   | yes       | [Audiences](#audiences)                                               |
| `audience.require_verified_identifier`              | `false`                                                                      |                                                                   | yes       | [Audiences](#audiences)                                               |
| `identifiers.normalisers`                           | `['email' => EmailNormaliser::class, 'phone' => E164PhoneNormaliser::class]` |                                                                   |           | [Identifiers](identity-models.md#identifiers)                         |
| `rate_limits.table`                                 | `rate_limits`                                                                | `AUTHENTICATION_RATE_LIMITS_TABLE`                                |           | [Rate limits](#rate-limits)                                           |
| `rate_limits.connection`                            | `null`                                                                       | `AUTHENTICATION_RATE_LIMITS_CONNECTION`                           |           | [Rate limits](#rate-limits)                                           |
| `rate_limits.sign_in.per_identifier`                | 5 per 300 s                                                                  |                                                                   | yes       | [Rate limits](#rate-limits)                                           |
| `rate_limits.sign_in.per_ip`                        | 50 per 300 s                                                                 |                                                                   | yes       | [Rate limits](#rate-limits)                                           |
| `rate_limits.refresh.per_identifier`                | 10 per 60 s                                                                  |                                                                   | yes       | [Rate limits](#rate-limits)                                           |
| `rate_limits.refresh.per_ip`                        | 100 per 60 s                                                                 |                                                                   | yes       | [Rate limits](#rate-limits)                                           |
| `rate_limits.code_request.per_identifier`           | 5 per 3600 s                                                                 |                                                                   | yes       | [Rate limits](#rate-limits)                                           |
| `rate_limits.code_request.per_ip`                   | 50 per 3600 s                                                                |                                                                   | yes       | [Rate limits](#rate-limits)                                           |
| `rate_limits.passkey_options.per_identifier`        | `null`                                                                       |                                                                   | yes       | [Rate limits](#rate-limits)                                           |
| `rate_limits.passkey_options.per_ip`                | 100 per 300 s                                                                |                                                                   | yes       | [Rate limits](#rate-limits)                                           |
| `rate_limits.client_credentials.per_identifier`     | `null`                                                                       |                                                                   | yes       | [Rate limits](#rate-limits)                                           |
| `rate_limits.client_credentials.per_ip`             | 100 per 60 s                                                                 |                                                                   | yes       | [Rate limits](#rate-limits)                                           |
| `rate_limits.password_reset_request.per_identifier` | 5 per 3600 s                                                                 |                                                                   | yes       | [Rate limits](#rate-limits)                                           |
| `rate_limits.password_reset_request.per_ip`         | 50 per 3600 s                                                                |                                                                   | yes       | [Rate limits](#rate-limits)                                           |
| `rate_limits.password_reset.per_identifier`         | 10 per 900 s                                                                 |                                                                   | yes       | [Rate limits](#rate-limits)                                           |
| `rate_limits.password_reset.per_ip`                 | 50 per 900 s                                                                 |                                                                   | yes       | [Rate limits](#rate-limits)                                           |
| `rate_limits.identifier_change.per_identifier`      | 5 per 3600 s                                                                 |                                                                   | yes       | [Rate limits](#rate-limits)                                           |
| `rate_limits.identifier_change.per_ip`              | 50 per 3600 s                                                                |                                                                   | yes       | [Rate limits](#rate-limits)                                           |
| `refresh_token.sources`                             | `['body', 'header']`                                                         |                                                                   | yes       | [Refreshing](refreshing.md)                                           |
| `refresh_token.body_field`                          | `refresh_token`                                                              |                                                                   | yes       | [Refreshing](refreshing.md)                                           |
| `refresh_token.header`                              | `X-Refresh-Token`                                                            |                                                                   | yes       | [Refreshing](refreshing.md)                                           |
| `refresh_token.cookie.name`                         | `__Secure-refresh_token`                                                     |                                                                   | yes       | [Refresh token cookie](refreshing.md#refresh-token-cookie)            |
| `refresh_token.cookie.path`                         | `null`                                                                       |                                                                   | yes       | [Refresh token cookie](refreshing.md#refresh-token-cookie)            |
| `refresh_token.cookie.domain`                       | `null`                                                                       |                                                                   | yes       | [Refresh token cookie](refreshing.md#refresh-token-cookie)            |
| `refresh_token.cookie.allowed_origins`              | `[]`                                                                         |                                                                   | yes       | [Refresh token cookie](refreshing.md#refresh-token-cookie)            |
| `refresh_token.cookie.csrf_header`                  | `X-Requested-With`                                                           |                                                                   | yes       | [Refresh token cookie](refreshing.md#refresh-token-cookie)            |
| `api_keys.table`                                    | `api_keys`                                                                   | `AUTHENTICATION_API_KEYS_TABLE`                                   |           | [API key settings](#api-key-settings)                                 |
| `api_keys.prefix`                                   | `ak`                                                                         | `AUTHENTICATION_API_KEYS_PREFIX`                                  |           | [API key settings](#api-key-settings)                                 |
| `api_keys.rotation_overlap_seconds`                 | `86400`                                                                      | `AUTHENTICATION_API_KEYS_ROTATION_OVERLAP_SECONDS`                |           | [API key settings](#api-key-settings)                                 |
| `api_keys.max_rotation_overlap_seconds`             | `604800`                                                                     | `AUTHENTICATION_API_KEYS_MAX_ROTATION_OVERLAP_SECONDS`            |           | [API key settings](#api-key-settings)                                 |
| `api_keys.last_used_throttle_seconds`               | `60`                                                                         | `AUTHENTICATION_API_KEYS_LAST_USED_THROTTLE_SECONDS`              |           | [API key settings](#api-key-settings)                                 |
| `api_keys.prune_after_days`                         | `30`                                                                         | `AUTHENTICATION_API_KEYS_PRUNE_AFTER_DAYS`                        |           | [API key settings](#api-key-settings)                                 |
| `verification.link_ttl_minutes`                     | `60`                                                                         | `AUTHENTICATION_VERIFICATION_LINK_TTL_MINUTES`                    |           | [Identifier verification](identity-models.md#identifier-verification) |
| `passwords.min_length`                              | `15`                                                                         | `AUTHENTICATION_PASSWORDS_MIN_LENGTH`                             |           | [Password policy](passwords.md#password-policy)                       |
| `passwords.max_length`                              | `128`                                                                        | `AUTHENTICATION_PASSWORDS_MAX_LENGTH`                             |           | [Password policy](passwords.md#password-policy)                       |
| `passwords.letters`                                 | `false`                                                                      |                                                                   |           | [Password policy](passwords.md#password-policy)                       |
| `passwords.mixed_case`                              | `false`                                                                      |                                                                   |           | [Password policy](passwords.md#password-policy)                       |
| `passwords.numbers`                                 | `false`                                                                      |                                                                   |           | [Password policy](passwords.md#password-policy)                       |
| `passwords.symbols`                                 | `false`                                                                      |                                                                   |           | [Password policy](passwords.md#password-policy)                       |
| `passwords.breached.when_unavailable`               | `reject`                                                                     | `AUTHENTICATION_PASSWORDS_BREACHED_WHEN_UNAVAILABLE`              |           | [Password policy](passwords.md#password-policy)                       |
| `passwords.reset.link_ttl_seconds`                  | `3600`                                                                       | `AUTHENTICATION_PASSWORDS_RESET_LINK_TTL_SECONDS`                 |           | [Password reset](passwords.md#password-reset)                         |
| `identifier_changes.table`                          | `identifier_changes`                                                         | `AUTHENTICATION_IDENTIFIER_CHANGES_TABLE`                         |           | [Changing identifiers](identifier-changes.md)                         |
| `identifier_changes.ttl_seconds`                    | `3600`                                                                       | `AUTHENTICATION_IDENTIFIER_CHANGES_TTL_SECONDS`                   |           | [Changing identifiers](identifier-changes.md)                         |
| `identifier_changes.recent_authentication_seconds`  | `900`                                                                        | `AUTHENTICATION_IDENTIFIER_CHANGES_RECENT_AUTHENTICATION_SECONDS` |           | [Changing identifiers](identifier-changes.md)                         |
| `codes.table`                                       | `one_time_codes`                                                             | `AUTHENTICATION_CODES_TABLE`                                      |           | [One-time codes](#one-time-codes)                                     |
| `codes.key`                                         | `null`                                                                       | `AUTHENTICATION_CODES_KEY`                                        |           | [One-time codes](#one-time-codes)                                     |
| `codes.length`                                      | `6`                                                                          | `AUTHENTICATION_CODES_LENGTH`                                     |           | [One-time codes](#one-time-codes)                                     |
| `codes.ttl_seconds`                                 | `600`                                                                        | `AUTHENTICATION_CODES_TTL_SECONDS`                                |           | [One-time codes](#one-time-codes)                                     |
| `codes.max_attempts`                                | `5`                                                                          | `AUTHENTICATION_CODES_MAX_ATTEMPTS`                               |           | [One-time codes](#one-time-codes)                                     |
| `codes.resend_cooldown_seconds`                     | `60`                                                                         | `AUTHENTICATION_CODES_RESEND_COOLDOWN_SECONDS`                    |           | [One-time codes](#one-time-codes)                                     |
| `delivery.queue.connection`                         | `null`                                                                       | `AUTHENTICATION_DELIVERY_QUEUE_CONNECTION`                        |           | [One-time codes](#one-time-codes)                                     |
| `delivery.queue.name`                               | `null`                                                                       | `AUTHENTICATION_DELIVERY_QUEUE`                                   |           | [One-time codes](#one-time-codes)                                     |
| `passkeys.table`                                    | `passkeys`                                                                   | `AUTHENTICATION_PASSKEYS_TABLE`                                   |           | [Passkeys](#passkeys)                                                 |
| `passkeys.challenges_table`                         | `passkey_challenges`                                                         | `AUTHENTICATION_PASSKEYS_CHALLENGES_TABLE`                        |           | [Passkeys](#passkeys)                                                 |
| `passkeys.challenge_ttl_seconds`                    | `300`                                                                        | `AUTHENTICATION_PASSKEYS_CHALLENGE_TTL_SECONDS`                   |           | [Passkeys](#passkeys)                                                 |
| `passkeys.relying_party.id`                         | `null`                                                                       | `AUTHENTICATION_PASSKEYS_RP_ID`                                   | yes       | [Passkeys](#passkeys)                                                 |
| `passkeys.relying_party.name`                       | `env('APP_NAME')`                                                            | `APP_NAME`                                                        | yes       | [Passkeys](#passkeys)                                                 |
| `passkeys.relying_party.origins`                    | `[]`                                                                         |                                                                   | yes       | [Passkeys](#passkeys)                                                 |

## Storage

```php
'storage' => [
    'connection' => env('AUTHENTICATION_STORAGE_CONNECTION'),
],
```

Every table the package ships lives on `storage.connection`, the default connection when `null`: devices, pending
sign-ins, one-time codes, passkeys and their challenges, API keys, identifier changes, and the attempt counters unless
`rate_limits.connection` names a connection of their own (see [Rate limits](#rate-limits)). The shipped models read and
write them there, and the published migrations create them there: each names the storage connection as its own, so
`php artisan migrate` creates every table where the package uses it, whichever connection the migrator runs on. With
`null`, the migrations follow the migrator, as any migration that names no connection does, while the models use the
default connection, so run them on the default connection. Laravel keeps its `migrations` table on the migrator's
connection either way.

The tables share one connection because a session, the completion of a pending sign-in, a password reset and an
identifier change each write several of them in one transaction, which two connections cannot commit as one. The device
model must therefore live there too: the shipped `Device` takes the storage connection unless a subclass names a
connection of its own, and a device model, shipped or custom, on any other connection fails closed with an
`InvalidDeviceModelConfigurationException` when a `jwt` guard is built or a device is looked up, rather than splitting a
session across two transactions. Password resets and identifier changes need the identity there as well (see [Password
reset](passwords.md#password-reset) and [Changing identifiers](identifier-changes.md)). API keys need no device model:
an `api_key` guard never reads it. Connections are compared by name, a model's own or the default one, so two names for
one database count as two connections.

Identity and principal models may live on another connection, but Laravel gives a related model that names no connection
its parent's, so such a model should name its own (`protected $connection = 'mysql';`) for the device's
`authenticatable()` and `principal()` relations to load it from there. The package itself never loads an owner through
those relations.

A value that is neither a connection name nor `null` or empty fails closed with an `InvalidArgumentException` naming the
key, and `authentication:check` reports it, as it does a name `database.connections` does not configure. A model takes
the connection when it is built, so keep the setting fixed while the application runs. Changing it does not move tables
already created, and a rollback runs against the setting at the time it runs: moving the tables is a deploy, with a
migration of your own that moves them and a restart of every worker.

## Per-guard JWT configuration

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

## Token and session lifetimes

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

## Audiences

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

A principal's type is its own or its tenant's (see [Principal type](identity-models.md#principal-type)); with a list, a
principal without a type is refused. The session layer asks the guard before it issues anything: a sign-in with a method
the guard does not list fails with `method_not_allowed`, and a principal whose type it does not admit with
`principal_ineligible`, at sign-in and again on every refresh, so a valid credential for one audience cannot open or
keep a session in another. With `require_verified_identifier`, a sign-in that used an identifier (an email address for
the password method) fails with `identifier_unverified` unless the identity reports that identifier verified (see
[Identifier verification](identity-models.md#identifier-verification)); sign-ins that used no identifier, such as SSO
through `start()`, and refreshes are not gated, since the external provider or the existing session vouches for them.
The check is made before any principal is resolved, so an unverified identifier gets `identifier_unverified` whether or
not the identity has a principal yet, and the answer cannot tell whether it has been invited anywhere. A switch of
principal is held to the identifier type its session's sign-in used, which the device records.

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

## Per-guard principal resolvers

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

## Device

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
every column when it creates a device (see [Signing in](signing-in.md#signing-in-the-session-service)); `getGuard()`,
`getSignInMethod()` and `getSignInIdentifierType()` read the guard, method and type of identifier it recorded. The
bearer path and refresh honour a device only for the guard it records, refresh only while that guard still allows the
method it records, and a switch of principal admits its target with the identifier type it records (`null` for a
sign-in that used none, which is held to no type), so a device written outside the session service must record all
three.

Subclass the model or swap `device.model` entirely - custom models must implement the `EloquentDevice` contract and live
on the storage connection (see [Storage](#storage)). A device's identifier is always its primary key: tokens carry it in
`did`, and the bearer path and refresh find the device by primary key, whatever the key column is called. Other column
names come from the contract's accessors (`getRefreshKeyName()`, `getRevokedAtName()`, and so on); the shipped migration
creates the default names, so a model that renames a column needs its own migration.

A device with `revoked_at` set is rejected everywhere: an access token naming it fails exactly as if the device were
missing, and its refresh token fails with `device_revoked`. Revoking a device therefore ends its session at once rather
than when its access tokens expire. Revocation marks the row, with the time and a reason in `revoked_reason`, and clears
both refresh digests; it never deletes the row (pruning does, later). The package revokes a device when its session
signs out, when the application revokes it or signs an identity or principal out everywhere (see
[Signing out and revoking sessions](sessions.md#signing-out-and-revoking-sessions)), and when the refresh exchange
detects a replay. Revoking is idempotent, so a device that is already revoked keeps its first revocation, and
`DeviceRevoked` reports each revocation the package makes. A device whose session has ended, past its idle or absolute
deadline, is rejected the same way on the bearer path and as a sign-in pin, and fails refresh with `session_expired`
(see [Token and session lifetimes](#token-and-session-lifetimes)). An access token that names a device is accepted only
for the principal the device's session records (`principal_type`, `principal_id`), and only when it was issued no
earlier than the second of the session's last principal switch (`principal_switched_at`); otherwise it fails with
`device_principal_mismatch`. A switch therefore ends the access tokens of the principal it switched from at once, and
switching back does not revive the ones issued before it. A device that records no principal accepts no token, and a
device pinned on `attempt()` must record the principal being bound. Both checks read the row already loaded, with no
extra query. `ActsAsDevice` reads any stored timestamp as a value, with or without a `datetime` cast on the column, and
throws a `LogicException` when the device was loaded without one of its refresh or revocation state columns (both
digests, the rotation time, the session's start, the principal switch time, both deadlines, and the revocation time) or
without the sign-in's identifier type (`sign_in_identifier_type`), for example through a `devices()` relation or a
global scope that selects other columns, so a partial select is reported instead of being read as a device that is not
revoked, has no deadline, or whose sign-in used no identifier.

## Sign-in

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
`password`; anything else, or any other key in a guard's `sign_in` block, fails with an `InvalidArgumentException` when
a password sign-in runs. A sign-in that needs a further factor waits in `pending_table` (on the storage connection) for
at most `pending_ttl_seconds`, an integer from 30 to 3600 (see [Additional factors](signing-in.md#additional-factors)).

## One-time codes

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
[Signing in with a one-time code](signing-in.md#signing-in-with-a-one-time-code)) send a code of `length` digits (6 to
10), drawn uniformly with `random_int()`, that works once, for `ttl_seconds` (60 to 3600), and for at most
`max_attempts` checks (1 to 20); after that it is locked until another is requested. Another code for the same number
may be requested `resend_cooldown_seconds` (0 to `ttl_seconds`) after the last, and replaces it at once: the earlier
code stops working. Each number is an integer, or a digit string as `env()` returns one; anything else fails closed with
an `InvalidArgumentException` naming the key when a code is first issued, and `authentication:check` reports it. The
settings are global, not per guard.

Codes live in `table` (`authentication-migrations` creates `one_time_codes`), on the storage connection, one row per
binding: the purpose (a sign-in, a verification, a password reset code or link, or an identifier change), the guard, the
identifier's type and normal form and, for a verification or a change, the identity. The row is stored under an
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
`Models\OneTimeCode` beside the others (see [Pruning devices](operations.md#pruning)).

## Passkeys

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
give the browser. Both tables live on the storage connection; prune expired challenges with `model:prune` (see [Pruning
devices](operations.md#pruning)). Passkeys are not pruned: one lasts until its owner removes it. The algorithms offered
are ES256, EdDSA (when PHP's sodium extension is loaded, as it is by default) and RS256.

## Rate limits

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
| `identifier_change`      | `per_identifier` | 5 per 3600 seconds  | Every change request to the new identifier or by the identity; given back only when refused under its lock     |
| `identifier_change`      | `per_ip`         | 50 per 3600 seconds | Every change request from the IP address; given back only when refused under the identity's lock               |

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
with a `Retry-After` header. A request for a one-time code costs a message whoever has the number, so every request for
a valid number counts, whether a code is sent or the resend cooldown holds it back, and no slot is given back; the
number is counted in its normal form, whether or not anyone has it.

Identifiers are counted in their canonical form, through the normaliser of their type when one is registered (see
[Identifiers](identity-models.md#identifiers)), so every casing of an address shares one counter, and otherwise trimmed
and lower-cased. IP addresses are counted canonically too: an IPv6 client is counted by its /64 network, the block a
single client is usually given, so it cannot spread its attempts over its own addresses. An IPv6 address that carries an
IPv4 client's address, IPv4-mapped (`::ffff:0:0/96`) or translated through the NAT64 well-known prefix (`64:ff9b::/96`),
shares that IPv4 address's counter. A translator on a network-specific prefix (such as `64:ff9b:1::/48`, or your own)
puts every IPv4 client it serves into one /64 counter: resolve the client's own address before the request reaches the
guard, with Laravel's trusted proxies, so the limits see each client apart. The table holds only keyed digests
(HMAC-SHA256, under a key derived from `app.key`) of what each counter counts: the guard, flow, scope and identifier or
IP address, or, for an account, the flow and the account, without the guard. An IP address, an identifier or an account
id is easy to guess, so a plain digest of one could be reversed by anyone who reads the table (from a backup or a
replica, say); a keyed one cannot without your application key. Rotating `app.key` starts every counter afresh, and with
no `app.key` the limiter fails closed with an `InvalidArgumentException`. Every change to a count is one statement the
database applies atomically. A database error propagates as a server error: a limiter that cannot count lets nothing
through. The one exception is giving back a completed further factor's slots after its commit, which is reported instead
(see [Writing a sign-in method](signing-in.md#writing-a-sign-in-method)).

> **Transactions:** the counters live on `rate_limits.connection`, the storage connection (see [Storage](#storage)) when
> `null`. Counts written on the same connection as a transaction you open around a sign-in are rolled back with it, so a
> sign-in that your code rolls back is not counted, and attempts made that way are not limited. If you wrap sign-ins in
> transactions you may roll back, point `rate_limits.connection` at a connection of its own (a second connection to the
> same database will do). Do the same on MySQL when you call a limited flow, such as an identifier change request,
> inside a transaction of yours: until your commit, a counter's row stays locked, and so does the gap of the index a
> counter not created yet would go in, so two such transactions that each create a counter in one gap deadlock.

Ended windows stay in the table until they are pruned, as do pending sign-ins that were never completed (see
[Additional factors](signing-in.md#additional-factors)). Schedule Laravel's pruning command with both models, and the
device model, as shown in [Pruning devices](operations.md#pruning).

## API key settings

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

Keys live in `table`, on the storage connection. `prefix` (a lower-case letter, then up to 15 lower-case letters or
digits) starts every new key, so your keys are recognisable in logs and to secret scanners; changing it leaves existing
keys working. A rotation keeps the replaced key working for `rotation_overlap_seconds` unless it names its own overlap,
never beyond `max_rotation_overlap_seconds` (at most 30 days). A key's last use is recorded at most once per
`last_used_throttle_seconds` (0 to 86400; 0 records every use), and `model:prune` deletes keys revoked or expired more
than `prune_after_days` ago (0 to 3650). Each number is an integer, or a digit string as `env()` returns one; anything
else fails closed when it is used, and `authentication:check` reports it.

## Credential validation timing

`attempt()` and `validate()` wrap credential checks in a constant-time `Timebox` to prevent timing side-channels, and
the session service's `signIn()` runs its sign-in method and the checks after it in the same budget, as do a password
reset submission and the password check of `Reauthentication::password()` before an identifier change:

```php
'timebox' => [
    'credentials_microseconds' => 400000,
],
```

Must exceed the worst-case hasher cost. Only a check that succeeds returns before the budget ends, and only for itself:
every check a guard makes waits out the full budget again when it fails, however many succeeded before it on the same
guard (one guard serves a whole request, command or queue worker).
