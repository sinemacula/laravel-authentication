<?php

declare(strict_types = 1);

use SineMacula\Laravel\Authentication\Models\Device;

return [

    /*
    |---------------------------------------------------------------------------
    | Device tracking
    |---------------------------------------------------------------------------
    |
    | Configures the package's default Eloquent device adapter. JWT refresh
    | lookup and rotation require `device.model` to be an Eloquent model
    | implementing the package `EloquentDevice` contract. Column names come from
    | that contract's accessors (e.g. `getRefreshKeyName()`); the shipped
    | migration and model use the default names, so a custom model that renames
    | a column ships its own migration. Every authentication that binds a
    | persisted EloquentDevice records when, from which IP address, and with
    | which user agent it was last used, at most once per
    | `last_used_throttle_seconds` (0 records every use).
    |
    */

    'device' => [
        'model'                      => env('AUTHENTICATION_DEVICE_MODEL', Device::class),
        'table'                      => env('AUTHENTICATION_DEVICE_TABLE', 'devices'),
        'last_used_throttle_seconds' => (int) env('AUTHENTICATION_DEVICE_LAST_USED_THROTTLE_SECONDS', 60),
    ],

    /*
    |---------------------------------------------------------------------------
    | Credential validation timing
    |---------------------------------------------------------------------------
    |
    | Microsecond budget passed to Illuminate\Support\Timebox around the
    | credential checks in a guard's `attempt()` and `validate()`. Must exceed
    | the worst-case hasher cost (bcrypt cost 12 ≈ 150–250ms) or timing-safety
    | breaks down.
    |
    */

    'timebox' => [
        'credentials_microseconds' => (int) env('AUTHENTICATION_TIMEBOX_CREDENTIALS_US', 400000),
    ],

    /*
    |---------------------------------------------------------------------------
    | Credential redaction in events
    |---------------------------------------------------------------------------
    |
    | Laravel's `Attempting` and `Failed` events receive the credentials passed
    | to a guard's `attempt()`, and any listener, queued job, or log can capture
    | them. The guards remove every key whose name contains `password`
    | (case-insensitive) before dispatching, always, and keep the rest, the
    | identifier included, for throttling and audit listeners. List further
    | key-name fragments to remove (for example `secret` or `code`) here.
    |
    */

    'events' => [
        'redacted_credential_keys' => [],
    ],

    /*
    |---------------------------------------------------------------------------
    | JWT
    |---------------------------------------------------------------------------
    |
    | Sessionless JWT defaults consumed by JwtTokenService and JwtGuard. Access
    | tokens are self-verifying and are not backed by a server-side access-token
    | store, but JwtGuard still rehydrates identity, principal, and optional
    | device state on bearer authentication. A resolved, persisted device may
    | still trigger normal device-authenticated side effects such as debounced
    | last-use writes. Signing material is always a `kid => secret` map in
    | `keys` plus the `active_kid` that signs new tokens; every token carries
    | its kid, and any kid in the map verifies. Signing is HMAC only:
    | `algorithm` must be HS256, HS384, or HS512, and every key must be at
    | least 32, 48, or 64 bytes respectively. Invalid signing material fails
    | closed when a JWT guard or token service is resolved. Every token carries
    | a `grd` claim naming the guard that issued it, and a guard rejects tokens
    | issued by any other guard, even with a shared key. `issuer`/`audience`
    | are optional; when set they are strictly verified on every parse. Each
    | must be a string or null, and `algorithm` a string, here and in a guard
    | override; any other type fails closed rather than being ignored.
    |
    */

    'jwt' => [

        // `kid => secret` map. Out of the box it holds one key, `default`, read
        // from AUTHENTICATION_JWT_KEY. To rotate, add a new kid backed by its
        // own env var (e.g. AUTHENTICATION_JWT_KEY_2026_05), point `active_kid`
        // at it, and remove the old kid once every token signed under it has
        // expired.
        'keys' => [
            'default' => env('AUTHENTICATION_JWT_KEY'),
        ],

        // Kid in the `keys` map that signs newly issued tokens.
        'active_kid' => env('AUTHENTICATION_JWT_ACTIVE_KID', 'default'),

        'algorithm' => env('AUTHENTICATION_JWT_ALGORITHM', 'HS256'),

        // Lifetimes, in minutes, each overridable per guard. An access token
        // lives `access_ttl_minutes` (1 to 1440). A session (a device) ends
        // `refresh_idle_ttl_minutes` after its last refresh, and in any case
        // `refresh_absolute_ttl_minutes` after it started (each 1 to 5256000,
        // ten years). No token outlives its session: a refresh token, and an
        // access token whose lifetime is longer, expire when it would. Values
        // must be integers, or digit strings as `env()` returns them; anything
        // else fails closed when the guard is resolved.
        'access_ttl_minutes'           => env('AUTHENTICATION_JWT_ACCESS_TTL_MINUTES', 5),
        'refresh_idle_ttl_minutes'     => env('AUTHENTICATION_JWT_REFRESH_IDLE_TTL_MINUTES', 60 * 24 * 90),
        'refresh_absolute_ttl_minutes' => env('AUTHENTICATION_JWT_REFRESH_ABSOLUTE_TTL_MINUTES', 60 * 24 * 180),

        // Seconds (0 to 300) after a refresh during which the refresh token it
        // replaced still gets the session's current credential, so a lost
        // response or a parallel refresh does not sign the client out. After
        // the window, or with 0, presenting a replaced refresh token is treated
        // as theft and revokes the device. Overridable per guard.
        'refresh_grace_seconds' => env('AUTHENTICATION_JWT_REFRESH_GRACE_SECONDS', 30),

        // Clock-skew tolerance, in seconds (0 to 300), on every token's `exp`
        // and `iat`. It never stretches a session: a device past its idle or
        // absolute deadline is rejected however recent its access token.
        'leeway_seconds' => env('AUTHENTICATION_JWT_LEEWAY_SECONDS', 30),

        'issuer'   => env('AUTHENTICATION_JWT_ISSUER'),
        'audience' => env('AUTHENTICATION_JWT_AUDIENCE'),
    ],
];
