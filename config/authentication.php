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
    | a column ships its own migration. Bearer-path last-seen persistence is
    | driven by the bound device instance itself, so it only runs when that
    | resolved device is a persisted EloquentDevice.
    |
    */

    'device' => [
        'model'                      => env('AUTHENTICATION_DEVICE_MODEL', Device::class),
        'table'                      => env('AUTHENTICATION_DEVICE_TABLE', 'devices'),
        'last_seen_throttle_seconds' => (int) env('AUTHENTICATION_DEVICE_LAST_SEEN_THROTTLE_SECONDS', 60),
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
    | last-seen writes. Signing material is always a `kid => secret` map in
    | `keys` plus the `active_kid` that signs new tokens; every token carries
    | its kid, and any kid in the map verifies. Signing is HMAC only:
    | `algorithm` must be HS256, HS384, or HS512, and every key must be at
    | least 32, 48, or 64 bytes respectively. Invalid signing material fails
    | closed when a JWT guard or token service is resolved. `issuer`/`audience`
    | are optional; when set they are strictly verified on every parse.
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

        'algorithm'           => env('AUTHENTICATION_JWT_ALGORITHM', 'HS256'),
        'access_ttl_minutes'  => (int) env('AUTHENTICATION_JWT_ACCESS_TTL_MINUTES', 15),
        'refresh_ttl_minutes' => (int) env('AUTHENTICATION_JWT_REFRESH_TTL_MINUTES', 60 * 24 * 30),
        'leeway_seconds'      => (int) env('AUTHENTICATION_JWT_LEEWAY_SECONDS', 30),
        'issuer'              => env('AUTHENTICATION_JWT_ISSUER'),
        'audience'            => env('AUTHENTICATION_JWT_AUDIENCE'),
    ],
];
