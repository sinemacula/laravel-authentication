<?php

declare(strict_types = 1);

use SineMacula\Laravel\Authentication\Models\Device;

return [

    /*
    |---------------------------------------------------------------------------
    | Device tracking
    |---------------------------------------------------------------------------
    |
    | Configures the shipped Device Eloquent model and its underlying table.
    | Both are swappable so consumers may bring their own model class or
    | rename the table to avoid collisions with existing schemas.
    |
    */

    'device' => [
        'model'              => env('AUTHENTICATION_DEVICE_MODEL', Device::class),
        'table'              => env('AUTHENTICATION_DEVICE_TABLE', 'devices'),
        'refresh_key_column' => env('AUTHENTICATION_DEVICE_REFRESH_KEY_COLUMN', 'refresh_key'),
        // Throttle window (seconds) for the last-seen timestamp listener.
        // Writes within this window are skipped to avoid a per-request write
        // hot-spot on the device row.
        'last_seen_throttle_seconds' => (int) env('AUTHENTICATION_DEVICE_LAST_SEEN_THROTTLE_SECONDS', 60),
    ],

    /*
    |---------------------------------------------------------------------------
    | Organization scopes
    |---------------------------------------------------------------------------
    |
    | Strings used by AbstractGuard::isInternal()/isExternal() to compare
    | against the resolved organization scope. Override per environment.
    |
    */

    'scopes' => [
        'internal' => env('AUTHENTICATION_SCOPE_INTERNAL', 'internal'),
        'external' => env('AUTHENTICATION_SCOPE_EXTERNAL', 'external'),
    ],

    /*
    |---------------------------------------------------------------------------
    | Credentials
    |---------------------------------------------------------------------------
    |
    | Field name the BasicGuard passes to the identity provider when building
    | credentials from HTTP Basic headers. Override when the identity model
    | keys off `username`, `phone`, etc.
    |
    */

    'credentials' => [
        'identifier_field' => env('AUTHENTICATION_IDENTIFIER_FIELD', 'email'),
    ],

    /*
    |---------------------------------------------------------------------------
    | Credential validation timing
    |---------------------------------------------------------------------------
    |
    | Microsecond budget passed to Illuminate\Support\Timebox on the
    | credential-validation path. Must exceed the worst-case hasher cost
    | (bcrypt cost 12 ≈ 150–250ms) or timing-safety breaks down.
    |
    */

    'timebox' => [
        'credentials_microseconds' => (int) env('AUTHENTICATION_TIMEBOX_CREDENTIALS_US', 400000),
    ],

    /*
    |---------------------------------------------------------------------------
    | JWT
    |---------------------------------------------------------------------------
    |
    | Stateless JWT defaults consumed by JwtTokenService and JwtGuard.
    | Configure either `secret` (single-secret mode) or `keys` + `active_kid`
    | (kid-based rotation). The package refuses to boot with no signing
    | material. `issuer`/`audience` are optional; when set they are strictly
    | verified on every parse.
    |
    */

    'jwt' => [
        'secret' => env('AUTHENTICATION_JWT_SECRET'),

        // Optional `kid => secret` map for graceful key rotation. When
        // populated, takes precedence over `secret` above.
        'keys' => [],

        // Kid in the `keys` map that signs newly issued tokens. Required when
        // `keys` is non-empty.
        'active_kid' => env('AUTHENTICATION_JWT_ACTIVE_KID', ''),

        'algorithm'           => env('AUTHENTICATION_JWT_ALGORITHM', 'HS256'),
        'access_ttl_minutes'  => (int) env('AUTHENTICATION_JWT_ACCESS_TTL_MINUTES', 15),
        'refresh_ttl_minutes' => (int) env('AUTHENTICATION_JWT_REFRESH_TTL_MINUTES', 60 * 24 * 30),
        'leeway_seconds'      => (int) env('AUTHENTICATION_JWT_LEEWAY_SECONDS', 30),
        'issuer'              => env('AUTHENTICATION_JWT_ISSUER'),
        'audience'            => env('AUTHENTICATION_JWT_AUDIENCE'),
    ],
];
