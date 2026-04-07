<?php

declare(strict_types = 1);

return [

    /*
    |--------------------------------------------------------------------------
    | Device tracking
    |--------------------------------------------------------------------------
    |
    | Configures the shipped Device Eloquent model and its underlying table.
    | Both are swappable so consumers may bring their own model class or
    | rename the table to avoid collisions with existing schemas.
    |
    */

    'device' => [
        // @phpstan-ignore larastan.noEnvCallsOutsideOfConfig
        'model' => env('AUTHENTICATION_DEVICE_MODEL', \SineMacula\Laravel\Authentication\Models\Device::class),
        // @phpstan-ignore larastan.noEnvCallsOutsideOfConfig
        'table' => env('AUTHENTICATION_DEVICE_TABLE', 'devices'),
        // @phpstan-ignore larastan.noEnvCallsOutsideOfConfig
        'refresh_key_column' => env('AUTHENTICATION_DEVICE_REFRESH_KEY_COLUMN', 'refresh_key'),
        // Throttle window (seconds) for the last-seen timestamp listener. Writes within
        // this window are skipped to avoid a per-request write hot-spot on the device row.
        // @phpstan-ignore larastan.noEnvCallsOutsideOfConfig, cast.int
        'last_seen_throttle_seconds' => (int) env('AUTHENTICATION_DEVICE_LAST_SEEN_THROTTLE_SECONDS', 60),
    ],

    /*
    |--------------------------------------------------------------------------
    | Organization scopes
    |--------------------------------------------------------------------------
    |
    | Strings used by AbstractGuard::isInternal()/isExternal() to compare
    | against the resolved organization scope. Override per environment.
    |
    */

    'scopes' => [
        // @phpstan-ignore larastan.noEnvCallsOutsideOfConfig
        'internal' => env('AUTHENTICATION_SCOPE_INTERNAL', 'internal'),
        // @phpstan-ignore larastan.noEnvCallsOutsideOfConfig
        'external' => env('AUTHENTICATION_SCOPE_EXTERNAL', 'external'),
    ],

    /*
    |--------------------------------------------------------------------------
    | Credentials
    |--------------------------------------------------------------------------
    |
    | Field name the BasicGuard passes to the identity provider when
    | building credentials from HTTP Basic headers. Swap to `username`,
    | `phone`, or any other column your identity model uses as its
    | authentication identifier.
    |
    */

    'credentials' => [
        // @phpstan-ignore larastan.noEnvCallsOutsideOfConfig
        'identifier_field' => env('AUTHENTICATION_IDENTIFIER_FIELD', 'email'),
    ],

    /*
    |--------------------------------------------------------------------------
    | Credential validation timing
    |--------------------------------------------------------------------------
    |
    | Microsecond budget passed to Illuminate\Support\Timebox inside the
    | shared credential-validation path. Must comfortably exceed the
    | worst-case hasher cost (bcrypt cost 12 on commodity hardware is
    | typically 150–250ms) or the constant-time guarantee breaks down.
    |
    */

    'timebox' => [
        // @phpstan-ignore larastan.noEnvCallsOutsideOfConfig, cast.int
        'credentials_microseconds' => (int) env('AUTHENTICATION_TIMEBOX_CREDENTIALS_US', 400000),
    ],

    /*
    |--------------------------------------------------------------------------
    | JWT
    |--------------------------------------------------------------------------
    |
    | Stateless JWT defaults consumed by JwtTokenService and JwtGuard.
    | `secret` is REQUIRED — the JwtTokenService refuses to construct
    | with an empty secret so a missing env var fails loudly at boot
    | rather than silently accepting forged tokens. `issuer`/`audience`
    | are optional; when set they are strictly verified on every parse.
    |
    */

    'jwt' => [
        // @phpstan-ignore larastan.noEnvCallsOutsideOfConfig
        'secret' => env('AUTHENTICATION_JWT_SECRET'),
        // @phpstan-ignore larastan.noEnvCallsOutsideOfConfig
        'algorithm' => env('AUTHENTICATION_JWT_ALGORITHM', 'HS256'),
        // @phpstan-ignore larastan.noEnvCallsOutsideOfConfig, cast.int
        'access_ttl_minutes' => (int) env('AUTHENTICATION_JWT_ACCESS_TTL_MINUTES', 15),
        // @phpstan-ignore larastan.noEnvCallsOutsideOfConfig, cast.int
        'refresh_ttl_minutes' => (int) env('AUTHENTICATION_JWT_REFRESH_TTL_MINUTES', 60 * 24 * 30),
        // @phpstan-ignore larastan.noEnvCallsOutsideOfConfig, cast.int
        'leeway_seconds' => (int) env('AUTHENTICATION_JWT_LEEWAY_SECONDS', 30),
        // @phpstan-ignore larastan.noEnvCallsOutsideOfConfig
        'issuer' => env('AUTHENTICATION_JWT_ISSUER'),
        // @phpstan-ignore larastan.noEnvCallsOutsideOfConfig
        'audience' => env('AUTHENTICATION_JWT_AUDIENCE'),
    ],
];
