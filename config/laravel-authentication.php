<?php

declare(strict_types=1);

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
        'model'              => env('AUTHENTICATION_DEVICE_MODEL', \SineMacula\Laravel\Authentication\Models\Device::class),
        'table'              => env('AUTHENTICATION_DEVICE_TABLE', 'devices'),
        'refresh_key_column' => env('AUTHENTICATION_DEVICE_REFRESH_KEY_COLUMN', 'refresh_key'),
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
        'internal' => env('AUTHENTICATION_SCOPE_INTERNAL', 'internal'),
        'external' => env('AUTHENTICATION_SCOPE_EXTERNAL', 'external'),
    ],

    /*
    |--------------------------------------------------------------------------
    | JWT
    |--------------------------------------------------------------------------
    |
    | Stateless JWT defaults consumed by JwtTokenService and JwtGuard.
    |
    */

    'jwt' => [
        'secret'              => env('AUTHENTICATION_JWT_SECRET'),
        'algorithm'           => env('AUTHENTICATION_JWT_ALGORITHM', 'HS256'),
        'access_ttl_minutes'  => (int) env('AUTHENTICATION_JWT_ACCESS_TTL_MINUTES', 15),
        'refresh_ttl_minutes' => (int) env('AUTHENTICATION_JWT_REFRESH_TTL_MINUTES', 60 * 24 * 30),
    ],
];
