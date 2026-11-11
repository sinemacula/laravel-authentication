<?php

declare(strict_types = 1);

use SineMacula\Laravel\Authentication\Identifiers\E164PhoneNormalizer;
use SineMacula\Laravel\Authentication\Identifiers\EmailNormalizer;
use SineMacula\Laravel\Authentication\Models\Session;

return [

    /*
    |---------------------------------------------------------------------------
    | Storage
    |---------------------------------------------------------------------------
    |
    | The connection every package table lives on (`null` for the default). The
    | tables share one connection because several flows write more than one of
    | them in a single transaction. Keep it fixed while the application runs.
    |
    */

    'storage' => [
        'connection' => env('AUTHENTICATION_STORAGE_CONNECTION'),
    ],

    /*
    |---------------------------------------------------------------------------
    | Session tracking
    |---------------------------------------------------------------------------
    |
    | The default Eloquent session adapter. `session.model` must implement the
    | package `EloquentSession` contract and live on the storage connection.
    | Ended sessions are pruned by `model:prune` after `prune_after_days`.
    |
    | A pending session holds a pending credential, read from the body field
    | `pending_credential_field`, that expires after `pending_ttl_seconds`.
    |
    | `table` may be up to 47 characters, as PostgreSQL truncates longer index
    | names.
    |
    */

    'session' => [
        'model'                      => env('AUTHENTICATION_SESSION_MODEL', Session::class),
        'table'                      => env('AUTHENTICATION_SESSION_TABLE', 'authentication_sessions'),
        'pending_ttl_seconds'        => env('AUTHENTICATION_SESSION_PENDING_TTL_SECONDS', 300),
        'pending_credential_field'   => env('AUTHENTICATION_SESSION_PENDING_CREDENTIAL_FIELD', 'pending_credential'),
        'last_used_throttle_seconds' => (int) env('AUTHENTICATION_SESSION_LAST_USED_THROTTLE_SECONDS', 60),
        'prune_after_days'           => env('AUTHENTICATION_SESSION_PRUNE_AFTER_DAYS', 30),
    ],

    /*
    |---------------------------------------------------------------------------
    | Proofs
    |---------------------------------------------------------------------------
    |
    | The tables that record each session's proofs, the provenance of a session
    | an external provider established, and the per-connection guards that keep
    | sign-ins and revocations from missing each other. Each table name may be
    | up to 47 characters.
    |
    */

    'proofs' => [
        'table'            => env('AUTHENTICATION_PROOFS_TABLE', 'authentication_proofs'),
        'provenance_table' => env('AUTHENTICATION_PROOFS_PROVENANCE_TABLE', 'authentication_provenance'),
        'guards_table'     => env('AUTHENTICATION_PROOFS_GUARDS_TABLE', 'authentication_connection_guards'),
    ],

    /*
    |---------------------------------------------------------------------------
    | Revocation by connection
    |---------------------------------------------------------------------------
    |
    | Whether the session service ends sessions when a connection is disabled or
    | deleted, or a link is removed. One set to `false` returns `0` and writes
    | nothing.
    |
    */

    'revocation' => [
        'connection_disabled' => true,
        'connection_deleted'  => true,
        'link_removed'        => true,
    ],

    /*
    |---------------------------------------------------------------------------
    | Sign-in
    |---------------------------------------------------------------------------
    |
    | The identity column the password sign-in method looks identities up by. A
    | guard may name its own in
    | `auth.guards.<name>.sign_in.password_identifier`.
    |
    */

    'sign_in' => [
        'password_identifier' => env('AUTHENTICATION_SIGN_IN_PASSWORD_IDENTIFIER', 'email'),
    ],

    /*
    |---------------------------------------------------------------------------
    | Credential validation timing
    |---------------------------------------------------------------------------
    |
    | Microsecond budget for the Timebox around credential checks. It must
    | exceed the worst-case hasher cost (bcrypt cost 12 takes about 150-250ms).
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
    | Laravel's `Attempting` and `Failed` events carry the credentials passed to
    | `attempt()`. Keys containing `password` are always removed; list further
    | key-name fragments to remove here.
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
    | Signing and lifetime defaults for the JWT guards, each overridable per
    | guard. Signing is HMAC only. `issuer` and `audience` have no default and
    | must be set. A change needs a worker restart under Octane or a queue
    | worker.
    |
    */

    'jwt' => [

        // To rotate, add a kid, point `active_kid` at it, and remove the old
        // kid once every token it signed has expired.
        'keys' => [
            'default' => env('AUTHENTICATION_JWT_KEY'),
        ],

        // Kid in the `keys` map that signs newly issued tokens.
        'active_kid' => env('AUTHENTICATION_JWT_ACTIVE_KID', 'default'),

        'algorithm' => env('AUTHENTICATION_JWT_ALGORITHM', 'HS256'),

        // Minutes. Set the absolute lifetime to `null` explicitly for no limit.
        'access_ttl_minutes'           => env('AUTHENTICATION_JWT_ACCESS_TTL_MINUTES', 5),
        'refresh_idle_ttl_minutes'     => env('AUTHENTICATION_JWT_REFRESH_IDLE_TTL_MINUTES', 60 * 24 * 90),
        'refresh_absolute_ttl_minutes' => env('AUTHENTICATION_JWT_REFRESH_ABSOLUTE_TTL_MINUTES', 60 * 24 * 180),

        // Seconds a replaced refresh token still works, so a lost response or a
        // parallel refresh does not sign the client out.
        'refresh_grace_seconds' => env('AUTHENTICATION_JWT_REFRESH_GRACE_SECONDS', 30),

        // Clock-skew tolerance in seconds on `exp` and `iat`; it never extends
        // a session.
        'leeway_seconds' => env('AUTHENTICATION_JWT_LEEWAY_SECONDS', 30),

        // Required: the `iss` and `aud` of every token.
        'issuer'   => env('AUTHENTICATION_JWT_ISSUER'),
        'audience' => env('AUTHENTICATION_JWT_AUDIENCE'),
    ],

    /*
    |---------------------------------------------------------------------------
    | Applications
    |---------------------------------------------------------------------------
    |
    | The defaults every application (guard) starts from; a guard overrides any
    | of them in an `application` block on its `config/auth.php` entry.
    | `methods` is empty by default, which refuses every sign-in.
    |
    */

    'application' => [
        'methods'                     => [],
        'require_verified_identifier' => false,
        'client_secret_post'          => false,
    ],

    /*
    |---------------------------------------------------------------------------
    | Identifiers
    |---------------------------------------------------------------------------
    |
    | Normalisers keyed by identifier type, applied by the
    | `NormalizedIdentifier` cast and the `model` provider. The phone normaliser
    | accepts only E.164 numbers (see docs/guides/identity-models.md).
    |
    */

    'identifiers' => [
        'normalizers' => [
            'email' => EmailNormalizer::class,
            'phone' => E164PhoneNormalizer::class,
        ],
    ],

    /*
    |---------------------------------------------------------------------------
    | Rate limits
    |---------------------------------------------------------------------------
    |
    | Per-identifier and per-IP limits on each flow, counted in `table` so they
    | hold across servers without a cache. `null` turns a limit off. A guard
    | overrides any limit in a `rate_limits` block on its `config/auth.php`
    | entry. Counters are keyed from `app.key`, so rotating it resets every
    | window.
    |
    */

    'rate_limits' => [
        'table'      => env('AUTHENTICATION_RATE_LIMITS_TABLE', 'rate_limits'),
        'connection' => env('AUTHENTICATION_RATE_LIMITS_CONNECTION'),

        'sign_in' => [
            'per_identifier' => ['max' => 5, 'decay_seconds' => 300],
            'per_ip'         => ['max' => 50, 'decay_seconds' => 300],
        ],

        'refresh' => [
            'per_identifier' => ['max' => 10, 'decay_seconds' => 60],
            'per_ip'         => ['max' => 100, 'decay_seconds' => 60],
        ],

        'code_request' => [
            'per_identifier' => ['max' => 5, 'decay_seconds' => 3600],
            'per_ip'         => ['max' => 50, 'decay_seconds' => 3600],
        ],

        'passkey_options' => [
            'per_identifier' => null,
            'per_ip'         => ['max' => 100, 'decay_seconds' => 300],
        ],

        'client_credentials' => [
            'per_identifier' => null,
            'per_ip'         => ['max' => 100, 'decay_seconds' => 60],
        ],

        'password_reset_request' => [
            'per_identifier' => ['max' => 5, 'decay_seconds' => 3600],
            'per_ip'         => ['max' => 50, 'decay_seconds' => 3600],
        ],

        'password_reset' => [
            'per_identifier' => ['max' => 10, 'decay_seconds' => 900],
            'per_ip'         => ['max' => 50, 'decay_seconds' => 900],
        ],

        'identifier_change' => [
            'per_identifier' => ['max' => 5, 'decay_seconds' => 3600],
            'per_ip'         => ['max' => 50, 'decay_seconds' => 3600],
        ],

        'identifier_verification' => [
            'per_identifier' => ['max' => 10, 'decay_seconds' => 900],
            'per_ip'         => ['max' => 50, 'decay_seconds' => 900],
        ],

        'factor_code' => [
            'per_identifier' => null,
            'per_ip'         => ['max' => 50, 'decay_seconds' => 300],
        ],
    ],

    /*
    |---------------------------------------------------------------------------
    | Refresh token transport
    |---------------------------------------------------------------------------
    |
    | How each application's refresh token travels: `body` (the body field or
    | `header`) or `cookie` (an `HttpOnly` cookie, for a browser application). A
    | cookie application needs a `path`. A guard overrides any key in a
    | `refresh_token` block on its `config/auth.php` entry.
    |
    */

    'refresh_token' => [
        'transport'  => 'body',
        'body_field' => 'refresh_token',
        'header'     => 'X-Refresh-Token',

        'cookie' => [
            'name'            => null,
            'path'            => null,
            'allowed_origins' => [],
            'csrf_header'     => 'X-Requested-With',
        ],
    ],

    /*
    |---------------------------------------------------------------------------
    | API keys
    |---------------------------------------------------------------------------
    |
    | Keys non-human identities authenticate with, as
    | `<prefix>_<public>_<secret>`. Only the secret's SHA-256 digest is stored.
    | Revoked or expired keys are pruned by `model:prune` after
    | `prune_after_days`.
    |
    */

    'api_keys' => [
        'table'                        => env('AUTHENTICATION_API_KEYS_TABLE', 'api_keys'),
        'prefix'                       => env('AUTHENTICATION_API_KEYS_PREFIX', 'ak'),
        'rotation_overlap_seconds'     => env('AUTHENTICATION_API_KEYS_ROTATION_OVERLAP_SECONDS', 86400),
        'max_rotation_overlap_seconds' => env('AUTHENTICATION_API_KEYS_MAX_ROTATION_OVERLAP_SECONDS', 604800),
        'last_used_throttle_seconds'   => env('AUTHENTICATION_API_KEYS_LAST_USED_THROTTLE_SECONDS', 60),
        'prune_after_days'             => env('AUTHENTICATION_API_KEYS_PRUNE_AFTER_DAYS', 30),
    ],

    /*
    |---------------------------------------------------------------------------
    | Identifier verification
    |---------------------------------------------------------------------------
    |
    | How long a signed verification link stays valid, in minutes (1 to 10080).
    |
    */

    'verification' => [
        'link_ttl_minutes' => env('AUTHENTICATION_VERIFICATION_LINK_TTL_MINUTES', 60),
    ],

    /*
    |---------------------------------------------------------------------------
    | Passwords
    |---------------------------------------------------------------------------
    |
    | The policy applied to a new password. The default minimum of 15 is NIST SP
    | 800-63B's for a single-factor password. Bind a `BreachedPasswordChecker`;
    | `breached.when_unavailable` decides what happens when it cannot answer.
    |
    */

    'passwords' => [
        'min_length' => env('AUTHENTICATION_PASSWORDS_MIN_LENGTH', 15),
        'max_length' => env('AUTHENTICATION_PASSWORDS_MAX_LENGTH', 128),
        'letters'    => false,
        'mixed_case' => false,
        'numbers'    => false,
        'symbols'    => false,

        'breached' => [
            'when_unavailable' => env('AUTHENTICATION_PASSWORDS_BREACHED_WHEN_UNAVAILABLE', 'reject'),
        ],

        'reset' => [
            'link_ttl_seconds' => env('AUTHENTICATION_PASSWORDS_RESET_LINK_TTL_SECONDS', 3600),
        ],
    ],

    /*
    |---------------------------------------------------------------------------
    | Identifier changes
    |---------------------------------------------------------------------------
    |
    | Pending identifier changes wait in `table` for at most `ttl_seconds` until
    | the new identifier is proven. Prune expired changes with `model:prune`.
    |
    */

    'identifier_changes' => [
        'table'       => env('AUTHENTICATION_IDENTIFIER_CHANGES_TABLE', 'identifier_changes'),
        'ttl_seconds' => env('AUTHENTICATION_IDENTIFIER_CHANGES_TTL_SECONDS', 3600),
    ],

    /*
    |---------------------------------------------------------------------------
    | Freshness
    |---------------------------------------------------------------------------
    |
    | How recent a session's qualifying proof must be for each operation. A
    | guard overrides any operation in a `freshness` block on its
    | `config/auth.php` entry, where `null` removes it. An operation with no
    | requirement is never fresh.
    |
    */

    'freshness' => [
        'identifier_change' => [
            'max_age_seconds' => env('AUTHENTICATION_FRESHNESS_IDENTIFIER_CHANGE_SECONDS', 900),
            'proofs'          => ['first_factor', 'first_factor_reauthentication', 'external_reauthentication', 'additional_factor', 'recovery_code'],
        ],
        'password_establishment' => [
            'max_age_seconds' => env('AUTHENTICATION_FRESHNESS_PASSWORD_ESTABLISHMENT_SECONDS', 900),
            'proofs'          => ['first_factor', 'first_factor_reauthentication', 'external_reauthentication', 'additional_factor', 'recovery_code'],
        ],
        'factor_change' => [
            'max_age_seconds' => env('AUTHENTICATION_FRESHNESS_FACTOR_CHANGE_SECONDS', 900),
            'proofs'          => ['additional_factor', 'recovery_code'],
        ],
        'first_additional_factor' => [
            'max_age_seconds' => env('AUTHENTICATION_FRESHNESS_FIRST_ADDITIONAL_FACTOR_SECONDS', 900),
            'proofs'          => ['first_factor_reauthentication', 'external_reauthentication'],
        ],
    ],

    /*
    |---------------------------------------------------------------------------
    | One-time codes
    |---------------------------------------------------------------------------
    |
    | One-time codes for sign-in, verification, password resets, identifier
    | changes and factor packages. Codes are stored as an HMAC keyed with `key`
    | (at least 32 bytes) or a key derived from `app.key`. Prune expired codes
    | with `model:prune`.
    |
    */

    'codes' => [
        'table'                   => env('AUTHENTICATION_CODES_TABLE', 'one_time_codes'),
        'key'                     => env('AUTHENTICATION_CODES_KEY'),
        'length'                  => env('AUTHENTICATION_CODES_LENGTH', 6),
        'ttl_seconds'             => env('AUTHENTICATION_CODES_TTL_SECONDS', 600),
        'max_attempts'            => env('AUTHENTICATION_CODES_MAX_ATTEMPTS', 5),
        'max_deliveries'          => env('AUTHENTICATION_CODES_MAX_DELIVERIES', 3),
        'delivery_window_seconds' => env('AUTHENTICATION_CODES_DELIVERY_WINDOW_SECONDS', 1800),
        'resend_cooldown_seconds' => env('AUTHENTICATION_CODES_RESEND_COOLDOWN_SECONDS', 60),
    ],

    /*
    |---------------------------------------------------------------------------
    | Delivery
    |---------------------------------------------------------------------------
    |
    | The queue connection and name every package delivery is pushed to (`null`
    | for the defaults). A `sync` connection runs the job after the response.
    |
    */

    'delivery' => [
        'queue' => [
            'connection' => env('AUTHENTICATION_DELIVERY_QUEUE_CONNECTION'),
            'name'       => env('AUTHENTICATION_DELIVERY_QUEUE'),
        ],
    ],

    /*
    |---------------------------------------------------------------------------
    | Passkeys
    |---------------------------------------------------------------------------
    |
    | Passkey and challenge tables, and the challenge lifetime. Prune challenges
    | with `model:prune`.
    |
    | `relying_party` is the default every guard starts from; a guard overrides
    | it in a `passkeys` block on its `config/auth.php` entry. The package does
    | not consult the public suffix list, so never name a public suffix as the
    | id.
    |
    */

    'passkeys' => [
        'table'                 => env('AUTHENTICATION_PASSKEYS_TABLE', 'passkeys'),
        'challenges_table'      => env('AUTHENTICATION_PASSKEYS_CHALLENGES_TABLE', 'passkey_challenges'),
        'challenge_ttl_seconds' => env('AUTHENTICATION_PASSKEYS_CHALLENGE_TTL_SECONDS', 300),

        'relying_party' => [
            'id'      => env('AUTHENTICATION_PASSKEYS_RP_ID'),
            'name'    => env('APP_NAME'),
            'origins' => [],
        ],
    ],
];
