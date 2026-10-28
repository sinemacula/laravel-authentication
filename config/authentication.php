<?php

declare(strict_types = 1);

use SineMacula\Laravel\Authentication\Identifiers\EmailNormaliser;
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
    | `last_used_throttle_seconds` (0 records every use). Laravel's
    | `model:prune` deletes devices whose session ended (revoked, or past its
    | idle or absolute deadline) more than `prune_after_days` ago (0 to 3650,
    | counted from that end, not from creation; 0 prunes them as soon as they
    | end; an integer, or a digit string as `env()` returns one; anything else
    | fails closed when pruning runs). The shipped model opts in with the
    | `PrunesDevices` trait, as a custom model does.
    |
    */

    'device' => [
        'model'                      => env('AUTHENTICATION_DEVICE_MODEL', Device::class),
        'table'                      => env('AUTHENTICATION_DEVICE_TABLE', 'devices'),
        'last_used_throttle_seconds' => (int) env('AUTHENTICATION_DEVICE_LAST_USED_THROTTLE_SECONDS', 60),
        'prune_after_days'           => env('AUTHENTICATION_DEVICE_PRUNE_AFTER_DAYS', 30),
    ],

    /*
    |---------------------------------------------------------------------------
    | Sign-in
    |---------------------------------------------------------------------------
    |
    | The password sign-in method looks identities up by the column named in
    | `password_identifier`, which is also the identifier type the attempt
    | limits count and a guard that requires verified identifiers checks. A
    | guard whose identities are found by another column names its own in
    | `auth.guards.<name>.sign_in.password_identifier` (the only key a guard's
    | `sign_in` block may set). Either must be a lower-case column name (a
    | letter, then letters, digits, or underscores) that does not contain
    | `password`; anything else fails closed when a password sign-in runs.
    |
    | A sign-in the additional-factor policy asks a further factor of, or that
    | waits for the identity to choose its principal, waits in `pending_table`
    | (on the device model's connection) for at most `pending_ttl_seconds` (30
    | to 3600; an integer, or a digit string as `env()` returns one); anything
    | else fails closed when a pending sign-in is issued. Prune expired pending
    | sign-ins with `model:prune`.
    |
    */

    'sign_in' => [
        'password_identifier' => env('AUTHENTICATION_SIGN_IN_PASSWORD_IDENTIFIER', 'email'),
        'pending_table'       => env('AUTHENTICATION_SIGN_IN_PENDING_TABLE', 'pending_sign_ins'),
        'pending_ttl_seconds' => env('AUTHENTICATION_SIGN_IN_PENDING_TTL_SECONDS', 300),
    ],

    /*
    |---------------------------------------------------------------------------
    | Credential validation timing
    |---------------------------------------------------------------------------
    |
    | Microsecond budget passed to Illuminate\Support\Timebox around the
    | credential checks in a guard's `attempt()` and `validate()`, and around
    | a session service `signIn()` from its sign-in method to its admission.
    | Must exceed the worst-case hasher cost (bcrypt cost 12 ≈ 150–250ms) or
    | timing-safety breaks down.
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

        // Lifetimes per principal type are set per guard only, in
        // `auth.guards.<name>.jwt.by_principal_type.<type>`, with any of
        // `access_ttl_minutes`, `refresh_idle_ttl_minutes` and
        // `refresh_absolute_ttl_minutes`; each falls back to the guard's value.
    ],

    /*
    |---------------------------------------------------------------------------
    | Audiences
    |---------------------------------------------------------------------------
    |
    | An audience is a guard. These are the defaults every guard starts from; a
    | guard overrides any of them in an `audience` block on its
    | `config/auth.php` entry, where a key that is present wins, `null`
    | included. `methods` lists the sign-in methods that may start the guard's
    | sessions (a non-empty list of the lower-case names they are registered
    | under). `principal_types` lists the principal types that may hold them (a
    | non-empty list), or is `null` to admit any principal, typed or not; with a
    | list, an untyped principal is refused. `require_verified_identifier`
    | refuses a sign-in with an identifier (an email address, say) the identity
    | has not verified; sign-ins that use no identifier, such as SSO, are not
    | affected. A malformed value, or an unknown key, fails closed with an
    | `InvalidArgumentException` naming the guard and the key when the guard's
    | policy is first used.
    |
    */

    'audience' => [
        'methods'                     => ['password'],
        'principal_types'             => null,
        'require_verified_identifier' => false,
    ],

    /*
    |---------------------------------------------------------------------------
    | Identifiers
    |---------------------------------------------------------------------------
    |
    | Normalisers bring an identifier a person types to the one form it is
    | stored and looked up in, keyed by identifier type (a lower-case name).
    | Designate an identity attribute with the `NormalisedIdentifier` cast
    | (`'email' => NormalisedIdentifier::using('email')`) and the attribute is
    | normalised when it is set, the `model` provider normalises it before it
    | looks an identity up, and attempts are counted against its normal form.
    | Each value is a container abstract resolving to an
    | `IdentifierNormaliser`; the email normaliser trims and lower-cases.
    |
    */

    'identifiers' => [
        'normalisers' => [
            'email' => EmailNormaliser::class,
        ],
    ],

    /*
    |---------------------------------------------------------------------------
    | Rate limits
    |---------------------------------------------------------------------------
    |
    | Limits on each flow, per identifier and per IP address, counted in the
    | `table` on the write PDO of `connection` (`null` for the default), so they
    | hold across servers without a cache. Each limit allows `max` attempts (at
    | least 1) in each window of `decay_seconds` (1 to 86400), windows aligned
    | to the clock; `null` turns it off. Sign-in counts every attempt and gives
    | a successful one back; a secret a method checks against an account also
    | counts against that account under `per_identifier`, however the account
    | was found, in one count the account keeps across guards, which each guard
    | holds to its own limit, so the guard with the most permissive limit bounds
    | the account's guesses. An IPv6 address counts by its /64 network, and one
    | that carries an IPv4 client's address (IPv4-mapped, or the NAT64
    | well-known prefix `64:ff9b::/96`) as that IPv4 address. Refresh, which
    | cannot guess a secret, counts only failures, per device and per IP
    | address. Counts on `connection` are rolled back with any transaction a
    | caller opened there around a sign-in. A guard overrides any limit in a
    | `rate_limits` block on its `config/auth.php` entry, where a scope that is
    | present wins, `null` included, and a flow set to `null` turns both of its
    | limits off. A malformed limit or an unknown key fails closed with an
    | `InvalidArgumentException` naming the guard and the key. Counters are
    | stored under digests keyed from `app.key`, so rotating it starts every
    | window afresh. Prune ended windows with `model:prune`.
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
    ],

    /*
    |---------------------------------------------------------------------------
    | Refresh token transport
    |---------------------------------------------------------------------------
    |
    | Where `JwtGuard::refreshFromRequest()` reads a refresh token from: any of
    | `cookie`, `body` (`body_field` of the JSON or form body, never the query
    | string) and `header`. Only the listed sources are read, and a request
    | that carries a token in more than one of them is refused
    | (`refresh_token_conflict`), so the cookie's cross-site checks cannot be
    | side-stepped by also sending the token another way. A token read from the
    | cookie must come with an `Origin` that is the request's own or one of
    | `allowed_origins` (each exactly `scheme://host[:port]`, in lower case)
    | and a non-empty `csrf_header` header, else `cross_site_request`. The
    | cookie's `path`, the path the refresh and switch routes live under, is
    | required when the cookie is a source; `domain` is `null` for the
    | request's host only. `Auth::refreshTransport($guard)->cookie()` makes
    | the cookie (`HttpOnly`, `Secure`, `SameSite=Strict`, expiring with the
    | session) and `forgetCookie()` the one that clears it. A guard overrides
    | any key in a `refresh_token` block on its `config/auth.php` entry, where
    | a key that is present wins, inside `cookie` too. A malformed value or an
    | unknown key fails closed with an `InvalidArgumentException` naming the
    | guard and the key.
    |
    */

    'refresh_token' => [
        'sources'    => ['body', 'header'],
        'body_field' => 'refresh_token',
        'header'     => 'X-Refresh-Token',

        'cookie' => [
            'name'            => '__Secure-refresh_token',
            'path'            => null,
            'domain'          => null,
            'allowed_origins' => [],
            'csrf_header'     => 'X-Requested-With',
        ],
    ],

    /*
    |---------------------------------------------------------------------------
    | Identifier verification
    |---------------------------------------------------------------------------
    |
    | How long a signed verification link stays valid, in minutes (1 to 10080,
    | a week); `VerificationLinks::create()` may set a lifetime of its own in
    | the same range. A value of another type or out of range fails closed when
    | a link is created.
    |
    */

    'verification' => [
        'link_ttl_minutes' => env('AUTHENTICATION_VERIFICATION_LINK_TTL_MINUTES', 60),
    ],
];
