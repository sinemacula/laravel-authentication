<?php

declare(strict_types = 1);

use SineMacula\Laravel\Authentication\Identifiers\E164PhoneNormaliser;
use SineMacula\Laravel\Authentication\Identifiers\EmailNormaliser;
use SineMacula\Laravel\Authentication\Models\Device;

return [

    /*
    |---------------------------------------------------------------------------
    | Storage
    |---------------------------------------------------------------------------
    |
    | The connection every package table lives on (`null` for the default):
    | devices, pending sign-ins, one-time codes, passkeys and their challenges,
    | API keys, identifier changes, and the rate limit counters unless
    | `rate_limits.connection` names their own. The models read and write them
    | there, and the published migrations create them there. They share one
    | connection because a session, the completion of a pending sign-in, a
    | password reset and an identifier change each write several of them in one
    | transaction, which two connections cannot commit as one: a custom device
    | model must live on it too, or every device flow fails closed, and password
    | resets and identifier changes need the identity there as well. A value
    | that is neither a connection name nor `null` or empty fails closed when a
    | model is built, and `authentication:check` reports it, as it does a name
    | `database.connections` does not configure. Keep it fixed while the
    | application runs: moving the tables is a deploy, with a migration the
    | application performs and a worker restart.
    |
    */

    'storage' => [
        'connection' => env('AUTHENTICATION_STORAGE_CONNECTION'),
    ],

    /*
    |---------------------------------------------------------------------------
    | Device tracking
    |---------------------------------------------------------------------------
    |
    | Configures the package's default Eloquent device adapter. JWT refresh
    | lookup and rotation require `device.model` to be an Eloquent model
    | implementing the package `EloquentDevice` contract, on the storage
    | connection (the shipped model takes it, unless a subclass names its own).
    | Column names come from that contract's accessors (e.g.
    | `getRefreshKeyName()`); the shipped migration and model use the default
    | names, so a custom model that renames a column ships its own migration.
    | Every authentication that binds a persisted EloquentDevice records when,
    | from which IP address, and with which user agent it was last used, at most
    | once per `last_used_throttle_seconds` (0 records every use). Laravel's
    | `model:prune` deletes devices whose session ended (revoked, or past its
    | idle or absolute deadline) more than `prune_after_days` ago (0 to 3650,
    | counted from that end, not from creation; 0 prunes them as soon as they
    | end; an integer, or a digit string as `env()` returns one; anything else
    | fails closed when pruning runs, and `authentication:check` reports it).
    | The shipped model opts in with the `PrunesDevices` trait, as a custom
    | model does.
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
    | (on the storage connection) for at most `pending_ttl_seconds` (30 to 3600;
    | an integer, or a digit string as `env()` returns one); anything else fails
    | closed when a pending sign-in is issued, and `authentication:check`
    | reports it. Prune expired pending sign-ins with `model:prune`.
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
    | credential checks in a guard's `attempt()` and `validate()`, around a
    | session service `signIn()` from its sign-in method to its admission,
    | around a password reset submission, and around the password check that
    | reauthenticates an identifier change. Must exceed the worst-case hasher
    | cost (bcrypt cost 12 ≈ 150–250ms) or timing-safety breaks down.
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
    | sessions, by the lower-case names they are registered under, and the
    | machine credentials it accepts (`api_key`, `client_credentials`): a
    | non-empty list. `principal_types` lists the principal types that may hold
    | them (a non-empty list), or is `null` to admit any principal, typed or
    | not; with a list, an untyped principal is refused.
    | `require_verified_identifier` refuses a sign-in with an identifier (an
    | email address, say) the identity has not verified; sign-ins that use no
    | identifier, such as SSO, are not affected. A malformed value, or an
    | unknown key, fails closed with an `InvalidArgumentException` naming the
    | guard and the key when the guard's policy is first used.
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
    | `IdentifierNormaliser`; the email normaliser trims and lower-cases. The
    | phone normaliser accepts only numbers already in E.164 form (`+` and up
    | to 15 digits) and refuses anything else: an application that takes
    | mobile or free-form numbers binds its own normaliser under `phone`,
    | backed by `giggsey/libphonenumber-for-php` (see
    | docs/guides/identity-models.md).
    |
    */

    'identifiers' => [
        'normalisers' => [
            'email' => EmailNormaliser::class,
            'phone' => E164PhoneNormaliser::class,
        ],
    ],

    /*
    |---------------------------------------------------------------------------
    | Rate limits
    |---------------------------------------------------------------------------
    |
    | Limits on each flow, per identifier and per IP address, counted in the
    | `table` on the write PDO of `connection` (`null` for the storage
    | connection), so they hold across servers without a cache. Each limit
    | allows `max` attempts (at least 1) in each window of `decay_seconds` (1 to
    | 86400), windows aligned to the clock; `null` turns it off. Sign-in counts
    | every attempt and gives a successful one back; a secret a method checks
    | against an account also counts against that account under
    | `per_identifier`, however the account was found, in one count the account
    | keeps across guards, which each guard holds to its own limit, so the guard
    | with the most permissive limit bounds the account's guesses. An IPv6
    | address counts by its /64 network, and one that carries an IPv4 client's
    | address (IPv4-mapped, or the NAT64 well-known prefix `64:ff9b::/96`) as
    | that IPv4 address. Refresh, which cannot guess a secret, counts only
    | failures, per device and per IP address. A request for a one-time code
    | counts every request, per identifier and per IP address, and never gives
    | one back. A request for passkey sign-in options counts every request per
    | IP address (it names no identifier, so its `per_identifier` must stay
    | `null`). A client credentials exchange counts only failures, per IP
    | address; not per client id by default, since a client id is not a secret
    | and a count on it would let anyone who knows it lock the client out. A
    | request for a password reset link or code counts every request, per
    | identifier and per IP address, and never gives one back
    | (`password_reset_request`); a reset submission counts every submission,
    | per the identifier it names and per IP address, before anything else is
    | checked, and gives a successful one back (`password_reset`); both count an
    | identifier no one holds the same. A request to change an identifier counts
    | every request against the new identifier, under `per_identifier`, the
    | identity's own account under the same limit, and the IP address, and gives
    | them back only when it is refused under the identity's lock
    | (`identifier_change`). Counts on `connection` are rolled back with any
    | transaction a caller opened there around a sign-in. A guard overrides any
    | limit in a `rate_limits` block on its `config/auth.php` entry, where a
    | scope that is present wins, `null` included, and a flow set to `null`
    | turns both of its limits off. A malformed limit or an unknown key fails
    | closed with an `InvalidArgumentException` naming the guard and the key.
    | Counters are stored under digests keyed from `app.key`, so rotating it
    | starts every window afresh. Prune ended windows with `model:prune`.
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
    ],

    /*
    |---------------------------------------------------------------------------
    | Refresh token transport
    |---------------------------------------------------------------------------
    |
    | Where `JwtGuard::refreshFromRequest()` reads a refresh token from: any of
    | `cookie`, `body` (`body_field` of the JSON or form body, never the query
    | string) and `header`. Only the listed sources are read, and a request
    | that carries a token in more than one of them, or the cookie twice, is
    | refused (`refresh_token_conflict`), so the cookie's cross-site checks
    | cannot be side-stepped by also sending the token another way. A token
    | read from the cookie must come with an `Origin` that is the request's own
    | or one of `allowed_origins` (each exactly `scheme://host[:port]`, in
    | lower case) and a non-empty `csrf_header` header (a custom one: a
    | header a browser sends on its own is refused), else
    | `cross_site_request`. The cookie's `path`, the path the sign-in, refresh
    | and switch routes live under, is required when the cookie is a source;
    | `domain` is `null` for the request's host only. A `__Host-` name needs
    | the `path` `/` and no `domain` on a guard that reads the cookie. Names
    | PHP renames in a request are refused: a `.` in a header or cookie name,
    | and a `.`, a space or a bracket in `body_field`.
    | `Auth::refreshTransport($guard)->cookie()` makes the cookie (`HttpOnly`,
    | `Secure`, `SameSite=Strict`, expiring with the session) and
    | `forgetCookie()` the one that clears it. A guard overrides any key in a
    | `refresh_token` block on its `config/auth.php` entry, where a key that is
    | present wins, inside `cookie` too. A malformed value or an unknown key
    | fails closed with an `InvalidArgumentException` naming the guard and the
    | key.
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
    | API keys
    |---------------------------------------------------------------------------
    |
    | Keys non-human identities authenticate with, on an `api_key` guard (as
    | `Authorization: Bearer <key>`) or, as an OAuth client's id and secret, in
    | a `jwt` guard's client credentials exchange. Stored in `table`, on the
    | storage connection. A key is `<prefix>_<public>_<secret>`: `prefix` (a
    | lower-case letter, then up to 15 lower-case letters or digits) marks the
    | keys an application issues, so they are recognisable in logs and secret
    | scanners; changing it leaves existing keys working. Only the secret's
    | SHA-256 digest is stored. A rotation keeps the replaced key working for
    | `rotation_overlap_seconds` (0 to `max_rotation_overlap_seconds`, itself 0
    | to 2592000, 30 days) unless the rotation names its own overlap within the
    | maximum; the replacement expires only when the rotation names an expiry. A
    | key's last use is recorded at most once per `last_used_throttle_seconds`
    | (0 to 86400; 0 records every use). Laravel's `model:prune` deletes keys
    | revoked or expired more than `prune_after_days` ago (0 to 3650). Each
    | value is an integer, or a digit string as `env()` returns one; anything
    | else fails closed when it is used, and `authentication:check` reports it.
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
    | How long a signed verification link stays valid, in minutes (1 to 10080,
    | a week); `VerificationLinks::create()` may set a lifetime of its own in
    | the same range. A value of another type or out of range fails closed when
    | a link is created.
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
    | The policy `Auth::passwords()->check()` and `set()` apply to a new
    | password (never to the automatic rehash on sign-in). A password has at
    | least `min_length` characters (8 to 128) and at most `max_length`
    | (`min_length` to 4096), counted as Laravel's `min` and `max` rules count
    | them; each is an integer, or a digit string as `env()` returns one. The
    | default minimum of 15 is NIST SP 800-63B's for a password that is the only
    | factor; an application that always requires a further factor may lower it
    | to 8. While the hashing driver is bcrypt, which reads only 72 bytes, a
    | longer password is refused as too long and `min_length` may be at most 72,
    | and a password holding a null character, which bcrypt cannot hash, is
    | refused as well. `letters`, `mixed_case`, `numbers` and `symbols`
    | (booleans, off by default, as NIST advises) turn on the composition rules
    | of Laravel's `Password` rule. A password that passes is then given to the
    | bound `BreachedPasswordChecker`: the default one blocks nothing, and NIST
    | expects a blocklist check, so bind one of your own. When the checker
    | cannot answer (it throws `BreachedPasswordCheckUnavailableException`) the
    | exception is reported and `breached.when_unavailable` decides: `reject`
    | refuses the password (fail closed, the default), `allow` lets it through
    | (fail open). A password reset link works for `reset.link_ttl_seconds` (300
    | to 86400) after it is requested; a reset code lives as long as any
    | one-time code (see `codes`), and both share the codes' table, key and
    | resend cooldown. Requests for either are limited by the
    | `password_reset_request` rate limits, and submissions by the
    | `password_reset` ones. A malformed value fails closed when a password is
    | first checked, and `authentication:check` reports it.
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
    | `Auth::identifierChanges($guard)` changes an identity's email address or
    | phone number only once the new one is proven, by a one-time code sent to
    | it or a signed link the application sends it; until then the identity
    | keeps the current one. A request must come within
    | `recent_authentication_seconds` (60 to 86400) of the identity's sign-in on
    | the device it is made from, or of a proof the application confirmed
    | itself, or give the current password. It waits in `table`, on the storage
    | connection, for at most `ttl_seconds` (300 to 86400; a code request also
    | no longer than its code), and a newer request for the same identity and
    | type replaces it. Requests are limited by the `identifier_change` rate
    | limits, counted on the new identifier and on the identity. Each number is
    | an integer, or a digit string as `env()` returns one; anything else fails
    | closed when a change is first requested or confirmed, and
    | `authentication:check` reports it. The application binds an
    | `IdentifierChangeNotifier` to tell the old identifier; the change stands
    | if that notice fails. Prune expired changes with `model:prune`.
    |
    */

    'identifier_changes' => [
        'table'                         => env('AUTHENTICATION_IDENTIFIER_CHANGES_TABLE', 'identifier_changes'),
        'ttl_seconds'                   => env('AUTHENTICATION_IDENTIFIER_CHANGES_TTL_SECONDS', 3600),
        'recent_authentication_seconds' => env('AUTHENTICATION_IDENTIFIER_CHANGES_RECENT_AUTHENTICATION_SECONDS', 900),
    ],

    /*
    |---------------------------------------------------------------------------
    | One-time codes
    |---------------------------------------------------------------------------
    |
    | The `phone_code` and `email_code` sign-in methods, and verifying an
    | identifier by code, send a code of `length` digits (6 to 10) that works
    | once, for `ttl_seconds` (60 to 3600), and for at most `max_attempts`
    | checks (1 to 20), after which it is locked until another is requested.
    | Another code for the same identifier may be requested
    | `resend_cooldown_seconds` (0 to `ttl_seconds`) after the last, and
    | replaces it at once. Each number is an integer, or a digit string as
    | `env()` returns one. Codes are stored in `table`, on the storage
    | connection, as an HMAC keyed with `key` (at least 32 bytes), or with a key
    | derived from `app.key` when `key` is not set; rotating either only
    | invalidates the codes outstanding. Requests for codes are limited by the
    | `code_request` rate limits. Delivery is a queued job (see `delivery`). The
    | application binds its `OneTimeCodeSender`. A malformed value fails closed
    | when a code is first issued, and `authentication:check` reports it. Prune
    | expired codes with `model:prune`.
    |
    */

    'codes' => [
        'table'                   => env('AUTHENTICATION_CODES_TABLE', 'one_time_codes'),
        'key'                     => env('AUTHENTICATION_CODES_KEY'),
        'length'                  => env('AUTHENTICATION_CODES_LENGTH', 6),
        'ttl_seconds'             => env('AUTHENTICATION_CODES_TTL_SECONDS', 600),
        'max_attempts'            => env('AUTHENTICATION_CODES_MAX_ATTEMPTS', 5),
        'resend_cooldown_seconds' => env('AUTHENTICATION_CODES_RESEND_COOLDOWN_SECONDS', 60),
    ],

    /*
    |---------------------------------------------------------------------------
    | Delivery
    |---------------------------------------------------------------------------
    |
    | Everything the package sends (one-time codes, password reset links and
    | codes, identifier change codes and notices) is a queued job, never part
    | of the request, pushed once the write it reports has committed to the
    | `queue` connection and queue named (`null` for the defaults; the
    | connection must be configured in `queue.connections`). On a `sync`
    | connection it runs after the response is sent, and a `failover`
    | connection that can fall back to `sync` is pushed to after the response;
    | `authentication:check` warns about both while any `jwt` guard is
    | configured, since a worker is the production setting. A malformed value
    | fails closed before anything is counted or sent, and
    | `authentication:check` reports it.
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
    | Passkeys (WebAuthn credentials) are kept in `table` and the ceremonies'
    | single-use challenges in `challenges_table`, both on the package's storage
    | connection. A challenge lives `challenge_ttl_seconds` (30 to 600; an
    | integer, or a digit string as `env()` returns one), which is also the
    | `timeout` the options give the browser. Prune expired challenges with
    | `model:prune`.
    |
    | `relying_party` is the default every guard starts from; a guard
    | overrides any of its keys in a `passkeys` block on its `config/auth.php`
    | entry, where a key that is present wins. `id` is the relying party id: a
    | lower-case host name (not an IP address), required on every guard that
    | uses passkeys, which every credential is scoped to. `name` is the name
    | the browser shows, by default `app.name`. `origins` lists the exact
    | origins the ceremonies may run on, each `https://host[:port]` (or
    | `http://localhost[:port]` for development), in lower case, whose host is
    | the relying party id or a subdomain of it; the package does not consult
    | the public suffix list, so never name a public suffix as the id. A
    | malformed value or an unknown key fails closed with an
    | `InvalidArgumentException` naming the guard and the key when the guard's
    | passkeys are first used, and `authentication:check` reports it for every
    | guard whose audience allows `passkey` or that sets a `passkeys` block.
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
