# Operations

Running the package in production: where its reads go, what a long-running process keeps between requests and jobs,
which settings it reads once, rotating signing keys, pruning the rows sessions and credentials leave behind, and checking
the configuration before a deploy.

## Read replicas

Every read that decides authentication - the identity, the principal and the tenant it acts within, and the device with
its guard, sign-in method, refresh digests, rotation time, session deadlines and revocation state - goes to the write
connection, even when the database connection has `read` and `write` hosts. A replica can lag behind a revocation, a
deactivation, a refresh rotation, or an ended session, and a lookup it served could admit a credential the primary has
already rejected.

The package pins the lookups it makes, including the relations the identity, principal and device models eager-load
(`$with`), on whichever connection those relations live (a tenant in a separate landlord database, say). Code you plug
in carries the same obligation:

- a custom `IdentityProvider`, a `ModelProvider` subclass that builds its own query, or a custom `PrincipalResolver`
  must read from the write connection, including the relations its results eager-load;
- `resolveDefaultPrincipal()`, `resolveHintedPrincipal()`, `devices()` and, when `ModelProvider` checks a password,
  `getAuthPassword()` already run inside `WriteConnection::during()` for the identity, `getTenant()` for the principal,
  `isActive()` for the model it belongs to, and a device's guard, sign-in method, refresh state, session deadlines and
  revocation for the device: every model read made there, on any connection, goes to that connection's writer, and so
  does a query-builder read on the model's own connection. A query-builder or `DB` read on another connection, or made
  by a principal or identity that is not an Eloquent model, must pin itself.

`WriteConnection` does both. `query()` routes a single query; Eloquent fetches eager-loaded relations with separate
queries that it does not reach, so run a lookup whose results load relations inside `during()`, which pins every
connection a model resolves while its callback runs, plus the given model's own connection:

```php
use SineMacula\Laravel\Authentication\Database\WriteConnection;

// A query you build: route it to the write PDO, scoped to the identity.
$membership = WriteConnection::query(Membership::query()->where('identity_id', $identity->getKey()))->find($hint);

// Model reads on any connection, eager loads included, plus the identity's connection.
$principal = WriteConnection::during($identity, fn () => $this->lookUpPrincipal($identity));
```

## Long-running processes

One application can serve many requests (Octane) or run many queued jobs (a queue worker), so nothing one of them binds
may reach the next.

Octane serves each request in a sandbox: a copy of the application the worker booted, with a configuration of its own
and the request bound, and it forgets the booted application's scoped instances once each request ends, so a scoped
instance is resolved afresh for every request but one the application resolved at boot, which serves the first. Its
`FlushAuthenticationState` listener hands the auth manager the sandbox and forgets the guards, so each request resolves
the package guards again and authenticates from its own token or API key, or not at all: the identity, principal,
device, tenant and scopes one request bound, a refusal and a logout are gone for the next. `Auth::sessions()`,
`Auth::jwt()`, `Auth::codes()`, `Auth::apiKeys()`, `Auth::clientCredentials()` and the other services act on the
sandbox: its request (the client their events and devices record), its configuration (a value one request changes
applies to that request alone) and the dispatcher bound in it. The sign-in methods are built with the sandbox too, a
method registered at boot included, and so are the revoking listeners' session services, though the event dispatcher
builds those listeners with the booted application. Keep Octane's default listeners (`FlushAuthenticationState` and
`FlushTemporaryContainerInstances` among them), and leave the package's services out of `octane.warm`: a service warmed
at boot keeps the booted configuration, so a request that changes its own would not reach it. The package is tested
through Octane's own worker, sandbox and listeners (without a server), across sequences of requests.

Outside Octane, each request rebinds Laravel's `request`, which resets every package guard already resolved: the
identity, principal and device it bound, and whether it has resolved the request. A queue worker forgets only scoped
instances between jobs, so the package resets its guards when each job a worker runs starts (on `JobProcessing`,
through `AuthManager::forgetGuardState()`): a guard a job signs in with `login()` or `setUser()` is signed out again
for the next job. Only jobs a worker runs are reset: a job on the `sync` connection (the `sync` driver, or
`dispatchSync()` whatever the default connection) runs inside the request that dispatched it and leaves its guards as
they are, so a session the request just started stays bound and a request that signed out stays signed out. A
dispatcher or principal resolver swapped in after a guard resolved (`Event::fake()`, a rebinding of
`PrincipalResolver`) reaches the guard, its refresh exchange and its session service (and, through it, a switch of
principal and the revocations), which read the guard's collaborators each time they run.

The package's singletons hold configuration only: the token service factory memoises each guard's signing configuration
(see [Configuration lifetimes](#configuration-lifetimes)), not any identity's data, and the mark the password-change
listener reads during an automatic rehash is scoped, so it starts empty for each request and each job a worker runs
(under Octane, every request after the first when the application resolved it at boot). `WriteConnection::during()`
swaps Eloquent's process-wide connection resolver while its callback runs and restores it, and each connection's read
mode, when the callback returns or throws, so the next request reads as configured. No package class keeps a request, an
identity or a token in a static property. The sign-in methods you register are kept as long as the application serving
them, so they must hold no state between calls (see [Writing a sign-in method](signing-in.md#writing-a-sign-in-method)),
and so must a factor or audience policy you bind as a singleton.

## Configuration lifetimes

Laravel loads the configuration when the application boots, so a change to `config/authentication.php` or `.env` reaches
a long-running process only once it restarts: rebuild the configuration cache (`php artisan config:cache`) if you use
one, then restart the workers (`php artisan octane:reload`, `php artisan queue:restart`). A PHP-FPM request boots afresh
each time. Treat the package's configuration as fixed for a deployment.

Within one process, most settings are read each time they are used, so a value changed at runtime (`config([...])`, as a
test does) applies from the next use. Two kinds are read once and kept:

| Settings                                               | Read                                                   | Kept for                                                      |
|--------------------------------------------------------|--------------------------------------------------------|---------------------------------------------------------------|
| `authentication.jwt.*` and the guard's `jwt` block     | when the guard is built, or `Auth::jwt()` first called | the token service factory's life: a queue worker's whole life |
| A guard's `provider` and `principal_resolver` override | when the guard is built                                | the guard's life: one request, or a queue worker's whole life |

The token service factory is a singleton that builds each guard's token service (its keys, active kid, algorithm,
lifetimes, those per principal type included, refresh grace, leeway, issuer and audience) once, so a runtime change to a
JWT setting does not reach a token service already built, even for a guard built afterwards. Nor does it reach the
lifetimes per principal type the audience policy applies, which come from the token service; the rest of the audience
settings, the rate limits and every other setting are read anew. A queue worker resets its guards between jobs rather
than rebuilding them, so it keeps both kinds for as long as it runs. To change a kept setting, change the configuration
and restart the worker, as above.

Under Octane, each request runs in a copy of the application with its own copy of the configuration. A singleton first
resolved while a request is served, the token service factory included, lives only as long as that request; one resolved
before the first request (warmed through Octane's `warm` list, or resolved while the application boots) lives as long as
the worker, and one built with the configuration repository, such as the attempt limiter or the audience policy, then
reads the worker's configuration, not the request's copy.

## Key Rotation

Signing keys live in `jwt.keys` as a `kid → secret` map, and `jwt.active_kid` names the key that signs new tokens.
New tokens carry the active kid in their JWT header; the verifier accepts any kid in the map. To rotate, add the new
key to the published `config/authentication.php` alongside the current one and point `active_kid` at it:

```php
'jwt' => [
    'keys' => [
        'default' => env('AUTHENTICATION_JWT_KEY'),
        '2026-05' => env('AUTHENTICATION_JWT_KEY_2026_05'),
    ],
    'active_kid' => env('AUTHENTICATION_JWT_ACTIVE_KID', 'default'),
],
```

Generate the new key into `.env`, then set `AUTHENTICATION_JWT_ACTIVE_KID` to its kid:

```bash
echo "AUTHENTICATION_JWT_KEY_2026_05=$(openssl rand -base64 48)" >> .env
```

```dotenv
AUTHENTICATION_JWT_ACTIVE_KID="2026-05"
```

Tokens signed under `default` keep verifying while it stays in the map. Remove it once every token signed under it
has expired: a refresh token never outlives its session, so at most the absolute session lifetime after the switch.
Removing a kid immediately rejects every token signed under it, which is also how to revoke a compromised key.

## Pruning

Rows whose use has ended stay in their tables until Laravel's `model:prune` deletes them, each model in chunks of one
conditional `DELETE` that reads nothing:

| Model                     | Pruned once                                                                           |
|---------------------------|---------------------------------------------------------------------------------------|
| `Models\Device`           | its session has been over (revoked, or past a deadline) for `device.prune_after_days` |
| `Models\PendingSignIn`    | it has expired                                                                        |
| `Models\RateLimit`        | its window has ended                                                                  |
| `Models\OneTimeCode`      | it has expired                                                                        |
| `Models\PasskeyChallenge` | it has expired                                                                        |
| `Models\ApiKey`           | it was revoked or expired more than `api_keys.prune_after_days` ago                   |
| `Models\IdentifierChange` | it has expired                                                                        |

Passkeys are never pruned: one lasts until its owner removes it.

Revoked and ended devices are kept for audit: a device is pruned once its session has been over for
`device.prune_after_days` (default 30, from 0 to 3650), counted from when it was revoked or passed its idle or absolute
deadline, whichever came first, never from when it was created, so a long session is kept as long after it ends as a
short one. With 0, a device is pruned from the second its session ends. The value must be an integer, or a digit string
as `env()` returns one; anything else fails with an `InvalidArgumentException` when pruning runs. Each chunk is one
conditional `DELETE`, and nothing is read.

The package's models live outside your application's `app/Models`, so name them when you schedule the command:

```php
use Illuminate\Support\Facades\Schedule;
use SineMacula\Laravel\Authentication\Models\ApiKey;
use SineMacula\Laravel\Authentication\Models\Device;
use SineMacula\Laravel\Authentication\Models\IdentifierChange;
use SineMacula\Laravel\Authentication\Models\OneTimeCode;
use SineMacula\Laravel\Authentication\Models\PasskeyChallenge;
use SineMacula\Laravel\Authentication\Models\PendingSignIn;
use SineMacula\Laravel\Authentication\Models\RateLimit;

Schedule::command('model:prune', [
    '--model' => [
        Device::class,
        PendingSignIn::class,
        RateLimit::class,
        OneTimeCode::class,
        PasskeyChallenge::class,
        ApiKey::class,
        IdentifierChange::class,
    ],
])->hourly();
```

A custom device model opts in with the `PrunesDevices` trait alone (it brings Laravel's `MassPrunable` with it, and
using `MassPrunable` beside it is a PHP trait collision), and pruning reads its columns from the `EloquentDevice` name
accessors; schedule it under its own class name. Run `php artisan model:prune --model="App\Models\Device" --pretend` to
see how many devices would go. Pruning changes nothing about authentication: a pruned device's tokens fail as an unknown
device, exactly as they already failed once it was revoked or ended. Queued listeners of an event about a device that
has since been pruned cannot re-fetch it (see [Events](events.md#events)).

Before a token's `did` is looked up, it is checked against the device model's primary key: a UUID for `HasUuids`, a
ULID for `HasUlids`, an integer for an integer key, and a non-empty string otherwise. A `did` that cannot be a key is
treated as an unknown device without a query. A model whose key has some other format implements `ValidatesDeviceKey`
to describe it. Database errors are never read as an unknown device: they propagate as server errors.

## Checking the configuration

`php artisan authentication:check` resolves every `jwt` and `api_key` guard's settings the way the guard would and exits
`1` when any is wrong, `0` otherwise, for a deploy pipeline or a readiness probe. It checks each `jwt` guard's token
service (keys, active kid, algorithm, key lengths, lifetimes, those per principal type included, leeway, issuer and
audience), that its provider resolves to an `IdentityProvider`, its `principal_resolver` override, its audience settings
when the package's `AudiencePolicy` is bound, the rate limits of every flow, the password identifier, the refresh token
transport and, when its audience allows `passkey` or it sets a `passkeys` block, its passkey relying party; each
`api_key` guard's provider, `principal_resolver` override, audience settings (which must allow `api_key`) and rate
limits; and, for the whole package, the configured device model and pruning retention
(`authentication.device.prune_after_days`, otherwise checked only when `model:prune` runs), the pending sign-in lifetime
(`authentication.sign_in.pending_ttl_seconds`, otherwise checked only when a sign-in waits for a further factor or a
choice of principal), the password policy settings (`authentication.passwords`), the one-time code settings and key
(`authentication.codes`) and a bound `OneTimeCodeSender` when any guard allows a code sign-in method (`phone_code`,
`email_code`, or a `CodeSignIn` you registered), the delivery queue (`authentication.delivery.queue`), the passkey
challenge lifetime (`authentication.passkeys.challenge_ttl_seconds`), the API key settings (`authentication.api_keys`)
and the identifier change settings (`authentication.identifier_changes`). Every check runs, so one run lists every
problem, each as `[<guard>] <message>` (`[device]` for the device model and retention, `[sign_in]` for the pending
lifetime, `[passwords]` for the password policy, `[codes]` for the code settings and sender, `[delivery]` for the
delivery queue, `[passkeys]` for the challenge lifetime, `[api_keys]` for the API key settings, `[identifier_changes]`
for the identifier change settings), and a subject without one as `[<guard>] OK`. Delivery on a `sync` queue connection,
or on a `failover` one that can fall back to `sync`, while any `jwt` guard is configured (any of them may send codes,
reset links and codes, or identifier change codes and notices), is a `[delivery]` warning that leaves the exit code
alone, as is a `jwt` guard whose password resets or identifier changes would refuse to run: its provider's model on
another connection than the device model, or, for resets, a password identifier other than `email` while Laravel's
notification is the reset link sender (see [Password reset](passwords.md#password-reset)). Only the named guards are
checked with `--guard=api --guard=admin`; a named guard that is not configured, or neither a `jwt` nor an `api_key`
guard, is a problem. The command reads configuration only: it opens no database connection and never prints a key. The
package does not run these checks at boot; a misconfiguration otherwise surfaces when a guard first uses the setting.
