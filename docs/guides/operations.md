# Operations

Running the package in production: where its reads go, what a long-running process keeps between requests and jobs,
which settings it reads once, rotating signing keys, pruning the rows sessions and credentials leave behind, and
checking the configuration before a deploy.

## Read replicas

Every read that decides authentication - the identity, the principal and the tenant it acts within, the session with its
guard, sign-in method, refresh digests, rotation time, session deadlines and revocation state, and the session's proofs

- goes to the write connection, even when the database connection has `read` and `write` hosts. A replica can lag behind
a revocation, a deactivation, a refresh rotation, or an ended session, and a lookup it served could admit a credential
the primary has already rejected.

The package pins the lookups it makes, including the relations the identity, principal and session models eager-load
(`$with`), on whichever connection those relations live (a tenant in a separate landlord database, say). Code you plug
in carries the same obligation:

- a custom `IdentityProvider`, a `ModelProvider` subclass that builds its own query, or a custom `PrincipalResolver`
  must read from the write connection, including the relations its results eager-load;
- `resolveDefaultPrincipal()`, `resolveHintedPrincipal()`, `sessions()` and, when `ModelProvider` checks a password,
  `getAuthPassword()` already run inside `WriteConnection::during()` for the identity, `getTenant()` for the principal,
  `isActive()` for the model it belongs to, a session's guard, sign-in method, refresh state, session deadlines and
  revocation for the session, an application policy's `admitIdentifier()` for the identity, `ApplicationAccess` and the
  `TenantResolver` for the principal, and `TenantAccess` for the principal and the tenant (so a contract of your own
  that admits on a grant or a membership row reads the primary's):
  every model read made there, on any connection, goes to that connection's writer, and so does a query-builder read on
  the model's own connection. A query-builder or `DB` read on another connection, or made by a principal or identity
  that is not an Eloquent model, or a read a policy makes from `allowsMethod()`, must pin itself.

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
session, tenant and scopes one request bound, a refusal and a logout are gone for the next. `Auth::sessions()`,
`Auth::jwt()`, `Auth::codes()`, `Auth::apiKeys()`, `Auth::clientCredentials()` and the other services act on the
sandbox: its request (the client their events and sessions record), its configuration (a value one request changes
applies to that request alone) and the dispatcher bound in it. The sign-in methods are built with the sandbox too, a
method registered at boot included, and so are the revoking listeners' session services, though the event dispatcher
builds those listeners with the booted application. Keep Octane's default listeners (`FlushAuthenticationState` and
`FlushTemporaryContainerInstances` among them), and leave the package's services out of `octane.warm`: a service warmed
at boot keeps the booted configuration, so a request that changes its own would not reach it. The package is tested
through Octane's own worker, sandbox and listeners (without a server), across sequences of requests.

Outside Octane, each request rebinds Laravel's `request`, which resets every package guard already resolved: the
identity, principal and session it bound, and whether it has resolved the request. A queue worker forgets only scoped
instances between jobs, so the package resets its guards when each job a worker runs starts (on `JobProcessing`,
through `AuthManager::forgetGuardState()`): a guard a job signs in with `login()` or `setUser()` is signed out again
for the next job. Only jobs a worker runs are reset: a job on the `sync` connection (the `sync` driver, or
`dispatchSync()` whatever the default connection) runs inside the request that dispatched it and leaves its guards as
they are, so a session the request just started stays bound and a request that signed out stays signed out. A
dispatcher or principal resolver swapped in after a guard resolved (`Event::fake()`, a rebinding of
`PrincipalResolver`) reaches the guard and its session service (and, through it, a refresh, a switch and
the revocations), which read the guard's collaborators each time they run.

The package's singletons hold configuration only: the token service factory memoises each guard's signing configuration
(see [Configuration lifetimes](#configuration-lifetimes)), not any identity's data, and the mark the password-change
listener reads during an automatic rehash is scoped, so it starts empty for each request and each job a worker runs
(under Octane, every request after the first when the application resolved it at boot). `WriteConnection::during()`
swaps Eloquent's process-wide connection resolver while its callback runs and restores it, and each connection's read
mode, when the callback returns or throws, so the next request reads as configured. No package class keeps a request, an
identity or a token in a static property. The sign-in methods you register are kept as long as the application serving
them, so they must hold no state between calls (see [Writing a sign-in method](signing-in.md#writing-a-sign-in-method)),
and so must a factor or application policy you bind as a singleton.

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
lifetimes, refresh grace, leeway, issuer and audience) once, so a runtime change to a JWT setting does not reach a token
service already built, even for a guard built afterwards. Nor does it reach the lifetimes the application policy
applies, which come from the token service; the rest of the application settings, the rate limits and every other
setting are read anew. A queue worker resets its guards between jobs rather than rebuilding them, so it keeps both kinds
for as long as it runs. To change a kept setting, change the configuration and restart the worker, as above.

Like every setting, a change to an application's `application.methods` in the configuration files reaches a long-running
process only after the restart above; the list itself is read on every use, so a runtime `config([...])` applies at
once. Emptying the list (or removing a method) to stop an application's sign-ins and refreshes is therefore a deploy
plus a worker restart, after which every sign-in, refresh, switch, one-time code and password reset request
and machine credential it no longer lists is refused (see [Applications](configuration.md#applications)). Nothing is
revoked: access tokens already issued keep working until they expire, and sessions refresh again once the method is
listed again.

Under Octane, each request runs in a copy of the application with its own copy of the configuration. A singleton first
resolved while a request is served, the token service factory included, lives only as long as that request; one resolved
before the first request (warmed through Octane's `warm` list, or resolved while the application boots) lives as long as
the worker, and one built with the configuration repository, such as the attempt limiter or the application policy, then
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

Rows whose use has ended stay in their tables until Laravel's `model:prune` deletes them, in chunks: a session model in
chunks that each read the keys of its prunable sessions and delete their proofs, their provenance and the sessions, in
one transaction; every other model in chunks of one conditional `DELETE` that reads nothing:

| Model                     | Pruned once                                                                                                   |
|---------------------------|---------------------------------------------------------------------------------------------------------------|
| `Models\Session`          | it has been over (revoked, or past a deadline) for `session.prune_after_days`, with its proofs and provenance |
| `Models\RateLimit`        | its window has ended                                                                                          |
| `Models\OneTimeCode`      | it has expired                                                                                                |
| `Models\PasskeyChallenge` | it has expired                                                                                                |
| `Models\ApiKey`           | it was revoked or expired more than `api_keys.prune_after_days` ago                                           |
| `Models\IdentifierChange` | it has expired                                                                                                |

Passkeys are never pruned: one lasts until its owner removes it.

Revoked and ended sessions are kept for audit: a session is pruned once it has been over for `session.prune_after_days`
(default 30, from 0 to 3650), counted from when it was revoked or passed its idle or absolute deadline, whichever came
first (a pending session's idle deadline is its credential's expiry), never from when it was created, so a long session
is kept as long after it ends as a short one; a session with no absolute deadline is pruned once it went idle or was
revoked. With 0, a session is pruned from the second it ends. The value must be an integer, or a digit string as `env()`
returns one; anything else fails with an `InvalidArgumentException` when pruning runs. Each chunk, in one transaction on
the session's connection, reads the keys of up to a chunk of prunable sessions, deletes the proofs and the provenance
recorded for those keys (by the keys as strings, the form the proofs record them in, whatever the session model's key
type), then deletes the sessions; `ModelsPruned` reports the sessions pruned so far after each chunk. The proofs and
provenance have no pruning of their own: they go with their session, so a session deleted any other way (a truncation
included) leaves them behind, and an application that deletes sessions itself deletes, in the same transaction, the rows
of the `proofs.table` and `proofs.provenance_table` tables whose `session_id` is the session's key as a string (the form
they record it in, whatever the session model's key type, so an integer key is compared as its digits). Every sign-in
also deletes whatever is recorded under its new session's key before it records its own, so a key the database issues
again (an integer key whose counter a truncation reset) does not inherit an earlier session's proofs. That deletion
reads as of its transaction's snapshot: on MySQL at REPEATABLE READ, a sign-in inside a transaction of your own that
read the database before the earlier session's rows were committed does not see them, so delete a session's rows with it
rather than rely on the sign-in.

The package's models live outside your application's `app/Models`, so name them when you schedule the command:

```php
use Illuminate\Support\Facades\Schedule;
use SineMacula\Laravel\Authentication\Models\ApiKey;
use SineMacula\Laravel\Authentication\Models\IdentifierChange;
use SineMacula\Laravel\Authentication\Models\OneTimeCode;
use SineMacula\Laravel\Authentication\Models\PasskeyChallenge;
use SineMacula\Laravel\Authentication\Models\RateLimit;
use SineMacula\Laravel\Authentication\Models\Session;

Schedule::command('model:prune', [
    '--model' => [
        Session::class,
        RateLimit::class,
        OneTimeCode::class,
        PasskeyChallenge::class,
        ApiKey::class,
        IdentifierChange::class,
    ],
])->hourly();
```

A custom session model opts in with the `PrunesSessions` trait alone (it brings Laravel's `MassPrunable` with it, and
using `MassPrunable` beside it is a PHP trait collision), and pruning reads its columns from the `EloquentSession` name
accessors; schedule it under its own class name. A custom model that soft-deletes has its pruned sessions deleted
outright, as Laravel's mass pruning force-deletes, so their IP addresses and user agents are not kept. Run `php artisan
model:prune --model="App\Models\Session" --pretend` to see how many sessions would go. Pruning changes nothing about
authentication: a pruned session's tokens fail as an unknown session, exactly as they already failed once it was revoked
or ended. Queued listeners of an event about a session that has since been pruned cannot re-fetch it (see
[Events](events.md#events)).

Before a token's `sid` is looked up, it is checked against the session model's primary key: a UUID for `HasUuids`, a
ULID for `HasUlids`, an integer for an integer key, and a non-empty string otherwise. A `sid` that cannot be a key is
treated as an unknown session without a query. A model whose key has some other format implements `ValidatesSessionKey`
to describe it. Database errors are never read as an unknown session: they propagate as server errors.

## Checking the configuration

`php artisan authentication:check` resolves every `jwt` and `api_key` guard's settings the way the guard would and exits
`1` when any is wrong, `0` otherwise, for a deploy pipeline or a readiness probe. It checks each `jwt` guard's token
service (keys, active kid, algorithm, key lengths, lifetimes, leeway, issuer and audience), that its provider resolves
to an `IdentityProvider`, its `principal_resolver` override, its application (with the package's `ApplicationPolicy`,
its application settings; with a policy of your own, every registered sign-in method and `client_credentials` is asked
of it, and an exception it throws is a problem for the guard), the rate limits of every flow, the password identifier,
the refresh token transport, its own `freshness` block and, when its application allows `passkey` or it sets a
`passkeys` block, its passkey relying party; each `api_key` guard's provider, `principal_resolver` override, application
(which must allow `api_key` whatever the policy, since an `api_key` guard has no other use, and with the package's
policy, its settings) and rate limits; and, for the whole package, the storage and rate limit connections
(`authentication.storage.connection`, `authentication.rate_limits.connection`: a connection name configured in
`database.connections`, or none), the configured session model, which must live on the storage connection, and the
pruning retention while any `jwt` guard is configured (`authentication.session.prune_after_days`, otherwise checked only
when `model:prune` runs), the pending credential lifetime (`authentication.session.pending_ttl_seconds`, otherwise
checked only when a session becomes pending), the password policy settings (`authentication.passwords`), the one-time
code settings and key (`authentication.codes`) and a bound `OneTimeCodeSender` when any guard allows a code sign-in
method (`phone_code`, `email_code`, or a `CodeSignIn` you registered), the delivery queue
(`authentication.delivery.queue`), the passkey challenge lifetime (`authentication.passkeys.challenge_ttl_seconds`), the
API key settings (`authentication.api_keys`), the identifier change settings (`authentication.identifier_changes`), the
freshness requirements (`authentication.freshness`) and the revocation settings (`authentication.revocation`). Every
check runs, so one run lists every problem, each as
`[<guard>] <message>` (`[storage]` for the connections, `[session]` for the session model, retention and pending
lifetime, `[passwords]` for the password policy, `[codes]` for the code settings and sender, `[delivery]` for the
delivery queue, `[passkeys]` for the challenge lifetime, `[api_keys]` for the API key settings, `[identifier_changes]`
for the identifier change settings, `[freshness]` for the freshness requirements, `[revocation]` for the revocation
settings), and a subject without one as
`[<guard>] OK`. Delivery on a `sync` queue connection, or on a `failover` one that can fall back to `sync`, while any
`jwt` guard is configured (any of them may send codes, reset links and codes, or identifier change codes and notices),
is a `[delivery]` warning that leaves the exit code alone, as is a `jwt` guard whose package application settings allow
nothing (its `methods` lists nothing, or only `api_key`; see [Applications](configuration.md#applications); a policy of
your own, even one that wraps the package's, gets no such warning, since the names it allows are its own), and a `jwt`
guard whose password resets or identifier changes would refuse to run: its provider's model on another connection than
the storage connection, or, for resets, a password identifier other than `email` while Laravel's notification is the
reset link sender (see [Password reset](passwords.md#password-reset)). Only the named guards are checked with
`--guard=api --guard=admin`; a named guard that is not configured, or neither a `jwt` nor an `api_key` guard, is a
problem. The `[codes]` sender check still asks every `jwt` guard's application whether it allows a code sign-in method,
and an exception the policy throws for a guard left out of the run, whether the package's over settings it cannot read
or one of your own, is a `[codes]` problem naming that guard. The package's checks read configuration only: they open no
database connection and never print a key, though a policy of your own that reads the database when asked whether it
allows a method opens a connection. The package does not run these checks at boot; a misconfiguration otherwise surfaces
when a guard first uses the setting.
