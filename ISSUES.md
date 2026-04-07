# `sinemacula/laravel-authentication` — Senior Engineering Review

Reviewer perspective: senior engineer / architect, evaluating the package as a
candidate for **enterprise** auth (SOC2 / GDPR / multi-tenant SaaS) per the
package's stated goals.

The package is well-organised, type-strict, follows Laravel idioms, and the
contract surface is clean. However the **JWT refresh-token flow has critical
security gaps**, several PRD acceptance criteria are not actually enforced in
code, and there are a number of architectural / robustness concerns that should
be addressed before this is deployed against production traffic.

Severity legend:

- **Critical** — security vulnerability or correctness failure that should block
  release. - **High** — significant defect, spec gap, or production-risk;
  address before v1.0.0. - **Medium** — bad practice, fragility, or design smell
  that will hurt at scale or in incident-response. - **Low** — polish,
  ergonomics, documentation.

---

## Critical

### C1. Refresh-token "key" is compared with `!==`, not a hash check, and stored as plaintext-equivalent

`src/Guards/JwtGuard.php:142`

```php
if ($device === null || $device->getRefreshKey() !== $refreshKeyPayload) {
    return null;
}
```

 The `Device` contract docblock (`src/Contracts/Device.php:49`) and the
`JwtTokenService::issueRefreshToken` PHPDoc
(`src/Jwt/JwtTokenService.php:79-84`) both claim the column stores a **hashed**
refresh key — but the comparison is direct string equality. This means one of
two things, both bad:

1. The column is actually plaintext (the docs lie). DB exfiltration → every
   refresh token in the system is recoverable. 2. The column really is hashed
   (e.g. bcrypt). The `!==` will then *never* match and refresh is broken
   end-to-end. There is no test that exercises a real bcrypt round-trip —
   verify.

Even if it ever worked, `!==` is a **non-constant-time string comparison** and
is timing-attack vulnerable. It must be `hash_equals(...)` (or `Hash::check()`
if values are bcrypt-hashed). Pick one model — hashed or not — and make the
comparison match.

### C2. Refresh tokens have no expiry enforcement of any kind

`src/Jwt/JwtTokenService.php:89-100`, `src/Guards/JwtGuard.php:125-170`

`issueRefreshToken()` deliberately omits the `exp` claim. The PRD and the
docblock both say this is OK because:

> "their lifetime is bounded by the `refresh_ttl_minutes` check performed by
> the guard against the device's `last_logged_in_at` timestamp."

**No such check exists in the guard.** `JwtGuard::refresh()` parses with
`parseAllowingExpired()`, verifies the refresh-key payload, and immediately
issues a new access token. The `refresh_ttl_minutes` config key is read nowhere
outside its docblock — `grep` confirms it has zero call sites.

Net effect: **a refresh token that is once captured is valid forever**,
until/unless the consumer manually rotates the row. This is the single
highest-impact defect in the package and is a hard "do not deploy" item for any
system that has compliance obligations.

### C3. Refresh tokens are never rotated, and there is no replay-detection

`src/Guards/JwtGuard.php:125-170`

After a successful refresh:

- the device row is **not** updated with a new `refresh_key`, - a new refresh
  token is **not** issued, - there is no concept of refresh-token "generations"
  / "families" / "reuse detection".

Best-practice for stateless refresh flows is rotation on every use (RFC 6749
§10.4 / OAuth 2.0 Security BCP §4.13): on each refresh, the server burns the old
key, issues a new one, and *if the same refresh token is presented twice, the
entire session chain is revoked* (because the second presenter is presumed to be
an attacker replaying a stolen token). The current implementation supports
neither rotation nor revocation. Combined with C2, **a stolen refresh token is
permanent and silent**.

### C4. The plaintext refresh key is embedded inside the JWT body

`src/Jwt/JwtTokenService.php:89-100`

```php
$payload = [
    'did' => $device->getDeviceIdentifier(),
    'rk'  => $refreshKeyPlaintext,
    'iat' => $now,
];
```

 JWT bodies are base64, **not encrypted**. Putting the plaintext refresh
credential into the body means:

- Anywhere the JWT lands (proxies, access logs, browser extensions, error
  reporters, devtools, sentry breadcrumbs) the credential is in clear. - The
  hashing (whether broken or not, see C1) gives you nothing because the
  plaintext is the bearer credential and travels with the token.

The conventional design is: refresh tokens are opaque random strings (not JWTs);
the server hashes them on receipt and looks up by hash. A JWT-shaped refresh
token is justifiable, but only if the body carries an *opaque identifier* (e.g.
`jti`) and the lookup happens by that identifier.

### C5. JWT secret defaults to empty string and is silently accepted at boot

`src/AuthServiceProvider.php:66-75`, `config/laravel-authentication.php:55`

```php
return new JwtTokenService(
    $config->string('laravel-authentication.jwt.secret', ''),
    ...
);
```

 If the consumer forgets to set `AUTHENTICATION_JWT_SECRET`, the package boots
cleanly and `JWT::encode($payload, '', 'HS256')` silently encodes/decodes with
an empty HMAC key — i.e. the token is "signed" with a zero-knowledge key, anyone
can forge it, and there is no startup error. An enterprise package must **fail
closed** on missing required cryptographic material: either (a) drop the default
and let the typed config getter throw, (b) validate at the deferred singleton
resolution, or (c) validate inside `boot()` before `extend('jwt', ...)` is
registered.

---

## High

### H1. `pid`/`did` claim fall-through silently downgrades the request to a *different* principal

`src/Guards/JwtGuard.php:96-109`,
`src/Resolvers/DefaultPrincipalResolver.php:40-60`

In `JwtGuard::user()` the resolver is called as `$this->resolver->resolve($user,
$claims['pid'] ?? null)`. The default resolver
(`DefaultPrincipalResolver::resolve`) does:

1. If hint present and `HasPrincipals`: try
   `$identity->principals()->find($hint)`. 2. **If that returns null, fall
   through to `$identity instanceof Principal`, then to
   `resolveDefaultPrincipal()`.**

So if the token claims `pid = 99` but principal 99 has been deleted,
deactivated, or never belonged to that identity, the user is silently bound to
the *default* principal instead. This is a **privilege-confusion
vulnerability**: the access token explicitly claimed one acting context, the
server bound a different one, and the audit trail will record the wrong
principal. Fail-closed semantics are required: a present-but-unresolvable hint
must reject the token.

The same issue applies to `did` (`JwtGuard::resolveDeviceFromHint`,
`src/Guards/JwtGuard.php:181-190`): a token that claims `did = X` for a device
that no longer exists is accepted with `$device = null`, losing the audit
binding.

### H2. JWT bearer-resolution path does not fire most of the "six standard auth events" promised by the PRD

`src/Guards/JwtGuard.php:66-112`, `src/Guards/BasicGuard.php:29-63`

PRD:

> A successful authentication emits `Attempting`, `Validated`, `Login`, and `Authenticated` in the order Laravel emits them.

But the *production* code path for both stateless guards is `user()` (called by
`Auth::check()` / `Auth::user()` / the `auth` middleware). Tracing this path:

- `JwtGuard::user()` fires only `Authenticated` (via `setIdentity()`) plus
  `PrincipalAssigned` / `DeviceAuthenticated`. **No `Attempting`, no
  `Validated`, no `Login`.** - `BasicGuard::user()` fires `Validated` (inside
  the timebox), `Authenticated`, and `PrincipalAssigned`. **No `Attempting`, no
  `Login`.**

The full six-event sequence only fires through the `attempt()` / `login()` path,
which is **not** how stateless requests authenticate. As written, this is a
direct PRD/AC failure for "Standard Laravel auth events" against the JWT guard,
which is the package's primary use case.

### H3. `JwtGuard::user()` and `BasicGuard::user()` do not check identity-level activation

`src/Guards/JwtGuard.php:90-105`, `src/Guards/BasicGuard.php:47-57`

Both check `Principal::isActive()`, but the `Identity` contract has no
equivalent and the guards have no hook to consult it. A token issued to a user
who is subsequently *banned/disabled/deleted* (at the identity level rather than
the principal level) will continue to authenticate until the access token
expires. For an enterprise package this is a real audit gap. At minimum: add an
optional `isActive()` to a marker capability contract, document the shape, and
call it in both `user()` paths.

### H4. `parseAllowingExpired()` decodes the payload without re-verifying the signature

`src/Jwt/JwtTokenService.php:139-195`

After `firebase/php-jwt` throws `ExpiredException`, the code falls through to
`decodeIgnoringExpiry()`, which manually `urlsafeB64Decode`s the payload and
`json_decode`s it — **with no signature verification**.

In current `firebase/php-jwt` versions the signature is verified before the
`exp` check is reached, so by the time the exception is thrown the signature was
already validated. So today this is *not* exploitable. But it is
**defence-in-depth-fragile**: any future library upgrade that re-orders
verification (or any future contributor who copies this pattern to a new code
path) silently turns this into a "decode unverified attacker-controlled JSON"
bug. Re-decode with full verification using a JWT validator that exposes "ignore
exp", or store and re-use the verified `$decoded` from the original try block.

### H5. `AuthServiceProvider::register()` discards the existing AuthManager's `$customCreators`

`src/AuthServiceProvider.php:59-62`

```php
$this->app->extend(
    'auth',
    static fn (IlluminateAuthManager $existing, Application $app): AuthManager => new AuthManager($app),
);
```

 The closure ignores `$existing` and instantiates a **fresh** AuthManager.
`Illuminate\Auth\AuthManager::$customCreators`
(`vendor/laravel/framework/.../AuthManager.php:31`) is `protected` and not
copied across. If any third-party package or `AppServiceProvider` ran
`Auth::extend(...)` *before* this provider (provider order is largely
alphabetical by package name, which is fragile), those guard drivers are
silently lost and the manager will throw "Auth driver X is not defined" at first
resolve.

The robust shape is to *subclass-by-decoration* — promote the existing manager
rather than replace it — or to invoke the extend in `boot()` after copying the
`customCreators` (which requires reflection because they are `protected`).
Either is preferable to "drop the array on the floor".

### H6. `UpdateDeviceTimestamp` writes to the device row on **every authenticated request**

`src/Listeners/UpdateDeviceTimestamp.php:30-43`,
`src/Guards/AbstractGuard.php:364-371`, `src/Guards/JwtGuard.php:107-109`

Because `setDevice()` dispatches `DeviceAuthenticated` from `JwtGuard::user()`,
**every** authenticated request causes a synchronous `Device::save()` against
the bound row. At any reasonable API throughput this is a hot-spot write on a
single row per device, with no debouncing, no `queue` interface, no `INSERT … ON
DUPLICATE KEY UPDATE`-style atomicity, and no rate-limit (e.g. only update if
`last_logged_in_at < now() - 60s`).

There is also a semantic mismatch: the column is `last_logged_in_at`, but it now
functionally tracks "last *seen* / last token use". Either rename the column
(`last_active_at`) or guard the write to actual login transitions.

Worse, the listener uses `forceFill([...])->save()` (line 40-42) instead of an
`update([...])` — saving the entire dirty model, with whatever in-memory
mutations `Device::morphTo()` may have triggered, and bypassing `$fillable`.

### H7. `JwtGuard::login()` and `JwtGuard::refresh()` do not clear pre-existing state

`src/Guards/AbstractGuard.php:234-244`

```php
public function login(Identity $identity, Principal $principal, ?Device $device = null): void
{
    $this->setIdentity($identity);
    $this->setPrincipal($principal);
    if ($device !== null) {
        $this->setDevice($device);
    }
    ...
}
```

 If a guard is already bound to identity A with device A and `login(B,
principalB, null)` is called (no device), **device A remains bound**. Result:
identity B is now associated with identity A's device in audit events. The fix
is one line: explicitly null `$this->device` (and ideally `$this->principal`,
`$this->identity`) at the top of `login()` and at the top of the refresh
hydration block in `JwtGuard::refresh()`. Same fix needed in the refresh path.

### H8. JWTs carry no `iss`, `aud`, or `jti` claims

`src/Jwt/JwtTokenService.php:59-72`

For an enterprise auth package the absence of these is meaningful:

- **`iss` / `aud`** — without them, a token issued by service A in your fleet is
  replayable against service B as long as both share a secret (typical
  microservice deployments). This is an extremely common privilege-escalation
  vector. - **`jti`** — even though the package is "stateless", a `jti` is the
  *only* viable surface for a consumer to layer an external denylist for
  revocation (incident response: "a key was compromised, please invalidate all
  live tokens for principal X"). Without `jti`, consumers have to roll their own
  id and there is no audit ID to correlate against the access logs / activity
  log package.

### H9. `Device.refresh_key` column is unbounded, not unique, and not consistently sized

`database/migrations/2026_04_06_000000_create_devices_table.php:33-39`

```php
$blueprint->string($refreshKeyColumn);
...
$blueprint->index($refreshKeyColumn);
```

- No `->unique()`. Two devices with the same refresh key would silently
   coexist. - No size constraint. If the value is bcrypt (60 chars) sizing the
   column to 255 is wasteful; if it's `random_bytes(32)|hex` (64 chars)
   likewise. - An `index()` rather than `unique()` on a credential lookup column
   is a code smell. - If the documented "hashed" model means bcrypt, the column
   **cannot be looked up by index** because every bcrypt hash has its own salt —
   which means the entire refresh design is incoherent (you would have to load
   all rows for a given device and `Hash::check` each, or use a deterministic
   hash like SHA-256 instead of bcrypt). Pick one and make the schema, the
   contract docs, the migration, and the comparison consistent.

---

## Medium

### M1. `BasicGuard` hard-codes `email` as the credential identifier

`src/Guards/BasicGuard.php:42-45`

```php
$credentials = [
    'email'    => $username,
    'password' => $password,
];
```

 There is no way for a consumer to use `username`, `phone`, `subdomain+email`,
or any multi-field credential. For a package whose explicit goal is to be
domain-agnostic, this is a one-line oversight (read the field name from package
config or guard config) that will force consumers off the shipped guard the
moment they have any non-trivial identity model.

### M2. `ModelProvider::retrieveByCredentials` is fragile against unexpected key/value shapes

`src/Providers/ModelProvider.php:95-127`

- The closure callback path (`if ($value instanceof \Closure) { $value($query);
  }`) silently no-ops on any other type, including `int|string` *with a numeric
  `$key`* (which would crash `where()` upstream). - `is_array($value)` is
  treated as a `where($key, $array)` which produces invalid SQL in most cases. -
  After `array_filter` strips password-ish keys, the `$credentials` could end up
  empty — that case returns `null` (good) but every other malformed input simply
  runs an unbounded `where`-less query and `first()`s the first row. A defensive
  guard against `numeric($key) || ! is_string($key)` would prevent unintended
  "first row in table" authentication on malformed credential arrays.

### M3. `ModelProvider::createModel()` silently accepts an empty model class

`src/AuthServiceProvider.php:107-114`, `src/Providers/ModelProvider.php:189-194`

The provider closure casts `$config['model']` to string with a fallback of `''`,
and `createModel()` does `new $class;`. If the consumer forgets to set the model
on their auth provider, you don't get a clear configuration error — you get
`Class "" not found` from PHP's autoloader at the first `retrieveByCredentials`
call. Validate at registration / first-resolve.

### M4. `JwtTokenService::issueAccessToken` puts a non-string into the `sub` claim

`src/Jwt/JwtTokenService.php:63`

```php
'sub' => $identity->getAuthIdentifier(),
```

 RFC 7519 §4.1.2 requires `sub` to be a `StringOrURI`. `getAuthIdentifier()` may
legitimately return `int` (Eloquent integer keys), and then `firebase/php-jwt`
round-trips it as a JSON number. Cast to string: `'sub' => (string)
$identity->getAuthIdentifier()`. Same applies to `pid` and `did`.

### M5. JWT validation has zero clock-skew leeway

`src/Jwt/JwtTokenService.php:111-128`, `139-162`

`firebase/php-jwt` defaults `JWT::$leeway = 0`. In any distributed deployment
(load balancer, multi-region issuer/verifier, NTP drift) you will see spurious
401s on tokens issued one second in the future or expired one second ago. Expose
this through config (`jwt.leeway_seconds`, default 30) and set it on the static
JWT class once per request.

### M6. `JwtTokenService` is hard-bound to a single secret — no key rotation, no `kid`

`src/Jwt/JwtTokenService.php`

Enterprise key-management requires the ability to roll a signing key without
invalidating every live access token. The standard pattern is:

- Sign with the *current* key, embed the `kid` header. - Verify against a `kid →
  Key` map (`firebase/php-jwt` supports this natively via the second arg to
  `JWT::decode`). - During rotation, both old and new `kid`s are valid.

The current single-string secret design makes any production rotation strategy a
forklift change.

### M7. `JwtTokenService::parse` and `decodeIgnoringExpiry` both silently swallow all errors

`src/Jwt/JwtTokenService.php:111-128, 172-195`

Returning `null` for "no token", "expired", "tampered", and "malformed" makes
incident-response (and consumer debugging) significantly harder. There is also
no logging hook. Either return a rich result (`Result|Failure`), or expose a
`LoggerInterface` and `debug()` the failure reason in dev environments.

### M8. `JwtGuard::refresh()` fires no events on failure paths

`src/Guards/JwtGuard.php:125-170`

Every early-return is silent. Failed refreshes are exactly the events SOC2 /
SIEM pipelines need (potential token theft / replay). Fire `Failed` (or a new
`RefreshFailed`) on each return-null branch with enough detail to attribute
(request ip, did claim if present, failure reason).

### M9. `Refreshed` event payload omits the principal and device

`src/Events/Refreshed.php:26-34`

```php
public string $guard,
public Identity $identity,
```

 A refresh that updates the principal's binding context cannot be audit-logged
usefully without the principal and the device. Add them.

### M10. The `extend('auth')` callback runs in `register()` and does container-resolves transitively

`src/AuthServiceProvider.php:59-62`

`new AuthManager($app)` invokes `Illuminate\Auth\AuthManager::__construct` which
sets `$this->userResolver = fn ($g) => $this->guard($g)->user();`. This does not
eagerly resolve, so it is fine *today*, but extending `'auth'` from `register()`
is a category of pattern that has historically caused subtle ordering issues.
Prefer `$this->app->resolving('auth', ...)` or
`$this->app->afterResolving('auth', ...)`, which do not run until the container
actually wants the binding.

### M11. `AbstractGuard::id()` has a strange scalar fallback path

`src/Guards/AbstractGuard.php:124-137`

```php
if (is_scalar($identifier) || $identifier instanceof \Stringable) {
    return (string) $identifier;
}
```

 `is_scalar()` is true for `bool` and `float`. If somehow `getAuthIdentifier()`
returns `true` you'll silently return the string `"1"` as the auth id. Either:

- Trust the contract (`int|string|null` only, return the value, let the type
  fail if violated), or - Throw `LogicException` on unexpected types so the
  consumer learns immediately.

### M12. `AbstractGuard::hasValidCredentials` timebox window may be smaller than worst-case bcrypt

`src/Guards/AbstractGuard.php:430-441`

`$this->timebox->call(..., 200000)` = 200 ms. Bcrypt cost 12 on a slow shared
host can exceed 250 ms. When the real path takes longer than the timebox target,
the constant-time guarantee breaks down — a slow real-bcrypt path will be
visibly slower than the no-user path, re-introducing the enumeration oracle this
code is trying to defeat. Either:

- Set the window to a published high-water mark (e.g. 400 ms) and document it,
  or - Read it from config so consumers can tune it to their hash cost.

Also: the default Laravel `Hasher` typically uses bcrypt cost 12 which is fine,
but the timebox needs to be set with that in mind.

### M13. `BasicGuard::user()` does not fire `Attempting`/`Login`; `JwtGuard::user()` fires neither plus skips `Validated`

(See H2.) Beyond the spec gap, this also means `Failed` is **never fired on a
bad bearer token** — only the silent return-null happens. SIEM pipelines see
authentication failures as "no Authenticated event" rather than as an explicit
failure event. Add `fireAttemptingEvent()` and `fireFailedEvent()` to the
`user()` paths.

### M14. `AbstractGuard::login()` does not fire `Validated`

`src/Guards/AbstractGuard.php:199-223`

The `attempt()` path fires `Validated` from inside `hasValidCredentials()`.
Direct `login()` (called from refresh, consumer code, test helpers) does not.
Inconsistent.

### M15. The contextual `attempt()` signature breaks Laravel's `StatefulGuard` shape

`src/Contracts/ContextualGuard.php:29`

```php
public function attempt(array $credentials, ?Principal $principal = null, ?Device $device = null): bool;
```

 Laravel's `StatefulGuard::attempt()` is `attempt(array $credentials, $remember
= false): bool`. Because `ContextualGuard` only extends `Guard`, and not
`StatefulGuard`, this is technically OK — but it means you cannot type-hint a
stateful Laravel API helper against this guard. Document, or split signatures so
the second positional arg is `bool $remember` (which is meaningless here but
maintains shape) and the contextual extras live as named keyword arguments / a
separate method.

### M16. `protected $guarded = []` on the shipped Device model

`src/Models/Device.php:39`

Disables Eloquent's mass-assignment protection wholesale. Even though the model
is internal, this is a smell — a future contributor that exposes Device through
an API endpoint will get the worst possible default. Switch to `protected
$fillable = [...]` with the actual columns.

### M17. `Device::__construct` reads config on every model instantiation

`src/Models/Device.php:54-59`

```php
public function __construct(array $attributes = [])
{
    $this->setTable(Config::string('laravel-authentication.device.table', 'devices'));
    parent::__construct($attributes);
}
```

 `Config::string()` is called on **every Eloquent hydration** of the model —
including the per-row `newFromBuilder` path of large queries. Cache the table
name in a `static` property at first call, or read it once in a service-provider
hook.

### M18. Migration manually wires `authenticatable_*` instead of using `morphs()`

`database/migrations/2026_04_06_000000_create_devices_table.php:30-38`

```php
$blueprint->string('authenticatable_type');
$blueprint->string('authenticatable_id');
...
$blueprint->index(['authenticatable_type', 'authenticatable_id']);
```

 Use `$blueprint->morphs('authenticatable')` (or
`nullableMorphs`/`ulidMorphs`/`uuidMorphs` to match the consumer's identity key
shape). This:

- Creates the index in one step. - Picks the correct column types based on the
  identity model key type. - Avoids `string('authenticatable_id')` for an
  integer-keyed identity (which works but is wasteful and prevents efficient
  joins).

### M19. `MigrationCollisionGuard::ensureNotExists` does not check the active connection name

`src/Database/MigrationCollisionGuard.php:41-54`

Multi-database consumers (e.g. tenant-per-DB) can legitimately have a `devices`
table on connection A but not on the package's connection B. The error message
tells the user to rename, but does not tell them *which connection* it is
checking — a small but very useful diagnostic addition.

### M20. `setRequest` is called by container `refresh` but the listener does not re-bind anything else

`src/AuthServiceProvider.php:142, 161`, `src/Guards/AbstractGuard.php:390-395`

`$app->refresh('request', $guard, 'setRequest')` is correct, but if a consumer
rebinds `events` or the principal-resolver in tests, the guard keeps stale
references. Either expose a `withResolver()` / `withDispatcher()` setter and
`refresh()` against those, or document the constraint.

### M21. `Auth` facade subclass docblock is stale

`src/Facades/Auth.php:17-22`

The docblock advertises `principal()`, `device()`, `organization()`, `scope()`,
`isInternal()`, `isExternal()` — but **omits `identity()`** which the manager
exposes. And the `AuthServiceProvider` PHPDoc says "the six contextual
`Auth::macro` accessors" (which is also wrong — the manager is a subclass, no
macros), and lists seven accessors. Update both.

### M22. `ActsAsPrincipal::getOrganization()` triggers an N+1 trap

`src/Traits/ActsAsPrincipal.php:72-77`

```php
$organization = $this->getAttribute($this->getOrganizationRelationName());
```

 Reading the relation through `getAttribute()` lazy-loads it on demand. In a
request that authenticates a principal and immediately calls
`Auth::organization()` you eat one extra query per request. Document the
recommendation to eager-load `organization` on the principal in the resolver, or
at minimum mention it in the trait docblock.

### M23. `DefaultPrincipalResolver` throws `LogicException` from a credential-validation path

`src/Resolvers/DefaultPrincipalResolver.php:59`

A misconfigured identity (implements neither `Principal` nor `HasPrincipals`)
throws a `\LogicException` from inside the guard's auth path. This propagates as
an HTTP 500 with a message containing the model class name. Better: return
`null` and let the guard report a failed auth, or throw a typed package
exception that the consumer can map to a 401.

---

## Low

### L1. Magic strings everywhere for JWT claims

`src/Jwt/JwtTokenService.php`, `src/Guards/JwtGuard.php`

`'sub'`, `'pid'`, `'did'`, `'rk'`, `'iat'`, `'exp'` are stringly-typed across
two files. Class constants on `JwtTokenService` (or a `Claims` enum) would
prevent typos and make refactor-rename safe.

### L2. PHPDoc count discrepancies

`src/AuthManager.php:18-26`, `src/AuthServiceProvider.php:30-34`,
`src/Facades/Auth.php`

The class-level docblocks repeatedly say "the six contextual accessors" while
listing seven (`identity, principal, device, organization, scope, isInternal,
isExternal`). Decide whether `identity()` is a contextual accessor or not — it's
currently both exposed on the manager and missing from the facade docblock — and
pick a single canonical wording.

### L3. `Authenticatable` trait blanks `getRememberTokenName()` to `''`

`src/Traits/Authenticatable.php:27-30`

Returning the empty string is interpreted by Laravel as "no remember-token
column" *in some code paths*, but in others (Laravel's
`EloquentUserProvider::retrieveByToken`) it builds queries against the literal
column `""`. For a stateless package this never gets called, but the cleaner
approach is to override `setRememberToken()`/`getRememberToken()` to no-ops, or
to mark the trait as "do not use with `EloquentUserProvider::retrieveByToken`".

### L4. `Listeners/UpdateDeviceTimestamp` is registered with array-callable syntax

`src/AuthServiceProvider.php:175`

```php
Event::listen(DeviceAuthenticated::class, [UpdateDeviceTimestamp::class, 'handle']);
```

 Either rename `handle()` → `__invoke()` (and pass the class string) or rely on
Laravel's auto-discovery (`Event::listen(DeviceAuthenticated::class,
UpdateDeviceTimestamp::class)`). Cosmetic but more idiomatic.

### L5. `$guarded = []` and missing `$fillable` on `Device` (also covered in M16)

### L6. The `# @phpstan-ignore staticMethod.dynamicCall` comments in `ModelProvider` are a smell

`src/Providers/ModelProvider.php:55, 107, 174`

Three suppression markers around the same call shape — `(new
$class)->newQuery()` — suggests the abstraction (`createModel()` returning the
union type) isn't strong enough for Larastan. Often resolved by typing the model
class as `class-string<Model&Authenticatable>` *and* asserting `Model::class`
once.

### L7. `Refreshed` does not implement `ShouldDispatchAfterCommit` or queue interfaces

`src/Events/Refreshed.php`

Audit listeners on this event will fire mid-request even if a downstream DB
transaction rolls back. Trivial but worth thinking about for the activity-log
integration.

### L8. `Auth` facade subclass adds nothing the framework facade does not already provide

`src/Facades/Auth.php`

Other than the (incomplete, see L2) docblock annotations, the subclass is empty.
Consumers will likely use the framework facade directly anyway. Either delete it
(and put the `@method` tags on `AuthManager` itself) or own it as a real
first-class extension point.

### L9. `Refresh` claim key `'rk'` is non-namespaced

`src/Jwt/JwtTokenService.php:95`

JWT custom claims should be namespaced (RFC 7519 §4.3) — `urn:sm:auth:rk` or
similar. Two-character claim names risk collision with another package's claim
if a single token is co-consumed.

### L10. `BasicGuard` reads `getUser()`/`getPassword()` from the request

`src/Guards/BasicGuard.php:35-36`

These come from PHP's `$_SERVER['PHP_AUTH_USER']`/`PHP_AUTH_PW`. Behind PHP-FPM

- nginx the `Authorization` header is **not** automatically populated into those
superglobals unless the webserver is explicitly configured to forward it
(`fastcgi_pass_header Authorization;`). Worth a callout in the README and
possibly a fallback to parse `Authorization: Basic …` directly from the header.

### L11. `final` consistency

`AuthManager` is intentionally non-`final` (subclassable, per docblock);
`ModelProvider` is also non-`final` for no stated reason. Either document the
extension intent or mark `final`.

### L12. PHPStan ignore directives in the config file

`config/laravel-authentication.php:19-58`

Six `@phpstan-ignore larastan.noEnvCallsOutsideOfConfig` annotations on what is
itself a config file is a hint that the rule is being misapplied — investigate
whether the larastan rule has a `paths` exclude for `config/` instead of
suppressing line-by-line.

---

## Architectural / scope observations (not defects)

### A1. The package promises "audit-quality" auth but ships no `Failed` events on the production read paths

(See H2 / M13.) For SOC2 / GDPR forensics you need to be able to count failed
authentications per (ip, identity, principal) over a window. The package's
stated value-prop and its actual event surface are misaligned on the JWT path,
which is the use case the package primarily targets.

### A2. The Identity → Principal → Device model is well-conceived; the resolver contract is the right shape

The split is clean, the contracts are appropriately minimal, the 2D and 3D
adoption modes coexist reasonably, and the contracts genuinely allow consumers
to plug in their own models without subclassing. This is the strongest part of
the package.

### A3. Test alignment with PRD acceptance criteria should be re-audited

The PRD requires ≥90% line coverage on guards / providers / manager. Several of
the issues above (no rotation, no expiry, principal-hint fall-through,
identity-active gap, every-request device write, missing standard events on
`user()`) could only happen if there are no tests for those scenarios. Recommend
a tracing exercise: read each "Acceptance Criteria" bullet in the PRD, find the
corresponding test, and *prove* the behaviour.

### A4. Consider extracting refresh-token semantics to a small service

The refresh-flow concerns (rotation, expiry, replay detection, atomic update of
`refresh_key`, `last_used_at`) are non-trivial enough that they belong in a
`RefreshTokenService` or similar, not inline in `JwtGuard`. This would also make
it possible to write a focused unit test for the security-critical path
independently of the guard machinery.

### A5. The "stateless package" framing should be revisited for refresh

The PRD repeatedly emphasises "stateless". But the refresh flow inherently
requires state (the device row, the refresh key, the last-used timestamp,
ideally a generation counter). The package is *stateless for access* but
*stateful for refresh*. Calling that out plainly in the README would prevent a
lot of consumer confusion and would naturally lead to the rotation/replay fixes
above.

---

## Suggested remediation order

1. **Fix the refresh flow end-to-end** (C1, C2, C3, C4, H9, M9). This is one
   coherent piece of work; do not ship without it. 2. **Fix the silent
   fall-through on `pid` / `did`** (H1). This is a one-line correctness fix but
   high-impact. 3. **Validate JWT secret at boot, add
   `iss`/`aud`/`jti`/`leeway`/`kid` support** (C5, H8, M5, M6). One module, one
   PR. 4. **Wire the missing standard events into the `user()` paths** (H2, M13,
   M14). PRD compliance work. 5. **Add identity-level activation hook** (H3). 6.
   **Debounce the device-timestamp listener** (H6) — meaningful at production
   load. 7. **Stop overwriting state in `login()` / `refresh()` without clearing
   first** (H7). 8. **Fix `extend('auth')` to preserve `$customCreators`** (H5)
   before any consumer hits the broken-driver edge case. 9. The Medium / Low
   items can land as a follow-up cleanup pass.
