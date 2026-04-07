# `sinemacula/laravel-authentication` — Test Checklist

> A pre-implementation checklist of every assertion we can think of for the
> refactored `laravel-authentication` package. The goal isn't just 100% line
> coverage (that's the easy bit) — it's to maximise mutation kill-rate by
> nailing every conditional, every boundary, every operator, every event
> ordering, and every observable side effect.
>
> Cross-references in this document use `path/to/file.php:line` form so each
> bullet can be traced to the exact behaviour it pins down.

---

## Conventions

- **[unit]** — fast, isolated, mocks the framework where appropriate.
- **[feature]** — exercises a real Laravel container via Orchestra Testbench.
- **[integration]** — exercises the full HTTP middleware/event/facade surface.
- Each `[ ]` line is one independent assertion. Where multiple assertions are
  bundled in a single test method that's fine — just make sure each is its own
  `assert*` call (or its own data-provider row) so a mutation that breaks one
  fails the suite cleanly.

---

## 1. `AuthManager` (`src/Auth/AuthManager.php`)

- [ ] **[unit]** Class extends `Illuminate\Auth\AuthManager`.
- [ ] **[unit]** Class implements `SineMacula\Laravel\Iam\Auth\Contracts\Factory`.
- [ ] **[unit]** `Factory` contract extends `Illuminate\Contracts\Auth\Factory` (so existing Laravel typehints still
  resolve).
- [ ] **[feature]** Resolving `auth` from the container returns an `AuthManager` instance, not the stock Laravel
  manager.
- [ ] **[feature]** Resolving `auth` twice returns the same instance (singleton binding).
- [ ] **[feature]** `Auth::guard('jwt')` resolves to a `JwtGuard`.
- [ ] **[feature]** `Auth::guard('basic')` resolves to a `BasicGuard`.
- [ ] **[feature]** `Auth::createUserProvider('users')` returns a `ModelProvider` when configured with
  `driver => model`.

---

## 2. `AuthServiceProvider` (`src/Auth/AuthServiceProvider.php`)

### Registration

- [ ] **[feature]** Provider merges `config/iam.php` into `config('iam')` (the merged config has `scopes.internal`,
  `scopes.external`, `jwt.expiry`, `jwt.algorithm`).
- [ ] **[feature]** Merge does not overwrite values the consumer has already set in their own `config/iam.php`.
- [ ] **[feature]** `auth` is registered as a singleton bound to `AuthManager`.

### Publishing

- [ ] **[feature]** When `runningInConsole()` is true, `iam-config` publish group is registered and points at
  `config_path('iam.php')`.
- [ ] **[feature]** When not running in console, no publish group is registered.
- [ ] **[feature]** Running `vendor:publish --tag=iam-config` writes `config/iam.php` into the host application.

### Event listener wiring

- [ ] **[feature]** `DeviceAuthenticated` is wired to `UpdateDeviceTimestamp` via the framework dispatcher.
- [ ] **[feature]** Dispatching `DeviceAuthenticated` after boot triggers `UpdateDeviceTimestamp::handle` exactly once.
- [ ] **[feature]** No other listeners are registered against `DeviceAuthenticated` from this provider.

### Custom provider extension

- [ ] **[feature]** `model` driver is registered on the auth factory.
- [ ] **[feature]** Resolving the `model` provider returns a `ModelProvider` constructed with the framework's `hash`
  service.
- [ ] **[feature]** Resolving the `model` provider passes through the configured `model` class.
- [ ] **[unit]** Resolving the `model` provider with a missing `model` key throws `RuntimeException` with message
  *Missing model configuration for auth provider*.
- [ ] **[unit]** Resolving the `model` provider with `model => ''` (empty string) throws (uses `empty()`).
- [ ] **[unit]** Resolving the `model` provider with `model => null` throws.
- [ ] **[unit]** Resolving the `model` provider with `model => 0` throws (proves the empty check is `empty()` not
  `isset()`).

### Custom guard extension — `jwt`

- [ ] **[feature]** `jwt` driver is registered on the auth factory.
- [ ] **[feature]** Resolving a `jwt` guard returns an instance of `JwtGuard`.
- [ ] **[feature]** Resolved JWT guard has the framework dispatcher set (verify via `getDispatcher()`).
- [ ] **[feature]** Resolved JWT guard has the framework request injected (verify via `getRequest()`).
- [ ] **[feature]** Rebinding `request` in the container after the guard is constructed updates the guard's request
  reference (proves `app->refresh('request', $guard, 'setRequest')` wiring).
- [ ] **[unit]** Configuring a `jwt` guard with no `secret` throws `RuntimeException` *Missing JWT secret in guard
  configuration*.
- [ ] **[unit]** Configuring a `jwt` guard with `secret => ''` throws.
- [ ] **[unit]** Configuring a `jwt` guard with `secret => 123` (non-string) throws.
- [ ] **[feature]** JWT guard receives the configured `secret` (verify via `getSecret()`).
- [ ] **[feature]** JWT guard receives the user provider for the configured `provider` key.
- [ ] **[feature]** JWT guard with no `provider` key uses the default provider.
- [ ] **[feature]** Two `jwt` guards configured against different providers/secrets do not share state.

### Custom guard extension — `basic`

- [ ] **[feature]** `basic` driver is registered on the auth factory.
- [ ] **[feature]** Resolving a `basic` guard returns an instance of `BasicGuard`.
- [ ] **[feature]** Resolved Basic guard has the framework dispatcher set.
- [ ] **[feature]** Resolved Basic guard has the framework request injected.
- [ ] **[feature]** Rebinding `request` in the container updates the Basic guard's request reference.
- [ ] **[feature]** Basic guard receives the user provider for the configured `provider` key.
- [ ] **[feature]** Basic guard with no `provider` key uses the default provider.

### Composer / package autoload

- [ ] **[unit]** `composer.json` declares zero `require` entries for any other `sinemacula/laravel-*` IAM package (mfa,
  sso, authorization, audit-log, iam).
- [ ] **[integration]** A clean Laravel install with this package installed has no
  `sinemacula/laravel-mfa|sso|authorization|audit-log|iam` directories under `vendor/`.
- [ ] **[unit]** `composer.json` `extra.laravel.providers` lists `AuthServiceProvider`.

---

## 3. `AbstractGuard` (`src/Auth/Guards/AbstractGuard.php`)

> Behaviour shared by `JwtGuard` and `BasicGuard`. Many of these are easiest to
> exercise via a thin in-memory subclass that lets the test set
> `isPayloadValid()` outcomes deterministically. Where parity matters
> (`hasValidCredentials`, principal resolution, event ordering) we should
> ALSO assert through `JwtGuard` and `BasicGuard` directly.

### Constructor

- [ ] **[unit]** `name` is exposed as a readonly property.
- [ ] **[unit]** Provider passed in constructor is the same instance returned by `getProvider()`.
- [ ] **[unit]** Request passed in constructor is the same instance returned by `getRequest()`.
- [ ] **[unit]** Dispatcher is `null` until `setDispatcher()` is called (verify via `getDispatcher()`).

### `authenticate()` (`AbstractGuard.php:86`)

- [ ] **[unit]** Returns the resolved identity when `identity()` is non-null.
- [ ] **[unit]** Throws `Illuminate\Auth\AuthenticationException` when `identity()` is null.
- [ ] **[unit]** Does NOT throw when `identity()` is non-null after lazy resolution via `isPayloadValid()`.
- [ ] **[unit]** Exception thrown is exactly `AuthenticationException`, not a subclass.

### `identity()` lazy resolution (`AbstractGuard.php:96`)

- [ ] **[unit]** When `$this->identity` is already set, returns it without invoking `isPayloadValid()`.
- [ ] **[unit]** When `$this->identity` is null and `isPayloadValid()` returns true (and itself sets `$this->identity`),
  returns the now-set identity.
- [ ] **[unit]** When `$this->identity` is null and `isPayloadValid()` returns false, returns null.
- [ ] **[unit]** Calling `identity()` repeatedly when already authenticated does not re-invoke `isPayloadValid()` (
  memoisation guard).
- [ ] **[unit]** Calling `identity()` after `logout()` returns null (state was cleared).

### `check()` / `guest()` (`AbstractGuard.php:106`, `:116`)

- [ ] **[unit]** `check()` returns true iff `identity()` is non-null.
- [ ] **[unit]** `check()` returns false when `identity()` returns null.
- [ ] **[unit]** `guest()` is the strict inverse of `check()` for the authenticated case.
- [ ] **[unit]** `guest()` is the strict inverse of `check()` for the unauthenticated case.

### `user()` (`AbstractGuard.php:126`)

- [ ] **[unit]** Returns the same value `identity()` returns (Identity instance).
- [ ] **[unit]** Returns null when no identity is resolved.
- [ ] **[unit]** Return type satisfies `Illuminate\Contracts\Auth\Authenticatable` (so framework typehints accept it).

### `id()` type narrowing (`AbstractGuard.php:136`)

- [ ] **[unit]** Returns `int` when `getAuthIdentifier()` returns an int.
- [ ] **[unit]** Returns `string` when `getAuthIdentifier()` returns a string.
- [ ] **[unit]** Returns `null` when no identity.
- [ ] **[unit]** Returns `null` (not the float) when `getAuthIdentifier()` returns a `float`.
- [ ] **[unit]** Returns `null` when `getAuthIdentifier()` returns an array.
- [ ] **[unit]** Returns `null` when `getAuthIdentifier()` returns an object.
- [ ] **[unit]** Returns `null` when `getAuthIdentifier()` returns a `bool`.
- [ ] **[unit]** Returns the literal `0` int and the literal `'0'` string (proves type check, not truthy check).

### `principal()` lazy resolution (`AbstractGuard.php:152`)

- [ ] **[unit]** When `$this->principal` already set, returns it without invoking `isPayloadValid()`.
- [ ] **[unit]** When null but `isPayloadValid()` populates principal, returns the principal.
- [ ] **[unit]** When null and `isPayloadValid()` returns false, returns null.

### `principalId()` type narrowing (`AbstractGuard.php:162`)

- [ ] **[unit]** Returns int when principal id is int.
- [ ] **[unit]** Returns string when principal id is string.
- [ ] **[unit]** Returns null when no principal.
- [ ] **[unit]** Returns null when principal id is a float / array / object / bool.

### `device()` lazy resolution (`AbstractGuard.php:178`)

- [ ] **[unit]** When `$this->device` already set, returns it without invoking `isPayloadValid()`.
- [ ] **[unit]** When null but `isPayloadValid()` populates device, returns the device.
- [ ] **[unit]** When null and payload doesn't bind a device, returns null.

### `deviceId()` type narrowing (`AbstractGuard.php:188`)

- [ ] **[unit]** Same matrix as `id()` and `principalId()`: int / string returned, null otherwise.
- [ ] **[unit]** Returns null when device is null.

### `organization()` (`AbstractGuard.php:205`)

- [ ] **[unit]** Returns the principal's organization when both exist.
- [ ] **[unit]** Returns null when there is no principal.
- [ ] **[unit]** Returns null when the principal exists but `getOrganization()` returns null (2D model with no org).

### `organizationId()` (`AbstractGuard.php:215`)

- [ ] **[unit]** Returns int / string per type narrowing matrix.
- [ ] **[unit]** Returns null when organization is null.
- [ ] **[unit]** Returns null when org id is float / array / bool / object.

### `scope()` (`AbstractGuard.php:231`)

- [ ] **[unit]** Returns the organisation's scope string.
- [ ] **[unit]** Returns null when organization is null (covers no-principal and no-org cases).

### `isInternal()` (`AbstractGuard.php:241`)

- [ ] **[unit]** Returns true when scope === `config('iam.scopes.internal')`.
- [ ] **[unit]** Returns false when scope is null.
- [ ] **[unit]** Returns false when scope === external value.
- [ ] **[unit]** Returns false when scope is a non-matching string.
- [ ] **[unit]** Comparison is **case sensitive** (`'internal'` ≠ `'INTERNAL'`).
- [ ] **[unit]** Comparison is **strict** — `'1'` ≠ `1` against config.
- [ ] **[unit]** Honours a runtime override of `config('iam.scopes.internal')` (set config to a custom string and assert
  behaviour).

### `isExternal()` (`AbstractGuard.php:251`)

- [ ] **[unit]** Mirror of `isInternal()` against `config('iam.scopes.external')`.
- [ ] **[unit]** Returns false when scope is null.
- [ ] **[unit]** Returns false when scope matches `internal` (proves it isn't `!isInternal()`).
- [ ] **[unit]** When internal and external are configured to the same string, both methods return true (documents the
  config foot-gun and pins behaviour).

### `attempt()` (`AbstractGuard.php:264`)

- [ ] **[unit]** Always fires `Attempting` first, with `name` and supplied credentials, `remember=false`.
- [ ] **[unit]** Calls `$provider->retrieveByCredentials($credentials)` exactly once.
- [ ] **[unit]** Returns false when provider returns `null`.
- [ ] **[unit]** Throws `RuntimeException` *The provider must return an instance of …Identity* when provider returns an
  `Authenticatable` that does NOT implement `Identity`.
- [ ] **[unit]** Returns false when identity has empty `getAuthPassword()` (`null` and `''`), without firing `Failed`.
- [ ] **[unit]** Returns true when credentials validate via `provider->validateCredentials()`.
- [ ] **[unit]** On success, fires `Validated` (inside `hasValidCredentials`) before `Login`.
- [ ] **[unit]** On success, fires events in order: `Attempting`, `Validated`, `Login`, `Authenticated`,
  `PrincipalAssigned`. (`DeviceAuthenticated` only when device supplied.)
- [ ] **[unit]** On failure (bad password), fires `Attempting` then `Failed` and returns false.
- [ ] **[unit]** On failure, `Failed` payload contains the credentials and the *attempted* identity (not null), when an
  identity was found but password mismatched.
- [ ] **[unit]** On failure where no identity was found, no `Failed` event is fired (the early return on empty
  `getAuthPassword()` short-circuits before `fireFailedEvent`).
- [ ] **[unit]** When caller passes an explicit `$principal`, that principal is used (not the default).
- [ ] **[unit]** When caller passes no principal and identity implements `Principal` (2D), the identity itself becomes
  the principal.
- [ ] **[unit]** When caller passes no principal and identity implements `HasPrincipals`, `resolveDefaultPrincipal()` on
  the identity is called.
- [ ] **[unit]** When caller passes no principal and `HasPrincipals::resolveDefaultPrincipal()` returns null, throws
  *Unable to resolve a principal for the given identity*.
- [ ] **[unit]** When caller passes no principal and identity implements neither `Principal` nor `HasPrincipals`, throws
  *Unable to resolve a principal for the given identity*.
- [ ] **[unit]** When caller passes a device, `setDevice()` is called and `DeviceAuthenticated` fires.
- [ ] **[unit]** When caller passes no device, `setDevice()` is NOT called and `DeviceAuthenticated` does NOT fire.

### `login()` (`AbstractGuard.php:300`)

- [ ] **[unit]** Fires `Login` event with `name`, identity, `remember=false`.
- [ ] **[unit]** Fires `Login` BEFORE `Authenticated` (the latter fires inside `setIdentity`).
- [ ] **[unit]** Calls `setAuth(identity, principal, device)` exactly once.
- [ ] **[unit]** After login, `identity()`, `principal()`, `device()` (when supplied) all return the supplied instances.
- [ ] **[unit]** When device is omitted, `device()` returns null after login.

### `logout()` (`AbstractGuard.php:312`)

- [ ] **[unit]** Returns immediately and fires NOTHING when no identity is set.
- [ ] **[unit]** When an identity is set, fires `Logout` exactly once with `name` and identity.
- [ ] **[unit]** After logout, `identity()`, `principal()`, `device()` all return null.
- [ ] **[unit]** Calling `logout()` twice fires `Logout` only on the first call.
- [ ] **[unit]** When `identity()` resolves lazily via `isPayloadValid()` (so `$this->identity` is set as a side
  effect), then `logout()` DOES fire `Logout` because the property is now non-null.
- [ ] **[unit]** After lazy-load + logout, principal and device are also cleared (not just identity).

### `setAuth()` (`AbstractGuard.php:335`)

- [ ] **[unit]** Calls `setIdentity` then `setPrincipal`.
- [ ] **[unit]** Calls `setDevice` only when device is non-null.
- [ ] **[unit]** Fires `Authenticated`, `PrincipalAssigned`, `DeviceAuthenticated` in that order when all three are set
  fresh.
- [ ] **[unit]** Does not call `setDevice` when device is null (no `DeviceAuthenticated` fired).

### `validate()` (`AbstractGuard.php:351`)

- [ ] **[unit]** Calls `provider->retrieveByCredentials()` exactly once.
- [ ] **[unit]** Returns true when provider returns a valid `Identity` and password matches.
- [ ] **[unit]** Returns false when provider returns null.
- [ ] **[unit]** Returns false when provider returns an `Authenticatable` that is not an `Identity` (sets
  `lastAttempted` to null first).
- [ ] **[unit]** Stores result in `lastAttempted` only when it implements `Identity`; non-Identity result clears it.
- [ ] **[unit]** Default `$credentials = []` is accepted and returns false (no provider lookup match).

### `attempting()` (`AbstractGuard.php:366`)

- [ ] **[unit]** Registers a callback against `Attempting::class` on the dispatcher.
- [ ] **[unit]** When dispatcher is null, does NOT throw and silently no-ops.
- [ ] **[unit]** Registered callback is invoked when `attempt()` fires `Attempting`.

### `hasUser()` (`AbstractGuard.php:376`)

- [ ] **[unit]** Returns true only when `$this->identity` (the property, not the getter) is non-null.
- [ ] **[unit]** Returns false before any authentication.
- [ ] **[unit]** Returns false even when a valid bearer token is present but `identity()` has not yet been called (does
  NOT trigger lazy load).

### `setUser()` (`AbstractGuard.php:387`)

- [ ] **[unit]** Delegates to `setIdentity()` and returns `$this`.
- [ ] **[unit]** Throws `RuntimeException` *The identity must implement …Identity* when given a Laravel
  `Authenticatable` that doesn't implement `Identity`.
- [ ] **[unit]** Fires `Authenticated` event when identity is new.

### `setIdentity()` (`AbstractGuard.php:400`)

- [ ] **[unit]** Throws when given a non-`Identity` authenticatable.
- [ ] **[unit]** When current identity is null, replaces it and fires `Authenticated`.
- [ ] **[unit]** When given identity has the **same** auth identifier as the current one, does NOT fire `Authenticated`
  again.
- [ ] **[unit]** When given identity has a different identifier, replaces it and fires `Authenticated`.
- [ ] **[unit]** Returns `$this` for chaining.
- [ ] **[unit]** Comparison is on `getAuthIdentifier()`, not object identity (two distinct instances with the same id
  are treated as the same identity).

### `setPrincipal()` (`AbstractGuard.php:420`)

- [ ] **[unit]** When current principal is null, replaces it and fires `PrincipalAssigned`.
- [ ] **[unit]** When new principal has the same identifier as current, does NOT re-fire.
- [ ] **[unit]** When new principal has a different identifier, replaces and fires.
- [ ] **[unit]** Returns `$this` for chaining.

### `setDevice()` (`AbstractGuard.php:436`)

- [ ] **[unit]** When current device is null, replaces it and fires `DeviceAuthenticated`.
- [ ] **[unit]** When new device has the same identifier, does NOT re-fire.
- [ ] **[unit]** When new device has a different identifier, replaces and fires.
- [ ] **[unit]** Returns `$this` for chaining.

### Request / Dispatcher / Provider getters & setters

- [ ] **[unit]** `setRequest`/`getRequest` round-trip.
- [ ] **[unit]** `setDispatcher`/`getDispatcher` round-trip.
- [ ] **[unit]** `setProvider`/`getProvider` round-trip.
- [ ] **[unit]** All setters return `$this`.

### `resolveDefaultPrincipal()` (`AbstractGuard.php:525`)

- [ ] **[unit]** When identity implements `Principal`, returns the identity itself.
- [ ] **[unit]** When identity implements `HasPrincipals` and `resolveDefaultPrincipal()` returns a principal, returns
  that principal.
- [ ] **[unit]** When identity implements `HasPrincipals` but returns null, throws `RuntimeException` *Unable to resolve
  a principal for the given identity*.
- [ ] **[unit]** When identity implements neither, throws same `RuntimeException`.
- [ ] **[unit]** When identity implements both, the `Principal` branch wins (returns the identity itself).

### `hasValidCredentials()` (`AbstractGuard.php:656`) — timing

- [ ] **[unit]** Returns false when identity is null without invoking `validateCredentials`.
- [ ] **[unit]** Returns false when `validateCredentials` returns false.
- [ ] **[unit]** Returns true when identity is non-null AND `validateCredentials` returns true.
- [ ] **[unit]** Fires `Validated` event ONLY on success (not on failure or null identity).
- [ ] **[unit]** On success, calls `Timebox::returnEarly()` (verify via spy / mocked Timebox).
- [ ] **[unit]** On failure, does NOT call `returnEarly()` so the timebox enforces the wait.
- [ ] **[unit]** Wraps the check in a Timebox with a 200,000 microsecond (200 ms) budget — assert the literal value
  passed to `Timebox::call()`.
- [ ] **[unit, slow]** Real-time test: failed credential check elapsed time ≥ ~200 ms when no identity is found AND when
  an identity exists with a wrong password (constant-time enumeration mitigation).
- [ ] **[unit]** First call to `timebox()` lazily constructs the instance; second call returns the same instance.

### Event firing helpers (private methods exercised through public API)

- [ ] **[unit]** `fireAttemptEvent` payload: guard name, credentials array, `remember=false`.
- [ ] **[unit]** `fireValidatedEvent` payload: guard name, identity instance.
- [ ] **[unit]** `fireLoginEvent` payload: guard name, identity, `remember=false`.
- [ ] **[unit]** `fireLogoutEvent` payload: guard name, identity.
- [ ] **[unit]** `fireAuthenticatedEvent` payload: guard name, identity.
- [ ] **[unit]** `firePrincipalAssignedEvent` payload: guard name, principal.
- [ ] **[unit]** `fireDeviceAuthenticatedEvent` payload: guard name, device.
- [ ] **[unit]** `fireRefreshedEvent` payload: guard name, identity.
- [ ] **[unit]** `fireFailedEvent` payload: guard name, identity (or null), credentials.
- [ ] **[unit]** All `fire*` helpers no-op when dispatcher is null (run a full successful auth flow with no dispatcher
  and assert no exception).
- [ ] **[unit]** Each `fire*` helper passes `$this->name` (the actual guard name, not a hardcoded string).

---

## 4. `JwtGuard` (`src/Auth/Guards/JwtGuard.php`)

### Constructor / accessors

- [ ] **[unit]** Stores secret and exposes via `getSecret()`.
- [ ] **[unit]** `setSecret()` mutates the stored secret and returns `$this`.
- [ ] **[unit]** Constructor calls parent with name, provider, request.

### `getPayload()` and `decodeToken()` (private — exercised via `isPayloadValid`)

- [ ] **[unit]** Returns null when `request->bearerToken()` is null.
- [ ] **[unit]** Returns null when bearer token is the empty string.
- [ ] **[unit]** Returns null when token is not a valid JWT (any parse exception).
- [ ] **[unit]** Returns null when token signature is signed with a different secret.
- [ ] **[unit]** Returns null when token uses a different algorithm than `HS256`.
- [ ] **[unit]** Returns array (decoded claims) when token is valid.
- [ ] **[unit]** Catches `Throwable` from `JWT::decode` (so any underlying library exception class downgrades to `null`,
  not a 500).

### `isPayloadValid()` — happy path (`JwtGuard.php:114`)

- [ ] **[unit]** With a valid token, sets `$this->identity`, `$this->device`, `$this->principal` and returns true.
- [ ] **[unit]** Calls `setIdentity()` (so `Authenticated` event fires) when identity is fresh.
- [ ] **[unit]** Sets `$this->device` and `$this->principal` directly **without** going through `setDevice()` /
  `setPrincipal()` — verify that `DeviceAuthenticated` and `PrincipalAssigned` events do NOT fire on token validation.

### `isPayloadValid()` — failure modes

- [ ] **[unit]** Returns false when payload is null (no bearer token).
- [ ] **[unit]** Returns false when payload missing `identity` claim.
- [ ] **[unit]** Returns false when payload missing `device` claim.
- [ ] **[unit]** Returns false when payload missing `principal` claim.
- [ ] **[unit]** Returns false when `expires_at` is missing.
- [ ] **[unit]** Returns false when `expires_at` is not a string (int, array, null).
- [ ] **[unit]** Returns false when `expires_at` is in the past (one second before now).
- [ ] **[unit]** Returns true when `expires_at` is one second in the future.
- [ ] **[unit]** Boundary: `expires_at == now` is treated as past (`isPast()` semantics) — pin whichever direction the
  implementation chooses.
- [ ] **[unit]** When `ignoreExpiry=true`, expiry is bypassed (refresh path).
- [ ] **[unit]** When `ignoreExpiry=true`, the rest of the validation (identity/device/principal/os) still runs.
- [ ] **[unit]** Returns false when `provider->retrieveById()` returns null.
- [ ] **[unit]** Returns false when `retrieveById()` returns an `Authenticatable` that does NOT implement `Identity`.
- [ ] **[unit]** Returns false when identity does not implement `HasDevices`.
- [ ] **[unit]** Returns false when identity does not implement `HasPrincipals`.
- [ ] **[unit]** Returns false when identity implements `HasDevices` only (must implement BOTH).
- [ ] **[unit]** Returns false when identity implements `HasPrincipals` only.
- [ ] **[unit]** Returns false when `devices()->find()` returns null.
- [ ] **[unit]** Returns false when `devices()->find()` returns a model that does NOT implement `Device` (sets `device`
  to null then bails).
- [ ] **[unit]** Returns false when `principals()->find()` returns null.
- [ ] **[unit]** Returns false when `principals()->find()` returns a model that does NOT implement `Principal`.
- [ ] **[unit]** When principal exists but `isActive()` returns false, **clears** `identity`, `device`, AND `principal`
  to null and returns false.
- [ ] **[unit]** Inactive-principal branch: `Auth::user()` returns null afterwards (state is fully reset).
- [ ] **[unit]** Returns false when device's `lastLoggedIn` is null.
- [ ] **[unit]** Returns false when `lastLoggedIn->getTimestamp() !== payload['logged_in_at']`.
- [ ] **[unit]** Returns false when `device->getOperatingSystem() !== payload['os']`.
- [ ] **[unit]** Returns true only when ALL of: identity found, HasDevices, HasPrincipals, device found, principal
  found, principal active, lastLoggedIn timestamp matches, OS matches.
- [ ] **[unit]** When timestamps and OS match, the returned `true` is from the final boolean expression, not a sneaky
  early return.

### `refresh()` (`JwtGuard.php:79`)

- [ ] **[unit]** Returns null when `decodeToken($refreshToken)` returns null (invalid refresh JWT).
- [ ] **[unit]** Returns null when current bearer token in the request is also invalid (`isPayloadValid(true)` false).
- [ ] **[unit]** Returns null when bearer token is valid but no device is bound (synthetic case where device is somehow
  null after validation).
- [ ] **[unit]** Returns null when refresh payload `key` is missing.
- [ ] **[unit]** Returns null when refresh payload `key` is non-string (int, array).
- [ ] **[unit]** Returns null when `Hash::check(key, device->getRefreshKey())` returns false.
- [ ] **[unit]** Returns the bound identity when key matches.
- [ ] **[unit]** Fires exactly one `Refreshed` event when key matches (and identity is set).
- [ ] **[unit]** Does NOT fire `Refreshed` when refresh fails for any reason.
- [ ] **[unit]** `Refreshed` event payload contains the guard name and identity.
- [ ] **[unit]** Refresh path bypasses expiry of the access token (an expired access token + valid refresh succeeds).
- [ ] **[unit]** Refresh path still enforces OS / `logged_in_at` matching (the second `isPayloadValid(true)` call covers
  them).
- [ ] **[unit]** Refresh path uses `Hash::check`, not `===` (verify with a hashed value vs raw key).
- [ ] **[unit]** Refresh does NOT issue / return a new JWT itself — it returns the identity for the caller to mint a
  token (pin behaviour).

### `resolveDefaultPrincipal()` override (`JwtGuard.php:173`)

- [ ] **[unit]** Same matrix as the abstract version: returns identity if `Principal`, calls `HasPrincipals` resolver,
  throws otherwise.
- [ ] **[unit]** Override has identical observable behaviour to the parent (regression guard against drift).

---

## 5. `BasicGuard` (`src/Auth/Guards/BasicGuard.php`)

### `getCredentials()` (private)

- [ ] **[unit]** Returns `['key' => request->getUser(), 'password' => request->getPassword()]`.
- [ ] **[unit]** Returns `['key' => null, 'password' => null]` when request has no Authorization header.

### `isPayloadValid()` (`BasicGuard.php:26`)

- [ ] **[unit]** Returns false when `validate()` returns false.
- [ ] **[unit]** Returns false when `validate()` returns true but `lastAttempted` is somehow null (defensive branch).
- [ ] **[unit]** Returns true when validation succeeds AND lastAttempted is set.
- [ ] **[unit]** On success calls `setIdentity($lastAttempted)` (firing `Authenticated`).
- [ ] **[unit]** On success sets `$this->principal` directly via `resolveDefaultPrincipal($lastAttempted)` — does NOT go
  through `setPrincipal()`, so `PrincipalAssigned` does NOT fire on bearer auth via Basic.

### `resolveDefaultPrincipal()` override (`BasicGuard.php:48`)

- [ ] **[unit]** Returns the identity itself when it implements `Principal`.
- [ ] **[unit]** Throws `RuntimeException` *Basic guard requires the identity to implement …Principal* when identity
  does NOT implement `Principal`.
- [ ] **[unit]** Throws even when identity implements `HasPrincipals` (Basic intentionally only supports 2D).

### End-to-end Basic flow

- [ ] **[feature]** Valid `Authorization: Basic <base64(user:pass)>` resolves identity & principal.
- [ ] **[feature]** Invalid credentials → `check()` false, `user()` null.
- [ ] **[feature]** Missing Authorization header → `check()` false.
- [ ] **[feature]** Username with no matching identity → `check()` false in ~constant time.
- [ ] **[feature]** Valid username, wrong password → `check()` false in ~constant time.

---

## 6. `ModelProvider` (`src/Auth/Providers/ModelProvider.php`)

### `retrieveById()` (`ModelProvider.php:45`)

- [ ] **[unit]** Queries the configured model with `where(getAuthIdentifierName(), $identifier)`.
- [ ] **[unit]** Returns the matched model.
- [ ] **[unit]** Returns null when no row matches.
- [ ] **[unit]** Returns null when query returns something other than `Authenticatable` (defensive branch).
- [ ] **[unit]** Uses `first()` on the query, not `get()->first()`.

### `retrieveByToken()` (`ModelProvider.php:67`)

- [ ] **[unit]** Always returns null (remember-me is intentionally disabled).
- [ ] **[unit]** Does NOT touch the database.

### `updateRememberToken()` (`ModelProvider.php:82`)

- [ ] **[unit]** Is a no-op (does not save the model, does not throw).
- [ ] **[unit]** Returns void with no side effect even when given a real Eloquent model.

### `retrieveByCredentials()` (`ModelProvider.php:95`)

- [ ] **[unit]** Returns null when credentials are empty.
- [ ] **[unit]** Returns null when credentials only contain password-like keys (filtered to empty).
- [ ] **[unit]** Filters out any key containing `'password'` (test: `'password'`, `'old_password'`,
  `'password_confirmation'`, `'user_password'`).
- [ ] **[unit]** Does NOT filter out a key containing `'pass'` only (proves the substring is `'password'`).
- [ ] **[unit]** Scalar value uses `where(key, value)`.
- [ ] **[unit]** Plain array value uses `whereIn(key, array)`.
- [ ] **[unit]** `Arrayable` value uses `whereIn(key, value)` (verify with a `Collection`).
- [ ] **[unit]** `Closure` value is invoked with the query builder.
- [ ] **[unit]** Multiple credentials are AND-combined.
- [ ] **[unit]** Returns the matched model.
- [ ] **[unit]** Returns null when no row matches.
- [ ] **[unit]** Returns null when query returns non-`Authenticatable`.

### `validateCredentials()` (`ModelProvider.php:133`)

- [ ] **[unit]** Returns false when `password` key is missing.
- [ ] **[unit]** Returns false when `password` is `null`.
- [ ] **[unit]** Returns false when `password` is an int/array/object.
- [ ] **[unit]** Returns true when `hasher->check(plain, getAuthPassword())` returns true.
- [ ] **[unit]** Returns false when `hasher->check()` returns false.
- [ ] **[unit]** Calls `hasher->check()` exactly once.
- [ ] **[unit]** Passes plain password (not hashed) and the user's stored hash to the hasher (argument order matters).

### `rehashPasswordIfRequired()` (`ModelProvider.php:155`)

- [ ] **[unit]** Returns immediately when `password` key is missing.
- [ ] **[unit]** Returns immediately when `password` is non-string.
- [ ] **[unit]** Returns immediately when `needsRehash()` is false AND `force` is false.
- [ ] **[unit]** Rehashes when `needsRehash()` is true and `force` is false.
- [ ] **[unit]** Rehashes when `needsRehash()` is false and `force` is true.
- [ ] **[unit]** Rehashes when both are true.
- [ ] **[unit]** Returns immediately (no save) when user is not an Eloquent `Model`.
- [ ] **[unit]** Calls `user->setAttribute(getAuthPasswordName(), hasher->make(plain))`.
- [ ] **[unit]** Calls `user->save()` exactly once after setting the attribute.
- [ ] **[unit]** Setter is called BEFORE save (order).

### `createModel()` (`ModelProvider.php:183`)

- [ ] **[unit]** Returns a fresh instance of the configured class.
- [ ] **[unit]** Strips a leading backslash before instantiation (`'\\App\\User'` → `'App\\User'`).
- [ ] **[unit]** Tolerates a class string with no leading backslash (no double-strip).
- [ ] **[unit]** Each call returns a new instance, not a shared one.

### `filterCredentials()` (private — exercised via `retrieveByCredentials`)

- [ ] **[unit]** Removes `'password'`.
- [ ] **[unit]** Removes any key whose name contains `'password'`.
- [ ] **[unit]** Preserves all other keys (including `'email'`, `'username'`, `'token'`, `'pass'`).

---

## 7. Events (`src/Auth/Events/`)

### Common to all three

- [ ] **[unit]** Each event uses `Illuminate\Queue\SerializesModels`.
- [ ] **[unit]** Each event survives serialize/unserialize round-trip when the payload contains an Eloquent model (
  proves `SerializesModels` works at runtime).
- [ ] **[unit]** Each event is dispatchable via Laravel's standard `Event::dispatch()` and observable via
  `Event::listen()`.

### `DeviceAuthenticated`

- [ ] **[unit]** `guard` is a public string property assigned from constructor arg 1.
- [ ] **[unit]** `device` is a public `Device` property assigned from constructor arg 2.
- [ ] **[unit]** No additional logic in the constructor.

### `PrincipalAssigned`

- [ ] **[unit]** `guard` and `principal` public properties as above.

### `Refreshed`

- [ ] **[unit]** `guard` and `identity` public properties as above.

---

## 8. `UpdateDeviceTimestamp` listener (`src/Auth/Listeners/UpdateDeviceTimestamp.php`)

- [ ] **[unit]** When `event->device` is not an Eloquent `Model`, returns without saving.
- [ ] **[unit]** When `event->device` is an Eloquent Model, calls `setAttribute('logged_in_at', now)` then `save()`.
- [ ] **[unit]** Sets the attribute to a `Carbon::now()` value (assert it's a Carbon, within ±1s of test execution).
- [ ] **[unit]** Calls `setAttribute` BEFORE `save` (order matters).
- [ ] **[unit]** Always uses the literal `'logged_in_at'` attribute name (regression guard if someone wires this to the
  trait's configurable name in future).
- [ ] **[feature]** Listener is auto-fired when `DeviceAuthenticated` is dispatched and updates a real device row in the
  database.
- [ ] **[feature]** Listener does NOT update other device rows in the database.

---

## 9. `Auth` facade (`src/Auth/Facades/Auth.php`)

- [ ] **[unit]** Class extends `Illuminate\Support\Facades\Auth`.
- [ ] **[feature]** Resolves through the same `auth` container binding as the base facade (so
  `\SineMacula\…\Auth::user()` and `\Illuminate\Support\Facades\Auth::user()` return identical results).
- [ ] **[feature]** Calling `Auth::principal()` proxies to the current guard's `principal()`.
- [ ] **[feature]** Calling `Auth::device()` proxies to the current guard's `device()`.
- [ ] **[feature]** Calling `Auth::organization()` proxies to the current guard's `organization()`.
- [ ] **[feature]** Calling `Auth::scope()` proxies to the current guard's `scope()`.
- [ ] **[feature]** Calling `Auth::isInternal()` / `Auth::isExternal()` proxy to the current guard's methods.
- [ ] **[feature]** Calling `Auth::refresh($token)` proxies to the JWT guard's `refresh()`.
- [ ] **[feature]** Contextual methods on an unauthenticated guard return null / false without throwing.

---

## 10. Contracts (`src/Auth/Contracts/`)

Light shape tests — these mostly catch accidental signature drift.

- [ ] **[unit]** `Identity` extends `Illuminate\Contracts\Auth\Authenticatable`.
- [ ] **[unit]** `IdentityProvider` extends `Illuminate\Contracts\Auth\UserProvider`.
- [ ] **[unit]** `Factory` extends `Illuminate\Contracts\Auth\Factory`.
- [ ] **[unit]** `ContextualGuard` extends `Illuminate\Contracts\Auth\Guard`.
- [ ] **[unit]** `ContextualGuard` declares: `attempt`, `login`, `identity`, `principal`, `device`, `organization`,
  `scope`, `isInternal`, `isExternal`, `setPrincipal`, `setDevice`. Verify every method via reflection so a missing
  method fails the suite.
- [ ] **[unit]** `Device` declares: `getDeviceIdentifier`, `getLastLoggedIn`, `getLastMfaVerification`,
  `getOperatingSystem`, `getRefreshKey`. Reflection check for each.
- [ ] **[unit]** `Principal` declares: `getPrincipalIdentifier`, `getIdentity`, `getOrganization`, `isActive`.
- [ ] **[unit]** `Organization` declares: `getOrganizationIdentifier`, `getOrganizationScope`.
- [ ] **[unit]** `HasDevices::devices()` return type is `Builder`.
- [ ] **[unit]** `HasPrincipals::principals()` return type is `Builder`; `resolveDefaultPrincipal()` returns
  `?Principal`.
- [ ] **[unit]** Each guard (`JwtGuard`, `BasicGuard`) implements `ContextualGuard` via reflection.
- [ ] **[unit]** Each guard implements `Illuminate\Contracts\Auth\Guard` (so framework typehints accept it).
- [ ] **[unit]** Each guard satisfies every method on `Illuminate\Contracts\Auth\Guard` (`check`, `guest`, `user`, `id`,
  `validate`, `hasUser`, `setUser`) — call each via the parent contract type.

---

## 11. Traits (`src/Auth/Traits/`)

Tests use small in-memory stub Eloquent models with the trait composed in.

### `ActsAsDevice`

- [ ] **[unit]** `getDeviceIdentifierName()` returns the model's primary key name by default.
- [ ] **[unit]** `getDeviceIdentifier()` returns the value of `getDeviceIdentifierName()` attribute.
- [ ] **[unit]** Default `lastLoggedInName` is `'logged_in_at'`.
- [ ] **[unit]** `getLastLoggedIn()` returns whatever attribute is at the configured name (Carbon when cast).
- [ ] **[unit]** Returns null when the underlying attribute is null.
- [ ] **[unit]** Default `lastMfaVerificationName` is `'last_mfa_verified_at'`.
- [ ] **[unit]** `getLastMfaVerification()` returns the configured attribute.
- [ ] **[unit]** Default `operatingSystemName` is `'os'`.
- [ ] **[unit]** `getOperatingSystem()` casts to string (verify with int attribute → `'1'`).
- [ ] **[unit]** Default `refreshKeyName` is `'key'`.
- [ ] **[unit]** `getRefreshKey()` returns the configured attribute as-is.
- [ ] **[unit]** Subclass can override any of the four `*Name` properties and the getters honour the override.

### `ActsAsPrincipal`

- [ ] **[unit]** `getPrincipalIdentifierName()` returns primary key name.
- [ ] **[unit]** `getPrincipalIdentifier()` returns the value at that attribute.
- [ ] **[unit]** Default `identityRelationName` is `'user'`.
- [ ] **[unit]** `getIdentity()` returns the value of the configured relation.
- [ ] **[unit]** Default `organizationRelationName` is `'organization'`.
- [ ] **[unit]** `getOrganization()` returns the value of the configured relation.
- [ ] **[unit]** `getOrganization()` returns null when the relation is null (3D model with no org).
- [ ] **[unit]** Default `isActive()` returns `true`.
- [ ] **[unit]** Subclass can override `isActive()` and the override is honoured by `JwtGuard::isPayloadValid` (
  integration check).
- [ ] **[unit]** Relation name overrides take effect.

### `ActsAsOrganization`

- [ ] **[unit]** `getOrganizationIdentifierName()` returns primary key name.
- [ ] **[unit]** `getOrganizationIdentifier()` returns the value at that attribute.
- [ ] **[unit]** Default `scopeName` is `'scope'`.
- [ ] **[unit]** `getOrganizationScope()` returns the string value when attribute is a plain string.
- [ ] **[unit]** Casts an int attribute to string (`1` → `'1'`).
- [ ] **[unit]** When attribute is a `BackedEnum`, returns its `->value` cast to string.
- [ ] **[unit]** When attribute is a `BackedEnum` with int backing, the int value is cast to string (
  `Scope::Internal->value === 1` → `'1'`).
- [ ] **[unit]** When attribute is a `UnitEnum` (non-backed), returns `->name`.
- [ ] **[unit]** When attribute is `null`, returns the empty string (`(string) null === ''`) — pin documented behaviour.
- [ ] **[unit]** Subclass can override `scopeName`.
- [ ] **[unit]** `BackedEnum` branch precedes `UnitEnum` branch (a `BackedEnum` is also a `UnitEnum`; wrong order would
  return name not value).

### `Authenticatable` trait

- [ ] **[unit]** Composes `Illuminate\Auth\Authenticatable`.
- [ ] **[unit]** `getRememberTokenName()` returns the empty string `''` (intentional override — disables remember-me).
- [ ] **[unit]** `setRememberToken()` is callable (inherited) but a no-op against persistence (verify by integrating
  with `ModelProvider::updateRememberToken()`).
- [ ] **[unit]** Identity model using this trait satisfies `Illuminate\Contracts\Auth\Authenticatable` (passes type
  check).

---

## 12. Configuration (`config/iam.php`)

- [ ] **[unit]** `scopes.internal` defaults to `'INTERNAL'` when env var unset.
- [ ] **[unit]** `scopes.external` defaults to `'EXTERNAL'` when env var unset.
- [ ] **[unit]** `scopes.internal` honours `IAM_SCOPE_INTERNAL` env override.
- [ ] **[unit]** `scopes.external` honours `IAM_SCOPE_EXTERNAL` env override.
- [ ] **[unit]** `jwt.expiry` defaults to `5` when env unset (units = minutes per architecture decision; pin whichever
  the implementation enforces).
- [ ] **[unit]** `jwt.expiry` honours `IAM_JWT_EXPIRY` override.
- [ ] **[unit]** `jwt.algorithm` is `'HS256'` (no env binding).
- [ ] **[feature]** Consumer overriding `config('iam.scopes.internal')` at runtime changes `Auth::isInternal()`
  behaviour without restart.

---

## 13. PRD-level acceptance tests (PRD `01-laravel-authentication.md`)

These map directly to the **Acceptance criteria** in the PRD. Many are
duplicated above as unit tests; the goal here is the same assertion via the
real Laravel facade / middleware stack so we know the integration glue holds.

### Stateless JWT guard

- [ ] **[integration]** `Authorization: Bearer <valid jwt>` → `Auth::check() === true`.
- [ ] **[integration]** Same request → `Auth::user()` returns the identity.
- [ ] **[integration]** Same request → `Auth::id()` returns the identity's primary key.
- [ ] **[integration]** Same request → `Auth::principal()` returns the principal.
- [ ] **[integration]** Same request → `Auth::device()` returns the device record.
- [ ] **[integration]** Invalid JWT → `Auth::check() === false`, `Auth::user() === null`.
- [ ] **[integration]** Expired JWT → `Auth::check() === false`.
- [ ] **[integration]** Missing Authorization header → `Auth::check() === false`.
- [ ] **[integration]** JWT signed with the wrong secret → `Auth::check() === false`.
- [ ] **[integration]** JWT with `alg: none` → `Auth::check() === false`.
- [ ] **[integration]** JWT with a different algorithm (`RS256`) → `Auth::check() === false`.

### Stateless Basic guard

- [ ] **[integration]** Valid `Authorization: Basic` → `Auth::check() === true` and identity/principal/device exposed.
- [ ] **[integration]** Invalid Basic credentials → `Auth::check() === false`.
- [ ] **[integration]** Missing Basic header → `Auth::check() === false`.
- [ ] **[integration, slow]** Validation completes in ≥ ~200 ms whether or not the supplied identifier exists (
  timing-safe enumeration mitigation).

### Refresh token flow

- [ ] **[integration]** Valid refresh credential → new access token issued (caller side), `Refreshed` event fired,
  device's `logged_in_at` updated.
- [ ] **[integration]** Returned identity and principal from refresh match the original session.
- [ ] **[integration]** Revoked refresh credential (key altered server-side) → refresh fails, no new session, no
  `Refreshed` event.
- [ ] **[integration]** Invalid refresh credential → refresh fails, no new session, no `Refreshed` event.

### Laravel `Guard` contract compliance

- [ ] **[integration]** `auth` middleware (`auth:jwt`) protects a route — unauthenticated request returns 401 /
  redirects per Laravel default.
- [ ] **[integration]** `auth` middleware allows authenticated request through.
- [ ] **[integration]** `@auth` Blade directive renders correctly when authenticated.
- [ ] **[integration]** `@guest` Blade directive renders correctly when unauthenticated.
- [ ] **[integration]** Each shipped guard satisfies every method on `Illuminate\Contracts\Auth\Guard` via reflection.
- [ ] **[integration]** `Auth::shouldUse('jwt')` then `Auth::user()` works through the IAM facade.

### Standard Laravel auth events

- [ ] **[integration]** Successful auth via `attempt()` fires (in order): `Attempting`, `Validated`, `Login`,
  `Authenticated`.
- [ ] **[integration]** Failed auth fires `Attempting`, then `Failed`.
- [ ] **[integration]** Logout fires `Logout`.
- [ ] **[integration]** Each event payload contains the guard name in the same shape Laravel's first-party guards use.
- [ ] **[integration]** Each event payload contains the resolved authenticatable in the same shape Laravel emits.
- [ ] **[integration]** Listeners registered via `Event::listen` receive every event.
- [ ] **[integration]** No standard Laravel event is fired more than once per attempt/login/logout.

### Custom contextual events

- [ ] **[integration]** Successful authentication that resolves a principal fires `PrincipalAssigned` exactly once.
- [ ] **[integration]** `PrincipalAssigned` payload carries identity & principal (via the principal's `getIdentity()`).
- [ ] **[integration]** Successful authentication that binds a device fires `DeviceAuthenticated` exactly once.
- [ ] **[integration]** `DeviceAuthenticated` payload carries the device record.
- [ ] **[integration]** Successful refresh fires `Refreshed` exactly once with identity payload.
- [ ] **[integration]** No custom event is dispatched on a failed authentication.

### Contextual `Auth` facade methods

- [ ] **[integration]** Each of `principal()`, `device()`, `organization()`, `scope()` returns the resolved values when
  authenticated.
- [ ] **[integration]** Each returns null when unauthenticated.
- [ ] **[integration]** `isInternal()`, `isExternal()` return false when unauthenticated (do NOT throw).

### Principal resolver contract

- [ ] **[integration]** Consumer-supplied `HasPrincipals::resolveDefaultPrincipal()` return value is exposed through
  `Auth::principal()` after authentication.
- [ ] **[integration]** Guard contains no hard-coded reference to a specific Identity, Principal, Organization model
  name (regression scan / reflection).

### Polymorphic device tracking (forward-compat)

- [ ] **[integration]** Devices migration creates `authenticatable_type`, `authenticatable_id`, ULID primary key (when
  migration ships).
- [ ] **[integration]** A device record can reference any model the consumer designates as authenticatable through
  Laravel's polymorphic morph map.
- [ ] **[integration]** Composite index exists on `(authenticatable_type, authenticatable_id)`.
- [ ] **[integration]** Index exists on the refresh credential lookup column.
- [ ] **[integration]** Migration safety check (P1) — running migration when a `devices` table already exists surfaces a
  clear error before mutating state.

### Configurable Device model & table

- [ ] **[integration]** Setting a custom Device class in config causes guards to resolve devices through the custom
  class.
- [ ] **[integration]** Setting a custom table name causes the shipped Eloquent model to use that table name.
- [ ] **[integration]** Setting a custom table name causes the shipped migration to create that table name.

### Standalone installability

- [ ] **[integration]** Clean Laravel 13 install + this package only → test suite runs without any other
  `sinemacula/laravel-*` package present.
- [ ] **[unit]** `composer.json require` block contains zero `sinemacula/laravel-*` IAM siblings.

### 2D + 3D guard coexistence

- [ ] **[integration]** Application configures one route on a 2D guard and another on a 3D guard.
- [ ] **[integration]** 2D route: `Auth::user() === Auth::principal()` (same model).
- [ ] **[integration]** 3D route: `Auth::principal() !== Auth::user()` and `Auth::organization() !== null`.
- [ ] **[integration]** Both routes return correct results in the same test run (no static state leak between guards).
- [ ] **[integration]** Switching guards mid-request via `Auth::guard()->user()` does not bleed state across guards.

---

## 14. Cross-cutting / mutation-heavy edge cases

Things that mutation testers love to break that don't fit cleanly under one
class.

- [ ] **[unit]** Every `??=` and `??` operator in `AbstractGuard` and `JwtGuard` has a test for both branches (null path
  AND non-null path).
- [ ] **[unit]** Every `is_null()` / `!is_null()` check has a test for both branches.
- [ ] **[unit]** Every `instanceof` check has a test where the object IS an instance and where it ISN'T.
- [ ] **[unit]** Every `===` / `!==` comparison has a test where the values are equal and where they aren't (no swap
  with `==`).
- [ ] **[unit]** Boolean return helpers (`check`, `guest`, `hasUser`, `isInternal`, `isExternal`, `isActive`) each have
  a test for `true` AND `false`.
- [ ] **[unit]** Every `throw` is reachable from a test (each `RuntimeException` constructor message string is asserted
  to detect message-string mutations).
- [ ] **[unit]** Every method that returns `$this` has its return value asserted to be `$this` (not `null`, not a
  clone).
- [ ] **[unit]** Every public setter is followed in a separate test by the matching getter to confirm the value
  round-trips.
- [ ] **[unit]** Event payload assertions check exact field values, not just `instanceof EventClass` (catches mutations
  that swap argument order in event constructors).
- [ ] **[unit]** Event ordering tests use a recorder listener that captures `[event::class, payload]` tuples in the
  order they fire and assert the full sequence.
- [ ] **[unit]** Negative event tests: assert specific events DID NOT fire when they shouldn't (e.g., `Failed` not fired
  on missing-identity attempt; `DeviceAuthenticated` not fired when no device supplied; `Refreshed` not fired on a
  failed refresh).
- [ ] **[unit]** All `default` parameter values (`$device = null`, `$principal = null`, `$ignoreExpiry = false`,
  `$force = false`, `$credentials = []`) have a test that exercises the default and a test that overrides it.
- [ ] **[unit]** Constants/literals: pin the literal `200 * 1000` Timebox value, the literal `'HS256'` algorithm, the
  literal `'logged_in_at'` attribute name in the listener, the literal `'iam-config'` publish tag, and the literal
  `'Bearer'` scheme via the bearer token path.
- [ ] **[unit]** No code path swallows a `Throwable` other than `JwtGuard::decodeToken` (regression scan via static
  analysis or grep).

---

## 15. Suggested test scaffolding

> Not assertions — but worth building once so the assertions above stay cheap.

- A `RecordingDispatcher` test double that captures `[eventClass, payload, timeOrder]` tuples.
- A `StubIdentity` model implementing `Identity`, `HasDevices`, `HasPrincipals` with controllable principal & device
  collections.
- A `Stub2DUser` model implementing both `Identity` and `Principal` (for Basic / 2D tests).
- A `StubDevice` Eloquent model using `ActsAsDevice` with overridable `lastLoggedIn`, `os`, `refreshKey`.
- A `StubPrincipal` model using `ActsAsPrincipal` with controllable `isActive()` and `getOrganization()`.
- A `StubOrganization` with `ActsAsOrganization` and a configurable scope (string, BackedEnum, UnitEnum).
- A JWT factory helper that mints tokens with arbitrary claims so we can test missing-claim, wrong-type-claim, expired,
  future, OS-mismatch, timestamp-mismatch cases without re-implementing `firebase/php-jwt` in the test.
- A `FakeRequest` builder for `Authorization: Bearer` and `Authorization: Basic` headers.
- An in-memory subclass of `AbstractGuard` (`StubGuard`) that exposes a public `setIsPayloadValid(bool)` and a public
  `setPayloadResolution(Identity, ?Principal, ?Device)` for the AbstractGuard tests that don't want to go through the
  JWT/Basic concrete implementations.
