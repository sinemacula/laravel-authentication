# Guard Lifecycle and Events

## Purpose

This note records the event contract shared by the package guards. That contract matters because consumers may attach
security-sensitive listeners to Laravel's standard auth events and to the package's contextual events.

## Invariants

- Any real authentication attempt starts with Laravel's `Attempting` event.
- `Validated` means the identity has already been accepted by credentials or by an upstream mechanism such as bearer
  token verification or refresh. It does not guarantee that principal or device resolution will succeed afterwards.
- `Login` is fired before `Authenticated` to mirror Laravel's first-party guard ordering.
- `PrincipalAssigned` is emitted only after the identity is bound.
- `DeviceAuthenticated` is emitted only when a non-null device is bound.
- Rebinding clears any previously cached identity, principal, and device state before the new lifecycle begins.
- Request-local memoization is always on, but shared cross-request caching is opt-in and currently limited to JWT bearer
  identity rehydration through model providers.
- Basic auth and refresh stay live-only even when the optional shared bearer cache is enabled.

## Success Path

- `attempt()` emits `Attempting -> Validated -> Login -> Authenticated -> PrincipalAssigned -> DeviceAuthenticated?`.
- Direct `login()` emits the same sequence without `Attempting`. This is the package's public entry point for
  out-of-band authentication such as refresh, OAuth, or SSO callbacks.
- Bearer `user()` resolution may reuse a shared cached identity, then emits `Attempting` and routes through `login()`,
  so a successful bearer request still follows the direct `login()` sequence.
- Successful `refresh()` emits `Attempting`, then routes through `login()`, then emits the package `Refreshed` event.
- `logout()` emits Laravel's `Logout` event only when an identity was actually bound, then clears contextual state.

## Failure / Edge Cases

- No bearer token means there is nothing to attempt, so `JwtGuard::user()` returns `null` without firing auth events.
- A failed `attempt()` emits `Attempting` and `Failed`, but not `Login` or `Authenticated`.
- A successful credential check can still end in `Failed` if principal resolution later returns `null`, throws, or
  resolves an inactive principal. That is why `Validated` is not the same thing as "fully bound".
- Failed refresh emits Laravel's standard `Attempting` and `Failed` events plus the package `RefreshFailed` event with a
  machine-readable reason.
- `DeviceAuthenticated` is coupled to the shipped `UpdateDeviceTimestamp` listener, but only persisted `EloquentDevice`
  instances participate in that write path.
- Shared-cache store failures are fail-open: bearer auth falls back to a live identity lookup rather than denying auth
  or changing the event sequence.

## Implementation Anchors

- `src/Guards/Concerns/ValidatesGuardCredentials.php`: `hasValidCredentials()`, `fireAttemptingEvent()`,
  `fireValidatedEvent()`, `fireFailedEvent()`.
- `src/Guards/AbstractGuard.php`: `attempt()`, `login()`, `logout()`, `bindAuthenticationLifecycle()`,
  `resolveContextForCredentials()`.
- `src/Guards/Concerns/BindsContextualState.php`: `setPrincipal()`, `setDevice()`, `clearContextualState()`.
- `src/Guards/JwtGuard.php`: `resolveBearerToken()`, `refresh()`.
- `src/Cache/StoreBackedResolutionCache.php`: opt-in shared bearer identity cache.
- `src/Cache/ResolutionCacheInvalidator.php`: explicit invalidation hook for identity writes.
- `src/AuthServiceProvider.php`: listener registration for `DeviceAuthenticated`.
- `src/Listeners/UpdateDeviceTimestamp.php`: persisted side effect for rebound devices.

## Authoritative Tests

- `tests/Feature/Guards/AbstractGuardAttemptTest.php`
  `testAttemptDispatchesAttemptingEventBeforeValidation`
- `tests/Feature/Guards/AbstractGuardAttemptTest.php`
  `testAttemptDispatchesValidatedAfterSuccessfulHasherCheck`
- `tests/Feature/Guards/AbstractGuardLifecycleTest.php`
  `testLoginFiresValidatedEventBeforeBindingState`
- `tests/Feature/Guards/JwtGuardUserResolutionTest.php`
  `testUserBindsIdentityPrincipalAndDeviceFromValidToken`
- `tests/Feature/Guards/JwtGuardRefreshTest.php`
  `testRefreshDispatchesSuccessfulLifecycleEventsBeforeRefreshed`
- `tests/Feature/Guards/AbstractGuardLifecycleTest.php`
  `testSetRequestClearsBoundContextualState`
- `tests/Integration/Events/StandardAuthEventsIntegrationTest.php`
  `testSuccessfulAttemptDispatchesAttemptingThenValidatedThenLoginThenAuthenticated`
- `tests/Integration/Events/StandardAuthEventsIntegrationTest.php`
  `testBasicGuardNeverUsesResolutionCache`
- `tests/Integration/Events/CustomEventsIntegrationTest.php`
  `testRefreshedFiresAfterSuccessfulRefresh`
- `tests/Integration/Guards/JwtGuardResolutionFreshnessIntegrationTest.php`
  `testRefreshPathNeverUsesResolutionCache`

## Change Triggers

Update this note when any of the following change:

- the order or presence of `Attempting`, `Validated`, `Login`, `Authenticated`, `Failed`, `Logout`, `PrincipalAssigned`,
  `DeviceAuthenticated`, `Refreshed`, or `RefreshFailed`
- the decision to route bearer auth or refresh through `login()`
- the listener or persistence behavior attached to `DeviceAuthenticated`
- the rule that prior contextual state is cleared before rebinding
- the scope or semantics of the optional shared bearer identity cache
