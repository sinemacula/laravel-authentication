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
- Request-local memoization is always on: `user()` resolves a request at most once, whether it succeeds or fails, so a
  rejected token fires `Attempting` and `Failed` once. `setRequest()` starts over, an explicit `login()`, `attempt()`,
  or `setUser()` still binds after a failed resolution, and after `logout()` the guard stays signed out for the rest of
  the request. Nothing is persisted: there is no cross-request cache, and every bearer and refresh request reads the
  identity, principal, and device live.
- `id()`, `identity()`, `principal()`, `device()`, `tenant()`, and `type()` go through `user()`, so the first access on
  a request authenticates it even on a route without `auth` middleware, as Laravel's own guards do.

## Success Path

- `attempt()` emits `Attempting -> Validated -> Login -> Authenticated -> PrincipalAssigned -> DeviceAuthenticated?`.
- Direct `login()` emits the same sequence without `Attempting`. This is the package's public entry point for
  out-of-band authentication such as refresh, OAuth, or SSO callbacks.
- `setUser()` (behind Laravel's `actingAs()`) clears the previous context and emits `Authenticated -> PrincipalAssigned`
  for the identity and its default principal, without `Validated` or `Login`. An identity with no default principal is
  rejected with an `InvalidArgumentException` and the previous context is kept.
- Bearer `user()` resolution emits `Attempting` and routes through `login()`, so a successful bearer request follows
  the direct `login()` sequence.
- Successful `refresh()` emits `Attempting`, then routes through `login()`, then emits the package `Refreshed` event.
- `logout()` resolves the request if nothing has yet, emits Laravel's `Logout` event only when an identity is bound,
  then clears contextual state.

## Failure / Edge Cases

- No bearer token means there is nothing to attempt, so `JwtGuard::user()` returns `null` without firing auth events.
- A failed `attempt()` emits `Attempting` and `Failed`, but not `Login` or `Authenticated`.
- A successful credential check can still end in `Failed` if principal resolution later returns `null` or resolves a
  principal that is inactive or acts within an inactive tenant. That is why `Validated` is not the same thing as
  "fully bound".
- An `UnresolvableIdentityException` (an identity model that is neither a `Principal` nor `HasPrincipals`) is a
  misconfiguration, not a failed authentication. It propagates as a server error from `attempt()`, bearer resolution,
  and `refresh()`, with no `Failed` or `RefreshFailed` event.
- Activation is opt-in through `CanBeActive` on the identity, the principal, or the tenant, and is decided by
  `ActivationPolicy` on the credential, bearer, and refresh paths alike. A model without the capability is active.
- Failed refresh emits Laravel's standard `Attempting` and `Failed` events plus the package `RefreshFailed` event with a
  machine-readable reason.
- `DeviceAuthenticated` is coupled to the shipped `UpdateDeviceTimestamp` listener, but only persisted `EloquentDevice`
  instances participate in that write path.

## Implementation Anchors

- `src/Guards/Concerns/ValidatesGuardCredentials.php`: `hasValidCredentials()`, `fireAttemptingEvent()`,
  `fireValidatedEvent()`, `fireFailedEvent()`.
- `src/Guards/AbstractGuard.php`: `user()`, `resolveUserFromRequest()`, `attempt()`, `login()`, `logout()`,
  `setRequest()`, `bindAuthenticationLifecycle()`, `resolveContextForCredentials()`.
- `src/Guards/ActivationPolicy.php`: the opt-in identity, principal, and tenant activation checks.
- `src/Guards/Concerns/BindsContextualState.php`: the resolving accessors, `setPrincipal()`, `setDevice()`,
  `clearContextualState()`.
- `src/Guards/JwtGuard.php`: `resolveUserFromRequest()`, `resolveBearerToken()`, `refresh()`.
- `src/AuthenticationServiceProvider.php`: listener registration for `DeviceAuthenticated`.
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
- `tests/Integration/Events/CustomEventsIntegrationTest.php`
  `testRefreshedFiresAfterSuccessfulRefresh`
- `tests/Integration/Guards/JwtGuardResolutionFreshnessIntegrationTest.php`
  `testBearerRejectsPreviouslyIssuedTokenWhenIdentityBecomesInactiveBetweenRequests`
- `tests/Integration/Guards/ActivationOptInIntegrationTest.php`
  `testUserWithoutActiveColumnSignsInWithCredentials`
- `tests/Integration/Guards/TenantActivityIntegrationTest.php`
  `testBearerRejectsMemberOfTenantDeactivatedAfterIssue`
- `tests/Integration/Guards/MisconfiguredIdentityIntegrationTest.php`
  `testBearerRequestAnswersWithServerError`
- `tests/Integration/Guards/LazyContextResolutionIntegrationTest.php`
  `testAccessorResolvesBearerTokenWhenCalledFirst`
- `tests/Integration/Guards/RequestResolutionIntegrationTest.php`
  `testRejectedBearerTokenIsAttemptedOncePerRequest`, `testLogoutKeepsTheRequestSignedOut`
- `tests/Integration/Guards/ActingAsIntegrationTest.php`
  `testActingAsBindsEachIdentitysDefaultPrincipal`

## Change Triggers

Update this note when any of the following change:

- the order or presence of `Attempting`, `Validated`, `Login`, `Authenticated`, `Failed`, `Logout`, `PrincipalAssigned`,
  `DeviceAuthenticated`, `Refreshed`, or `RefreshFailed`
- the decision to route bearer auth or refresh through `login()`
- what `setUser()` binds
- the listener or persistence behavior attached to `DeviceAuthenticated`
- the rule that prior contextual state is cleared before rebinding
- the rule that bearer and refresh resolution read live state with no cross-request cache
