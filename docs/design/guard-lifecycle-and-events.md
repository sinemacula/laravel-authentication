# Guard Lifecycle and Events

## Purpose

This note records the event contract shared by the package guards. That contract matters because consumers may attach
security-sensitive listeners to Laravel's standard auth events and to the package's contextual events.

## Invariants

- Any real authentication attempt starts with Laravel's `Attempting` event.
- The credentials on `Attempting` and `Failed` never carry a password: keys whose name contains `password`
  (case-insensitive) are always removed, plus any fragment in `authentication.events.redacted_credential_keys`. The
  identifier and every other key are kept.
- `Validated` means the identity has already been accepted by credentials or by an upstream mechanism such as bearer
  token verification or refresh. It does not guarantee that principal or device resolution will succeed afterwards.
- `Login` is fired before `Authenticated` to mirror Laravel's first-party guard ordering.
- `PrincipalAssigned` is emitted only after the identity is bound.
- `DeviceAuthenticated` is emitted only when a non-null device is bound.
- Rebinding clears any previously cached identity, principal, and device state before the new lifecycle begins.
- A guard follows later container rebinds of the `events` dispatcher (and, without a guard-local override, of the
  `PrincipalResolver`), and passes each rebind on to its refresh exchange, so an `Event::fake()` made after the guard
  resolved receives `RefreshFailed` as well as the guard's own events.
- Request-local memoization is always on: `user()` resolves a request at most once, whether it succeeds or fails, so a
  rejected token fires `Attempting` and `Failed` once. `setRequest()` starts over, an explicit `login()`, `attempt()`,
  or `setUser()` still binds after a failed resolution, and after `logout()` the guard stays signed out for the rest of
  the request. A successful `login()` or `attempt()` (and so `refresh()`) settles the request before it fires `Login`,
  so a listener that reads the guard mid-bind never resolves the request's own token and leaves its device bound to
  the identity signing in. Nothing is persisted: there is no cross-request cache, and every bearer and refresh request
  reads the identity, principal, tenant, and device live, from the write connection.
- `id()`, `identity()`, `principal()`, `device()`, `tenant()`, and `type()` go through `user()`, so the first access on
  a request authenticates it even on a route without `auth` middleware, as Laravel's own guards do. `setPrincipal()`
  and `setDevice()` resolve the request first too, so a pin set before the first access replaces the principal or
  device the request's token binds instead of being replaced by it.

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
- A guest on a route that only package guards protect gets a JSON `401` whatever its `Accept` header: the package's
  `Http\Middleware\Authenticate` raises the `AuthenticationException` without evaluating Laravel's guest redirect, and
  `Http\UnauthenticatedResponse` renders it. Any other guard on the route keeps Laravel's response.
- A failed `attempt()` emits `Attempting` and `Failed`, but not `Login` or `Authenticated`.
- A principal or device pinned on `attempt()` is verified, not trusted: the principal goes through the resolver's hinted
  path and must come back as the same class with the same identifier (the bearer `pid` exact-match check) and be owned
  by the authenticated identity (its `getIdentity()` is that identity), and the device must be found among the
  identity's own `HasDevices` devices, of the same class and not revoked. The owner is read from the principal's stored
  key, ignoring an identity relation the resolver set, and an owner that cannot be read fails the check. The resolved
  instances are bound; a failed check fails the attempt. `login()` stays the trusted entry point.
- A successful credential check can still end in `Failed` if principal resolution later returns `null` or resolves a
  principal that is inactive or acts within an inactive tenant. That is why `Validated` is not the same thing as
  "fully bound".
- An `UnresolvableIdentityException` (an identity model that is neither a `Principal` nor `HasPrincipals`) is a
  misconfiguration, not a failed authentication. It propagates as a server error from `attempt()`, bearer resolution,
  and `refresh()`, with no `Failed` or `RefreshFailed` event.
- Activation is opt-in through `CanBeActive` on the identity, the principal, or the tenant, and is decided by
  `ActivationPolicy` on the credential, bearer, and refresh paths alike. A model without the capability is active. The
  tenant is read with the principal's connection pinned to the write connection. A principal whose tenant key names a
  tenant that opts in (`CanBeActive`) but cannot be loaded (deleted, soft-deleted, or scoped out) fails like one in an
  inactive tenant: `getTenant()` throws `TenantUnavailableException` rather than reporting no tenant, and a principal
  loaded without that tenant's key throws a `LogicException`. A tenant that does not opt in is never checked, and a
  relation to a model that is not a `Tenant` reports no tenant.
- Failed refresh emits Laravel's standard `Attempting` and `Failed` events plus the package `RefreshFailed` event with a
  machine-readable reason.
- `DeviceAuthenticated` is coupled to the shipped `UpdateDeviceTimestamp` listener, but only persisted `EloquentDevice`
  instances participate in that write path.

## Implementation Anchors

- `src/Guards/Concerns/ValidatesGuardCredentials.php`: `hasValidCredentials()`, `fireAttemptingEvent()`,
  `fireValidatedEvent()`, `fireFailedEvent()`, `redactCredentials()`.
- `src/Guards/AbstractGuard.php`: `user()`, `resolveUserFromRequest()`, `attempt()`, `login()`, `logout()`,
  `setRequest()`, `bindAuthenticationLifecycle()`, `resolveContextForCredentials()`.
- `src/Guards/ActivationPolicy.php`: the opt-in identity, principal, and tenant activation checks.
- `src/Guards/Concerns/BindsContextualState.php`: the resolving accessors, `setPrincipal()`, `setDevice()`,
  `clearContextualState()`.
- `src/Guards/Concerns/VerifiesPinnedContext.php`: the ownership checks for principals and devices pinned on
  `attempt()`.
- `src/Guards/JwtGuard.php`: `resolveUserFromRequest()`, `resolveBearerToken()`, `refresh()`.
- `src/AuthenticationServiceProvider.php`: listener registration for `DeviceAuthenticated`, `wireGuardRebinds()`, the
  `auth` middleware binding, and the guest response render callback.
- `src/Guards/JwtGuard.php` and `src/Jwt/RefreshTokenExchange.php`: `setDispatcher()` and `setPrincipalResolver()`, which
  keep the exchange on the guard's dispatcher and resolver.
- `src/Http/Middleware/Authenticate.php`, `src/Http/UnauthenticatedResponse.php`: the package guards' `401`.
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
- `tests/Feature/Guards/JwtGuardRefreshResolutionTest.php`
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
  `testBearerRejectsMemberOfTenantDeactivatedAfterIssue`, `testBearerRejectsMemberOfSoftDeletedTenant`
- `tests/Integration/Guards/TenantActivityIntegrationTest.php`
  `testTenantCheckReportsAMembershipLoadedWithoutItsTenantKey`
- `tests/Integration/Guards/TenantOptInIntegrationTest.php`
  `testUserWhoseTenantRelationIsNotATenantActsWithinNoTenant`, `testUserWhoseNonActivatableTenantIsDeletedStillSignsIn`
- `tests/Integration/Guards/MisconfiguredIdentityIntegrationTest.php`
  `testBearerRequestAnswersWithServerError`
- `tests/Integration/Guards/LazyContextResolutionIntegrationTest.php`
  `testAccessorResolvesBearerTokenWhenCalledFirst`, `testPinsSetBeforeFirstAccessAreNotReplacedByTheBearerToken`
- `tests/Integration/Guards/LazyContextResolutionIntegrationTest.php`
  `testLoginListenerReadingTheGuardDoesNotBindTheBearerTokensDevice`
- `tests/Integration/Guards/RequestResolutionIntegrationTest.php`
  `testRejectedBearerTokenIsAttemptedOncePerRequest`, `testLogoutKeepsTheRequestSignedOut`
- `tests/Integration/Guards/ActingAsIntegrationTest.php`
  `testActingAsBindsEachIdentitysDefaultPrincipal`
- `tests/Integration/Events/StandardAuthEventsIntegrationTest.php`
  `testAttemptingAndFailedEventsCarryNoPasswordLikeCredentials`
- `tests/Integration/Http/UnauthenticatedResponseIntegrationTest.php`
  `testGuestOnPackageGuardGetsUnauthorized`, `testGuestOnSessionGuardKeepsLaravelsResponse`
- `tests/Integration/Guards/PinnedContextOwnershipIntegrationTest.php`
  `testPrincipalOfAnotherClassWithTheSameIdentifierFailsTheAttempt`, `testAnotherMembersDeviceFailsTheAttempt`
- `tests/Integration/Guards/PinnedContextOwnershipIntegrationTest.php`
  `testAnotherMembersMembershipFailsEvenWhenTheResolverIsNotScoped`
- `tests/Integration/Guards/PinnedContextOwnershipIntegrationTest.php`
  `testAnotherMembersMembershipFailsEvenWhenTheResolverSetsTheInverseRelation`,
  `testMembershipWhoseOwnerIsDeletedFailsTheAttempt`
- `tests/Feature/Guards/VerifiesPinnedContextTest.php`
  `testPinnedPrincipalWithoutAnOwnerRelationFailsTheAttempt`
- `tests/Feature/AuthenticationServiceProviderTest.php`
  `testJwtGuardRefreshExchangeTracksLaterEventDispatcherRebind`

## Change Triggers

Update this note when any of the following change:

- the order or presence of `Attempting`, `Validated`, `Login`, `Authenticated`, `Failed`, `Logout`, `PrincipalAssigned`,
  `DeviceAuthenticated`, `Refreshed`, or `RefreshFailed`
- which credential keys are redacted from `Attempting` and `Failed`
- the response a guest gets on a route protected by package guards
- the decision to route bearer auth or refresh through `login()`
- what `setUser()` binds
- the listener or persistence behavior attached to `DeviceAuthenticated`
- how dispatcher and resolver rebinds reach the guard and its refresh exchange
- the rule that prior contextual state is cleared before rebinding
- the rule that bearer and refresh resolution read live state from the write connection with no cross-request cache
