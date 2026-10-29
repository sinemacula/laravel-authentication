# Guard Lifecycle and Events

## Purpose

This note records the event contract shared by the package guards. That contract matters because consumers may attach
security-sensitive listeners to Laravel's standard auth events and to the package's contextual events.

## Invariants

- Any sign-in attempt (`attempt()`, `signIn()`, `refresh()`) starts with Laravel's `Attempting` event. A request's
  bearer token is an authentication, not a sign-in (D5): it fires neither `Attempting`, `Validated`, `Login` nor
  `Failed`, only `Authenticated` and the contextual events, or `AuthenticationFailed` with the reason.
- `Login` and `SignedIn` report real sign-ins only: a sign-in through the session service and a refresh, which also
  fires `Refreshed`; `SignedIn::$refresh` tells them apart.
- The credentials on `Attempting` and `Failed` never carry a password: keys whose name contains `password`
  (case-insensitive) are always removed, plus any fragment in `authentication.events.redacted_credential_keys`. The
  identifier and every other key are kept.
- `Validated` means the identity has already been accepted by credentials or by an upstream mechanism such as a refresh
  token or an external identity provider. It does not guarantee that principal or device resolution will succeed
  afterwards.
- `Login` is fired before `Authenticated` to mirror Laravel's first-party guard ordering.
- A bind sets the identity, principal and device before it dispatches anything after `Login`: `Authenticated`,
  `PrincipalAssigned` and `DeviceAuthenticated` all describe the whole bound context (see `event-model.md`).
- `DeviceAuthenticated` is emitted only when a non-null device is bound.
- Rebinding clears any previously cached identity, principal, and device state before the new lifecycle begins.
- A guard follows later container rebinds of the `events` dispatcher (and, without a guard-local override, of the
  `PrincipalResolver`), and passes each rebind on to its refresh exchange, so an `Event::fake()` made after the guard
  resolved receives the exchange's `DeviceRevoked` as well as the guard's own events.
- Request-local memoization is always on: `user()` resolves a request at most once, whether it succeeds or fails, so a
  rejected token fires its `AuthenticationFailed` once. `setRequest()` starts over, an explicit `login()`, `attempt()`,
  or `setUser()` still binds after a failed resolution, and after `logout()` the guard stays signed out for the rest of
  the request. A successful `login()` or `attempt()` (and so `refresh()`) settles the request before it fires `Login`,
  so a listener that reads the guard mid-bind never resolves the request's own token and leaves its device bound to
  the identity signing in. Nothing is persisted: there is no cross-request cache, and every bearer and refresh request
  reads the identity, principal, tenant, and device live, from the write connection.
- `id()`, `identity()`, `principal()`, `device()`, `tenant()`, and `type()` go through `user()`, so the first access on
  a request authenticates it even on a route without `auth` middleware, as Laravel's own guards do. `setPrincipal()` and
  `setDevice()` resolve the request first too, so a principal or device set before the first access replaces the one the
  request's token binds instead of being replaced by it. They are trusted binds, like `login()`: they check neither
  ownership nor activity, nor a device's revocation or session deadlines, so a caller verifies what it passes them
  first.

## Success Path

- `attempt()` emits `Attempting -> Validated -> Login -> Authenticated -> PrincipalAssigned -> DeviceAuthenticated?`.
  It starts no session, so it never dispatches `SignedIn`, which reports the sessions the session service starts;
  Laravel's `Login` reports an `attempt()` sign-in.
- The session service's `signIn()` emits `Attempting`, then binds through `login()` (`Validated -> Login ->
  Authenticated -> PrincipalAssigned -> DeviceAuthenticated`) once the session's transaction is done, and dispatches
  `DeviceCreated` (new devices only) and `SignedIn` when the device's connection commits; `start()` does the same
  without `Attempting` (see `session-service.md`). A sign-in held for a further factor binds nothing: it emits
  `Attempting` (from `signIn()`) and then `AdditionalFactorRequired` once the pending sign-in commits. `complete()`
  binds and emits the `signIn()` sequence without `Attempting`; `discard()` emits `Failed` and then
  `AuthenticationFailed` (`additional_factor_failed`).
- A sign-in held for a choice of principal binds nothing either: `Attempting` (from `signIn()`) and then
  `PrincipalChoiceRequired` once the choice commits. `choose()` binds and emits the `signIn()` sequence without
  `Attempting` (or holds the chosen principal for a factor); a discarded choice emits `Failed` and then
  `AuthenticationFailed` (`principal_choice_abandoned`).
- `switchPrincipal()` is no sign-in: it binds through `authenticateAs()` (`Authenticated -> PrincipalAssigned ->
  DeviceAuthenticated`, no `Validated` or `Login`) and dispatches `PrincipalSwitched` once the switch commits on the
  device's connection; a refusal emits only `AuthenticationFailed` (flow `principal_switch`), with `DeviceRevoked` first
  for a replayed token.
- Direct `login()` emits the same sequence without `Attempting`. This is the package's public entry point for
  out-of-band authentication such as refresh, OAuth, or SSO callbacks.
- `setUser()` (behind Laravel's `actingAs()`) clears the previous context and emits `Authenticated -> PrincipalAssigned`
  for the identity and its default principal, without `Validated` or `Login`. An identity with no default principal is
  rejected with an `InvalidArgumentException` and the previous context is kept.
- `authenticateAs()` is the trusted bind of an authentication that is not a sign-in: it clears the previous context,
  settles the request, and emits `Authenticated -> PrincipalAssigned -> DeviceAuthenticated?` without `Validated` or
  `Login`.
- Bearer `user()` resolution binds through `bindVerifiedContext()` without a sign-in, so a successful bearer request
  emits only `Authenticated -> PrincipalAssigned -> DeviceAuthenticated?`, carrying the tenant the activity check
  loaded and the method the device's session records (see `BearerAuthentication`).
- Successful `refresh()` emits `Attempting`, then `Validated` and the full bind (`Login -> Authenticated ->
  PrincipalAssigned -> DeviceAuthenticated`), then the package `Refreshed` and `SignedIn` (`refresh` set) events once
  the rotation is committed on the device's connection (at once with no transaction open there). `refreshFromRequest()`
  emits the same once its transport has read the token; a request that carries none emits nothing, and one its
  transport refuses (`refresh_token_conflict`, `cross_site_request`, `token_invalid`) emits `Attempting`, `Failed` and
  `AuthenticationFailed` (flow `refresh`), as any failed refresh does (see `refresh-token-transport.md`).
- A new request (`setRequest()`, which the `request` rebind calls) resets the guard: the bound context, the last
  retrieved identity and whether the request was resolved. A queue worker keeps the application between jobs, so the
  package resets each resolved package guard to the current request when a job starts (`JobProcessing`,
  `AuthManager::forgetGuardState()`), without creating guards or registering rebinding callbacks. A job on the `sync`
  connection (the `sync` driver, or `dispatchSync()` whatever the default) runs inside the request or command that
  dispatched it and is skipped, so a session that request started stays bound and one it signed out stays signed out.
- `logout()` resolves the request if nothing has yet, emits Laravel's `Logout` event only when an identity is bound,
  then clears contextual state. On a JWT guard it signs the session out through the session service (`signOut()`): the
  bound persisted device is revoked first (`signed_out`, `DeviceRevoked` once committed), then `Logout`, then
  `forgetUser()` clears the state with no event and keeps the guard signed out for the rest of the request.

## Failure / Edge Cases

- No bearer token means there is nothing to attempt, so `JwtGuard::user()` returns `null` without firing auth events.
- A rejected bearer token fires only `AuthenticationFailed` (flow `bearer`), once per request, with the first reason in
  this order: `token_invalid`; `identity_unknown`, `identity_inactive`; `principal_mismatch` (the `pid` does not resolve
  to exactly that principal); `principal_inactive`, `tenant_inactive`; and for a token that names a device,
  `device_unknown` (not one of the identity's own, or not a key of the device model), `device_guard_mismatch`,
  `device_revoked`, `session_expired`, `device_principal_mismatch` (the device acts as another principal, or none, or
  switched principal after the token was issued); a token that names no device is checked against the "tokens valid
  after" times instead (`issued_before_cutoff`). Its context carries the identity, principal and device as far as they
  were found, and the `did` the token named.
- A guest on a route that only package guards protect gets a JSON `401` whatever its `Accept` header: the package's
  `Http\Middleware\Authenticate` raises the `AuthenticationException` without evaluating Laravel's guest redirect, and
  `Http\UnauthenticatedResponse` renders it. Any other guard on the route keeps Laravel's response.
- A failed `attempt()` emits `Attempting`, `Failed` and then the package `AuthenticationFailed` (flow `sign_in`) with a
  `FailureReason`, but not `Login` or `Authenticated`. `Failed` carries the account the credentials found (as Laravel's
  guards do), `AuthenticationFailed` only an identity whose password was accepted, plus the principal and tenant once
  resolved, the `password` method and the identifier as given; never a credential. An account whose own limit refused
  the password check is `account_rate_limited` on `AuthenticationFailed`, with the wait, while the caller sees only a
  failure (the session service's result says `invalid_credentials`).
- `attempt()` runs on the password sign-in method and the sign-in policies, resolved from the container when it runs:
  after `Attempting`, the audience policy must allow the `password` method (`method_not_allowed`, nothing counted, no
  timebox) and the attempt limiter must grant a slot for the configured identifier and the request's IP address
  (`rate_limited`, with the wait). Then, inside the credential timebox: the password (`invalid_credentials`),
  `Validated`, the identity, the principal and its tenant (activity and pins), the audience policy's admission, the
  pinned device (`device_mismatch`), the password rehash (`PasswordSignIn::rehash()`, honouring
  `hashing.rehash_on_login`; no other path writes a password), and the additional-factor policy, which `attempt()` can
  only refuse (`additional_factor_required`) and is never told of a pinned device. Only a success gives its slot back.
  `validate()` checks the credentials only, and still fires `Validated` when it accepts them.
- A principal or device pinned on `attempt()` is verified, not trusted: the principal goes through the resolver's hinted
  path and must come back as the same class with the same identifier (the bearer `pid` exact-match check) and be owned
  by the authenticated identity (its `getIdentity()` is that identity), and the device must be found among the
  identity's own `HasDevices` devices, of the same class, of this guard (a device of another guard, or of none, counts
  as missing), not revoked, with a session that has not ended, and acting as the principal being bound. The owner
  is read from the principal's stored key, ignoring an identity relation the resolver set and even when lazy loading is
  prevented, and an owner that cannot be read fails the check. The resolved instances are bound; a failed check fails
  the attempt. `login()`, `setPrincipal()`, and `setDevice()` stay trusted binds.
- A successful credential check can still end in `Failed` if principal resolution later returns `null` or resolves a
  principal that is inactive or acts within an inactive tenant. That is why `Validated` is not the same thing as
  "fully bound".
- An `UnresolvableIdentityException` (an identity model that is neither a `Principal` nor `HasPrincipals`) is a
  misconfiguration, not a failed authentication. It propagates as a server error from `attempt()`, bearer resolution,
  and `refresh()`, with no `Failed` or `AuthenticationFailed` event.
- Activation is opt-in through `CanBeActive` on the identity, the principal, or the tenant, and is decided by
  `ActivationPolicy` on the credential, bearer, and refresh paths alike. A model without the capability is active. The
  tenant is read from the write connection, also when it lives on another connection than the principal. A principal
  whose tenant key names a tenant that opts in (`CanBeActive`) but cannot be loaded (deleted, soft-deleted, or scoped
  out) fails like one in an inactive tenant: `getTenant()` throws `TenantUnavailableException` rather than reporting no
  tenant or a `withDefault()` placeholder for the missing row, and a principal loaded without that tenant's key, or
  without the type column of a polymorphic tenant relation, throws a `LogicException`; a polymorphic tenant whose key is
  set but whose type is empty cannot be loaded either. A tenant that does not opt in is never checked, and a relation to
  a model that is not a `Tenant` reports no tenant.
- Failed refresh emits Laravel's standard `Attempting` and `Failed` events and then the package `AuthenticationFailed`
  (flow `refresh`) with a machine-readable reason; the exchange returns that event and the guard dispatches it. A
  refresh that revokes the device because its token was replayed (`rotation_reuse`) also emits `DeviceRevoked`. It is
  dispatched only by the call that revoked the device, never for one already revoked, and only once the revocation is
  committed on the device's own connection, so a rolled-back revocation is never reported. When that connection has no
  open transaction the revocation is committed at once, and the order is `DeviceRevoked`, `Failed`,
  `AuthenticationFailed`, even if a transaction is open on another connection, whose rollback does not withdraw it.
  Inside a transaction on the device's connection, `Failed` and `AuthenticationFailed` come first and `DeviceRevoked`
  follows when that transaction commits. The transaction Laravel's testing traits wrap around each test is not counted,
  as it never commits. `DeviceRevoked` reports only the revocations the package makes (replay detection, sign-out, and
  the session service's revocations, see `device-lifecycle.md`): a device an application revokes by writing
  `revoked_at` itself fires no event.
- A rate-limited refresh emits `Attempting`, `Failed` and `AuthenticationFailed` (`rate_limited`, with `retryAfter`),
  and then throws `ThrottleRequestsException` (a 429 with `Retry-After`) instead of returning `null`.
- Verifying an identifier (`IdentifierVerifier::verify()`, behind `VerificationLinks::consume()`) never binds a guard
  or starts a session. Only the call whose locked update marked the identifier verified dispatches
  `IdentifierVerified`, once that update is committed on the identity's connection (at once for an identity that is
  not an Eloquent model); a repeat or a mismatch dispatches nothing.
- A grace retry (the previous rotation id, inside the grace window) is a successful refresh: it emits the same events
  as one that rotates, `Refreshed` included.
- `DeviceAuthenticated` is coupled to the shipped `RecordDeviceUsage` listener, which records the time, IP address, and
  user agent of the use, at most once per `authentication.device.last_used_throttle_seconds`. Only persisted
  `EloquentDevice` instances participate in that write path. It records the client the event carries, the request
  being served when the device was bound, so a long-running worker records the request it is serving, and the client
  values are cleaned by `ClientContext` before they are stored.

## Implementation Anchors

- `src/Guards/Concerns/ValidatesGuardCredentials.php`: `fireAttemptingEvent()`, `fireValidatedEvent()`,
  `fireFailedEvent()`, `redactCredentials()`.
- `src/Guards/AbstractGuard.php`: `user()`, `resolveUserFromRequest()`, `attempt()`, `validate()`, `login()`,
  `authenticateAs()`, `logout()`, `forgetUser()`, `bindAuthenticationLifecycle()`, `bindVerifiedContext()`;
  `src/Guards/Concerns/RebindsCollaborators.php`: `setRequest()`; `src/Guards/Concerns/SignsInWithCredentials.php`:
  `signInWithCredentials()`, `admitVerifiedIdentity()`.
- `src/Sessions/Methods/PasswordSignIn.php` and `src/Sessions/Admission/SignInAdmission.php`: the credential check and
  the activity, principal, tenant and audience checks every sign-in shares.
- `src/Guards/ActivationPolicy.php`: the opt-in identity, principal, and tenant activation checks.
- `src/Guards/Concerns/BindsContextualState.php`: the resolving accessors, `setPrincipal()`, `setDevice()`,
  `bindContext()`, `clearContextualState()`.
- `src/Guards/Concerns/VerifiesPinnedContext.php`: the ownership checks for principals and devices pinned on
  `attempt()`.
- `src/Guards/JwtGuard.php`: `resolveUserFromRequest()`, `resolveBearerToken()`, `refresh()`, `refreshFromRequest()`.
- `src/AuthManager.php`: `forgetGuardState()`; `src/Listeners/ForgetGuardStateBeforeJob.php`.
- `src/Guards/BearerAuthentication.php` and `src/Guards/OwnedDevice.php`: the bearer checks, their order and reasons,
  and the device checks they share with the `attempt()` device pin; `src/Sessions/IdentityDevices.php`: the device
  lookup both use.
- `src/AuthenticationServiceProvider.php`: listener registration for `DeviceAuthenticated`, `wireGuardRebinds()`, the
  `auth` middleware binding, and the guest response render callback.
- `src/Guards/JwtGuard.php` and `src/Jwt/RefreshTokenExchange.php`: `setDispatcher()` and `setPrincipalResolver()`,
  which keep the exchange on the guard's dispatcher and resolver.
- `src/Http/Middleware/Authenticate.php`, `src/Http/UnauthenticatedResponse.php`: the package guards' `401`.
- `src/Listeners/RecordDeviceUsage.php` and `src/Http/ClientContext.php`: the last-use write for bound devices.
- `src/Jwt/RefreshTokenExchange.php`: `revokeDevice()` and the `DeviceRevoked` dispatch, deferred to the device
  connection's commit by `Database\AfterCommit::run()`; `src/Events/DeviceRevoked.php`.

## Authoritative Tests

- `tests/Feature/Guards/AbstractGuardAttemptTest.php`
  `testAttemptDispatchesAttemptingEventBeforeValidation`
- `tests/Feature/Guards/AbstractGuardAttemptTest.php`
  `testAttemptDispatchesValidatedAfterSuccessfulHasherCheck`
- `tests/Feature/Guards/AbstractGuardTest.php`
  `testASuccessfulAttemptRunsEveryCheckInOrderAndGivesItsSlotBack`,
  `testAMethodTheGuardDoesNotAllowIsRefusedBeforeAnythingIsCounted`, `testARequiredFactorFailsTheAttempt`
- `tests/Feature/Guards/AbstractGuardLifecycleTest.php`
  `testLoginFiresValidatedEventBeforeBindingState`
- `tests/Feature/Guards/JwtGuardTest.php`
  `testARateLimitedRefreshFiresFailedAndThrowsA429`
- `tests/Integration/Sessions/PendingFactorSessionServiceTest.php`
  `testASignInHeldForAFactorReportsIt`, `testAFactorRequestIsReportedOnlyOnceItsPendingSignInCommits`,
  `testADiscardedPendingSignInCannotBeCompleted`
- `tests/Feature/Guards/JwtGuardUserResolutionTest.php`
  `testUserBindsIdentityPrincipalAndDeviceFromValidToken`
- `tests/Feature/Guards/JwtGuardRefreshResolutionTest.php`
  `testRefreshDispatchesSuccessfulLifecycleEventsBeforeRefreshed`
- `tests/Feature/Guards/AbstractGuardLifecycleTest.php`
  `testSetRequestClearsBoundContextualState`
- `tests/Integration/Process/RequestSequenceTest.php`
- `tests/Integration/Process/QueueWorkerGuardStateTest.php`
  `testWithoutTheResetOneJobsIdentityLeaksIntoTheNext`, `testEachJobStartsSignedOut`
- `tests/Integration/Process/ForgetGuardStateBeforeJobTest.php`
  `testASessionJustStartedOutlastsADispatchSyncJob`, `testASignedOutRequestStaysSignedOutAfterADispatchSyncJob`,
  `testTheSyncDefaultConnectionLeavesTheRequestsSessionBound`
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
- `tests/Integration/Guards/TenantActivityIntegrationTest.php`
  `testTenantCheckReportsAMorphMembershipLoadedWithoutItsTenantType`,
  `testTenantCheckRejectsAMorphMembershipWhoseTenantTypeIsEmpty`,
  `testTenantCheckRejectsAWithDefaultMembershipOfASoftDeletedTenant`
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
- `tests/Integration/Guards/PinnedContextOwnershipIntegrationTest.php`
  `testOwnMembershipHydratedWithLazyLoadingPreventedIsBound`
- `tests/Feature/Guards/VerifiesPinnedContextTest.php`
  `testPinnedPrincipalWithoutAnOwnerRelationFailsTheAttempt`,
  `testPinnedPrincipalWithoutAnOwnerRelationFailsTheAttemptUnderStrictMode`
- `tests/Feature/AuthenticationServiceProviderTest.php`
  `testJwtGuardRefreshExchangeTracksLaterEventDispatcherRebind`
- `tests/Integration/Guards/RefreshReplayIntegrationTest.php`
  `testReplayRevokesTheDeviceAndEndsItsAccessTokens`, `testRevocationIsReportedOnlyAfterCommit`
- `tests/Integration/Guards/SeparateDeviceConnectionIntegrationTest.php`
  `testReplayIsReportedAtOnceWhateverAnotherConnectionsTransactionDoes`,
  `testReplayInsideTheDeviceConnectionsTransactionIsReportedOnItsCommit`,
  `testReplayRolledBackWithANestedTransactionIsNeverReported`
- `tests/Integration/Guards/ReplayUnderDatabaseTransactionsIntegrationTest.php`
  `testReplayOutsideTheApplicationsTransactionsIsReportedAtOnce`
- `tests/Integration/Guards/DeviceUsageIntegrationTest.php`
  `testEachRequestRecordsItsOwnClientOutsideTheThrottleWindow`, `testRefreshRecordsTheClientItCameFrom`,
  `testCraftedUserAgentIsStoredCleaned`
- `tests/Integration/Verification/IdentifierVerifierTest.php`
  `testProvingTheCurrentIdentifierVerifiesIt`, `testVerifyingAgainReportsAlreadyVerified`,
  `testEventWaitsForTheCommitAndNeverReportsARollback`
- `tests/Integration/Guards/BearerAuthenticationTest.php`
  `testABearerRequestReportsOnlyTheAuthentication`, `testATokenTheRowsRejectIsReportedOnceWithItsReason`,
  `testARequestWithoutATokenDispatchesNothing`
- `tests/Feature/Guards/AbstractGuardEventContextTest.php`
  `testAuthenticateAsReportsTheBindButNoSignIn`, `testAListenerOnAuthenticatedSeesTheWholeContext`

## Change Triggers

Update this note when any of the following change:

- the order or presence of `Attempting`, `Validated`, `Login`, `Authenticated`, `Failed`, `Logout`, `PrincipalAssigned`,
  `DeviceAuthenticated`, `Refreshed`, `AuthenticationFailed`, `AdditionalFactorRequired`, `PrincipalChoiceRequired`,
  `PrincipalSwitched`, `DeviceRevoked`, or `IdentifierVerified`
- the order of the sign-in policy checks in `attempt()`
- which credential keys are redacted from `Attempting` and `Failed`
- the response a guest gets on a route protected by package guards
- the decision that a bearer request binds without a sign-in and refresh as one
- what `setUser()` binds
- the listener or persistence behavior attached to `DeviceAuthenticated`
- how dispatcher and resolver rebinds reach the guard and its refresh exchange
- the rule that prior contextual state is cleared before rebinding
- the rule that bearer and refresh resolution read live state from the write connection with no cross-request cache
