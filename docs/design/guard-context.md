# Guard Context

## Purpose

This note describes the one execution context each guard runs its flows on: the guard's name, identity provider,
principal resolver and event dispatcher, the request it serves, and its credential timebox. It covers why the context is
shared and mutable, how it is rebound, and what a flow may keep from it.

## Invariants

- A guard built on `AbstractGuard` builds one `Runtime\GuardContext` in its constructor, from the six collaborators the
  constructor takes, and keeps it for its life (`protected readonly GuardContext $context`, and `context()` through
  `Contracts\HasGuardContext`). The constructor's signature is the one it always had, so a guard type an application
  writes still constructs.
- There is one copy of each collaborator. The guard's getters (`getName()`, `getProvider()`, `getPrincipalResolver()`,
  `getDispatcher()`, `getRequest()`) read the context, and its setters (`setRequest()`, `setDispatcher()`,
  `setPrincipalResolver()`) rebind it. A JWT guard builds its refresh exchange on its own context, through a factory it
  calls with it once, and the session revocations its `logout()` signs out through (`Sessions\SessionRevocations`)
  through another it calls with it on each sign-out, so both read the provider, the resolver and the dispatcher the
  guard reads; neither keeps a copy of them, and neither has setters.
- What a session flow may do to its guard's bound state is the internal port `Contracts\GuardBinding` (`user()`,
  `principal()`, `device()`, `tenant()`, `login()`, `authenticateAs()`, `forgetUser()`), which `AbstractGuard`
  implements. Its four readers resolve the request's credential on first access, as the guard's accessors do, so a
  sign-out given the guard reads the session the request carries. The session revocations take the binding per call,
  only for `signOut()` and `signOutEverywhere()`, and otherwise need nothing of the guard but its context.
- The code, passkey, API key, client credentials, password and identifier change services (`Codes\CodeService`,
  `Passkeys\PasskeyService`, `ApiKeys\ApiKeyService`, `ClientCredentials\ClientCredentialsExchange`,
  `Passwords\PasswordService`, `IdentifierChanges\IdentifierChangeService`) take the guard's context, not the guard, and
  so do the classes they build (`ResetRequests`, `ResetSubmissions`, `ChangeRequests`, `ChangeConfirmation`, and
  `Sessions\RecentAuthentication`, the reauthentication check), and `Sessions\PrincipalSwitch`, which the session
  service builds per switch. `ResetRecipient`'s static checks take the guard's name and provider. `AuthManager` resolves
  the guard, refuses one the service does not belong to with the message it always gave, and passes the guard's
  `context()`; for the password service it also passes the session revocations a change or a reset ends sessions
  through, built on that context (`SessionRevocations::forContext()`, on the container's connections and transactions
  manager). The queued `Codes\SendOneTimeCode` and `Passwords\SendPasswordReset` carry only the guard's name: when one
  runs it resolves the guard, accepts it only when `auth.guards` configures it with the `jwt` driver
  (`Config\JwtGuards::names()`), and takes its context through `HasGuardContext`, failing with a `LogicException` when
  the application replaced the `jwt` driver with a guard that has none (`Runtime\JwtGuardContexts::named()`, which both
  call). None of the six services' namespaces names a `Guards` class, and in `Sessions` only `SessionService` does.
- Only the owning guard rebinds a context: `rebindRequest()`, `rebindEvents()` and `rebindResolver()` are internal, and
  the architecture test fails a call of any of them outside `Guards`. The container's rebinds (`wireGuardRebinds()`:
  `request`, `events`, and the global `PrincipalResolver` unless the guard has a resolver of its own), `Event::fake()`,
  Octane's request rebind and `AuthManager::forgetGuardState()` all reach the context through the guard's setters.
- The package registers the container's rebinds only on the guards its own drivers build. A guard type's driver
  registers the same `refresh()` calls itself (`docs/guides/extending.md`); without them its context keeps the
  dispatcher and resolver it was built with for its life, and the request until `forgetGuardState()`, which gives every
  resolved `AbstractGuard` the current request.
- `setRequest()` rebinds the context and keeps all of its reset: the bound context, the last retrieved identity and
  whether the request was resolved.
- A flow reads a collaborator from the context each time it uses one and keeps no copy, so a flow built before a rebind
  (the guard's session service, its refresh exchange, a service the manager handed out) follows the rebind. An operation
  captures what it reports when it starts: the client of the request (`client()`) and its events' payload. Every event
  deferred to a commit is dispatched by the callback the commit runs, through the context's `dispatch()`, so it reaches
  the dispatcher as it is then, and a dispatcher swapped in between the write and the commit receives it: the guard's
  own deferred events, the refresh exchange's `DeviceRevoked`, the session revocations' `DeviceRevoked` and
  `SignedOutEverywhere`, and the events of the passkey, API key, password and identifier change services alike. No flow
  takes the dispatcher when it schedules an event. `Passkeys\PasskeySignIn`, a sign-in method the container builds
  rather than a flow of the guard, reads the container's dispatcher the same way, when the commit runs its
  `PasskeyUsed`.
- The credential timebox, `Runtime\CredentialTimebox`, is one per guard and wraps the guard's `Timebox`: `attempt()`,
  `validate()`, the session service's sign-ins, a password reset and a password reauthentication all run in it. Before
  every call it tells the box that it may not return early, so a check that fails after one that succeeded on the same
  guard waits out the budget again. The budget is read on each call from
  `authentication.timebox.credentials_microseconds`, and is `400000` for a value that is missing, not positive or not
  readable.
- Two guards never share a context: each guard's context, timebox and refresh exchange are its own, and its exchange is
  built with the same guard's token service.
- The context does not hold the guard's configuration block: each per-guard setting reads `auth.guards.<name>` by the
  guard's name, with its own validation and lifetime, and a cached block would be a second, stale source. Nor does it
  hold the container: flows that resolve a policy late keep taking the container, so a binding made later still applies.
- `Runtime` names nothing of `Guards`, `Sessions` or `Jwt`.

## Success Path

- A guard resolves with the request then being served in its context. The next request's `request` rebind calls
  `setRequest()`, which resets the guard and rebinds the context, and every flow of the guard then reads the new
  request.
- `Event::fake()` after a guard resolved rebinds `events`: the guard's own events, the session service's, the refresh
  exchange's `DeviceRevoked`, and the events of the code, passkey, API key, client credentials, password and identifier
  change services all go to the fake, those a write deferred before the fake to a commit after it included.
- A guard type an application writes reads its collaborators through `$this->context` (`name()`, `provider()`,
  `resolver()`, `events()`, `request()`, `client()`), dispatches through `$this->context->dispatch()`, and checks a
  secret inside `$this->context->timebox()->run()`.

## Failure / Edge Cases

- A guard with a resolver of its own (`principal_resolver`) is not wired to the global rebind, so its context keeps that
  resolver for its life, on refresh as on bearer requests.
- A deferred event scheduled before a request rebind carries the client its operation started from, not the new
  request's.
- A dispatcher swapped in after a write and before its commit (`Event::fake()` inside the caller's transaction, a rebind
  of `events`) receives every event the write deferred, a password set and the revocations of its change or reset alike,
  and the dispatcher bound at the write receives none. A write rolled back reports to neither.
- A flow that copied a collaborator out of the context would freeze it at that moment; none does, and the rebind tests
  hold every long-lived holder to reading per use.
- A subclass that read the protected properties a guard had before the context (`$this->name`, `$this->provider`,
  `$this->resolver`, `$this->events`, `$this->request`, `$this->timebox`) reads `$this->context` instead.

## Implementation Anchors

- `src/Runtime/GuardContext.php`, `src/Runtime/CredentialTimebox.php`, `src/Contracts/HasGuardContext.php`,
  `src/Contracts/GuardBinding.php`.
- `src/Guards/AbstractGuard.php`: the constructor, `context()`; `src/Guards/Concerns/ExposesCollaborators.php` and
  `src/Guards/Concerns/RebindsCollaborators.php`: the getters and setters.
- `src/Guards/JwtGuard.php`: the constructor (the exchange and revocations factories), `sessions()`, `logout()`;
  `src/Jwt/RefreshTokenExchange.php`: the constructor; `src/Sessions/SessionRevocations.php`;
  `src/Passwords/PasswordWriter.php`: `write()`.
- `src/AuthenticationServiceProvider.php`: `createJwtGuard()`, `wireGuardRebinds()`.
- `src/AuthManager.php`: `codes()`, `passkeys()`, `apiKeys()`, `clientCredentials()`, `passwords()`,
  `identifierChanges()`; the constructors of `src/Codes/CodeService.php`, `src/Passkeys/PasskeyService.php`,
  `src/ApiKeys/ApiKeyService.php`, `src/ClientCredentials/ClientCredentialsExchange.php`,
  `src/Passwords/PasswordService.php`, `src/Passwords/ResetRequests.php`, `src/Passwords/ResetSubmissions.php`,
  `src/IdentifierChanges/IdentifierChangeService.php`, `src/IdentifierChanges/ChangeRequests.php`,
  `src/IdentifierChanges/ChangeConfirmation.php`, `src/Sessions/RecentAuthentication.php` and
  `src/Sessions/PrincipalSwitch.php`; `src/Passwords/ResetRecipient.php`: `find()`, `eligible()`.
- `src/Runtime/JwtGuardContexts.php`: `named()`, called by `src/Codes/SendOneTimeCode.php` and
  `src/Passwords/SendPasswordReset.php`.
- The deferred reports: `src/ApiKeys/ApiKeyService.php` `report()`, `src/Passkeys/PasskeyService.php`
  `dispatchOnceCommitted()`, `src/Passkeys/PasskeyAssertions.php` `used()`, `src/IdentifierChanges/ChangeRequests.php`
  `deliver()`, `src/IdentifierChanges/ChangeConfirmation.php` `report()`.

## Authoritative Tests

- `tests/Feature/Runtime/GuardContextTest.php`
- `tests/Unit/Runtime/CredentialTimeboxTest.php`, `tests/Feature/Runtime/CredentialTimeboxTest.php`,
  `tests/Feature/Runtime/SharedCredentialTimeboxTest.php`
- `tests/Feature/Guards/ExposesCollaboratorsTest.php`, `tests/Feature/Guards/RebindsCollaboratorsTest.php`
- `tests/Feature/AuthenticationServiceProviderTest.php` `testJwtGuardWithoutOverrideTracksLaterGlobalResolverRebind`,
  `testJwtGuardWithOverrideIsNotClobberedByLaterGlobalResolverRebind`,
  `testJwtGuardRefreshExchangeTracksLaterEventDispatcherRebind`
- `tests/Feature/Jwt/RefreshTokenExchangeTest.php` `testARebindOfTheContextsDispatcherRoutesLaterRevocationsToIt`
- `tests/Integration/Contracts/EventSequenceTest.php` `testARequestReboundBeforeTheCommit`,
  `testADispatcherSwappedBeforeTheCommitReceivesTheEvents`
- `tests/Feature/Sessions/SessionRevocationsTest.php` `testADeferredReportReachesTheDispatcherAsItIsAtTheCommit`,
  `testTheGuardsLogoutNeedsNoSessionService`
- `tests/Feature/Runtime/GuardContextTest.php` `testAFakeSwappedInBeforeTheCommitReceivesEveryDeferredEvent`
- `tests/Integration/Passwords/PasswordWriterTest.php`
  `testThePasswordSetAndTheRevocationsReachTheDispatcherBoundAtTheCommit`,
  `tests/Feature/Passwords/ResetSubmissionsTest.php` `testAResetsEventsReachTheDispatcherBoundAtTheCommit`
- `tests/Feature/IdentifierChanges/IdentifierChangeConfirmationTest.php`
  `testEveryReportReachesTheDispatcherBoundAtTheCommit`
- `tests/Feature/Passkeys/PasskeyServiceTest.php` `testEveryEventReachesTheDispatcherBoundAtTheCommit`,
  `tests/Feature/Passkeys/PasskeySignInTest.php` `testAUseReachesTheDispatcherBoundAtTheCommit`,
  `tests/Integration/ApiKeys/ApiKeyServiceTest.php` `testEveryReportReachesTheDispatcherBoundAtTheCommit`
- `tests/Feature/ClientCredentials/ClientCredentialsExchangeTest.php` `testAnExchangeFollowsTheGuardsRebinds`
- `tests/Integration/Codes/SendOneTimeCodeTest.php` `testASignInJobForAnotherDriversGuardThrows`,
  `testASignInJobForAJwtDriverReplacedByAnotherGuardThrows`,
  `testASignInJobForAJwtDriverReplacedByAnotherPackageGuardSendsThroughItsProvider`,
  `testASignInJobNamingAnotherDriversJwtGuardThrows`,
  `testACodeSentThroughAnotherDriversJwtGuardIsDeliveredThroughTheJwtGuard`
- `tests/Feature/Runtime/JwtGuardContextsTest.php`; `tests/Feature/Passwords/SendPasswordResetTest.php`
  `testAJobNamingAnotherDriversJwtGuardThrows`, `testAJobForAJwtDriverReplacedByAnotherGuardThrows`,
  `testAJobForAJwtDriverReplacedByAnotherPackageGuardSendsThroughItsProvider`;
  `tests/Integration/Passwords/QueuedPasswordResetTest.php`
  `testAResetRequestedThroughAnotherDriversJwtGuardIsDeliveredThroughTheJwtGuard`
- `tests/Integration/Octane/JwtGuardRequestsTest.php`, `tests/Integration/Process/QueueWorkerGuardStateTest.php`,
  `tests/Integration/Process/ForgetGuardStateBeforeJobTest.php`
- `tests/Unit/Architecture/NamespaceDependenciesTest.php` `testOnlyTheGuardsRebindAGuardContext`

## Change Triggers

- A collaborator added to the context or taken out of it, or a flow that needs one the context does not hold.
- A flow that keeps something it read from the context, or reads the request when it reports rather than when it starts.
- A new way a guard's collaborator is swapped (a container rebind, a worker reset).
- Any change to the timebox's reset, its budget, or the flows that run in it.
