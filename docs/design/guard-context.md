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
  calls with it, so the exchange reads the provider, the resolver and the dispatcher the guard reads; the exchange keeps
  no copy of them and has no setters.
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
  captures what it reports when it starts: the client of the request (`client()`) and its events' payload. A callback
  deferred to a commit that dispatches through the context (`dispatch()`) reaches the dispatcher as it is when the
  callback runs, so a dispatcher swapped in between still receives the event: the guard's own deferred events and the
  refresh exchange's `DeviceRevoked` do.
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
  exchange's `DeviceRevoked`, and the events of the code, passkey and password services all go to the fake.
- A guard type an application writes reads its collaborators through `$this->context` (`name()`, `provider()`,
  `resolver()`, `events()`, `request()`, `client()`), dispatches through `$this->context->dispatch()`, and checks a
  secret inside `$this->context->timebox()->run()`.

## Failure / Edge Cases

- A guard with a resolver of its own (`principal_resolver`) is not wired to the global rebind, so its context keeps that
  resolver for its life, on refresh as on bearer requests.
- A deferred event scheduled before a request rebind carries the client its operation started from, not the new
  request's.
- The services that still take the guard and read its dispatcher themselves take it when they schedule a deferred event
  (a password set, a passkey's use, addition or removal, an API key's issue, rotation or revocation, an identifier
  change), so a dispatcher swapped between the scheduling and the commit does not receive that event.
- A flow that copied a collaborator out of the context would freeze it at that moment; none does, and the rebind tests
  hold every long-lived holder to reading per use.
- A subclass that read the protected properties a guard had before the context (`$this->name`, `$this->provider`,
  `$this->resolver`, `$this->events`, `$this->request`, `$this->timebox`) reads `$this->context` instead.

## Implementation Anchors

- `src/Runtime/GuardContext.php`, `src/Runtime/CredentialTimebox.php`, `src/Contracts/HasGuardContext.php`.
- `src/Guards/AbstractGuard.php`: the constructor, `context()`; `src/Guards/Concerns/ExposesCollaborators.php` and
  `src/Guards/Concerns/RebindsCollaborators.php`: the getters and setters.
- `src/Guards/JwtGuard.php`: the constructor (the exchange factory), `sessions()`, `timeboxed()`;
  `src/Jwt/RefreshTokenExchange.php`: the constructor.
- `src/AuthenticationServiceProvider.php`: `createJwtGuard()`, `wireGuardRebinds()`.

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
- `tests/Integration/Octane/JwtGuardRequestsTest.php`, `tests/Integration/Process/QueueWorkerGuardStateTest.php`,
  `tests/Integration/Process/ForgetGuardStateBeforeJobTest.php`
- `tests/Unit/Architecture/NamespaceDependenciesTest.php` `testOnlyTheGuardsRebindAGuardContext`

## Change Triggers

- A collaborator added to the context or taken out of it, or a flow that needs one the context does not hold.
- A flow that keeps something it read from the context, or reads the request when it reports rather than when it starts.
- A new way a guard's collaborator is swapped (a container rebind, a worker reset).
- Any change to the timebox's reset, its budget, or the flows that run in it.
