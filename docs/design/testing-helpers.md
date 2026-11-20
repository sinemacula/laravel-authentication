# Testing Helpers

## Purpose

This note describes how an application's tests act as an identity, a principal or a session on a package guard, how
that context survives the requests a test sends through the HTTP kernel, how it ends, what the bound-context assertions
compare, and the fakes the package ships for its delivery contracts.

## Invariants

- The helpers use only the guard's public, trusted `authenticateAs()`, `forgetUser()`, its collaborator accessors,
  `setDispatcher()` and the `@internal` `bindOnFirstRead()`; `setRequest()`, `forgetGuardState()`, the service provider
  and the guards' own rebinding callbacks behave exactly as without the helpers. `authenticateAs()` takes the scopes for
  a machine identity (`?array $scopes`, which binds `[]`, none, when it is `null`) and refuses scopes for a human one
  with an `InvalidArgumentException` before anything is bound (`BindsContextualState::assertScopable()`), so a test can
  act as a machine whose credential granted them. It takes the active tenant too (`?Tenant $tenant`); without one, the
  tenant is the one the session records, or the principal's own without a session.
- A guard acted on is bound again on the first read of each request, as a bearer request is resolved. On every
  `request` rebinding, after the guard's own `setRequest()` reset, the helpers hand the guard a `bindOnFirstRead()`
  callback: the guard registers its reset callback when it is created, and the helpers register theirs once per guard
  instance afterwards. The guard's first `user()` on the request runs the callback, which binds the context instead of
  resolving the request's credential, or reports that the guard is no longer acted on so the credential is resolved.
  Any reset (`setRequest()`, `forgetUser()`, a bind) discards a callback not yet run; `logout()` reads the guard first,
  so it runs the callback before signing out.
- A request that never reads the guard fires no bind events and records no use of the session. A read in the test body
  after such a request is that request's first read and binds it then.
- The kernel binds each request twice, with the same object: before the global middleware and again before routing it.
  When a global middleware reads the guard, the context is bound on that read with its events, and the router's read
  binds it again with the guard's dispatcher swapped for a `NullDispatcher`, restored even when the bind throws. A
  request therefore fires `Authenticated`, `PrincipalAssigned` and, with a session, `SessionAuthenticated` once, and
  records the session's use once, whether or not a global middleware read the guard. When a listener signed the guard
  out on the first bind, the router's read binds it again with its events, so the listener signs it out again.
- Each guard has at most one acting context, keyed by its name and tied to the guard instance acted on. Acting again on
  the guard replaces it, and the tenant `actingInTenant()` named with it; acting on another guard leaves it alone.
  `actingInTenant()` keeps the context acted as and changes only its active tenant.
- The context is bound as given: no ownership, activity, revocation or session-deadline check. A machine identity
  bound this way is limited to the scopes the test names, as if its credential granted them, and to none (`[]`) when it
  names none; scopes named for a human identity are refused, and nothing is kept.
- Acting makes the guard the default (`shouldUse()`), as Laravel's `actingAs()` does, and a model created for the test
  is no longer reported as just created, so a route returning it answers `200`, as with `be()`.
- A queued job a worker runs starts signed out (`ForgetGuardStateBeforeJob` calls `forgetGuardState()`, which calls each
  package guard's `setRequest()` directly, not through a rebinding, discarding a callback the last request did not run);
  the next request the test sends is acted as again.
- The assertions read the guard through its public accessors, so the first one on a request resolves it as application
  code would. Identity, principal, tenant and session match when both are absent, when they are the same instance, or
  when they are of the same class with identifiers that are equal as strings. Scopes compare exactly and in order.
- Laravel's `actingAs()` is unchanged: it binds through `setUser()` for code running in the test, and a request through
  the kernel starts over.
- Each fake implements one contract the package delivers or checks through (`OneTimeCodeSender`,
  `PasswordResetLinkSender`, `IdentifierChangeNotifier`, `BreachedPasswordChecker`), binds a fresh instance of itself in
  place of it with `fake()`, keeps what it receives instead of delivering it, and reads it back (`sent()` and
  `hasSent()`, or `checked()` and `hasChecked()` for the checker, each with an optional filter, `count()`, `forget()`,
  and a reader for the common question: `lastCodeFor()`, `lastTokenFor()`, `noticesFor()`). A delivery fake receives
  what the queued job delivers, so it holds nothing until the job runs.

## Success Path

1. `actingAsIdentity()`, `actingAsPrincipal()` or `actingOnSession()` resolves the package guard named (or the default),
   works out the identity, principal and session (and, for a machine, the scopes the test names), and hands them to the
   container's `Testing\ActingContext`.
2. The context binds them at once through `authenticateAs()` (which refuses scopes for a human, so nothing is kept),
   then stores them for the guard and registers its `request` rebinding callback for that guard instance once.
3. Each request the test sends rebinds `request`: the guard resets, then the helpers' callback hands it a first-read
   bind. The request's first read of the guard binds the context again, firing `Authenticated`, `PrincipalAssigned` and,
   with a session, `SessionAuthenticated`; a read after the kernel binds the same request again before routing it binds
   it without them.
4. `actingOnSession()` reads the session's owner key and principal columns without a query, loads the owner through the
   guard's provider and checks it is the exact owner (`SessionOwnership::isOwner()`), and resolves the recorded
   principal through the guard's resolver with the recorded identifier as the hint, checking it is the one recorded
   (`PrincipalReference::isRecordedOn()`); a session recording no principal acts as the owner's default one. The guard
   is the one the session records unless the test names it.
5. `actingInTenant()` acts again with the context already acted as on the guard, now in the tenant named, which every
   later request binds as the active tenant whether or not it is active.

## Failure / Edge Cases

- A guard of another driver (Laravel's `session`) is refused with an `InvalidArgumentException` naming it.
- `actingAsIdentity()` without a principal, for an identity with no default one, throws an `InvalidArgumentException`,
  as `setUser()` does.
- `actingOnSession()` throws an `InvalidArgumentException` when a guard is named that the session does not record, when
  the guard's provider does not find the session's exact owner (no owner key, a missing row, another model type), or
  when the guard's resolver does not resolve the principal the session records.
- `actingInTenant()` throws an `InvalidArgumentException` when the test does not act on the guard instance.
- Acting ends on `stopActing()` (which also signs the guard out for the rest of the current request) and on Laravel's
  `Logout` for the guard, which `logout()`, `Auth::sessions()->signOut()` and so a sign-out endpoint dispatch. The
  listener is registered on the application's dispatcher, so a test that fakes `Logout` (`Event::fake()` with no list)
  must call `stopActing()` itself.
- `Auth::forgetGuards()` creates new guard instances, whose own reset callbacks are registered after the helpers'; the
  helpers therefore leave a new instance alone until the test acts again, instead of binding it before its own reset.
- A context acted as wins over a credential the request carries: the first read binds the context instead of resolving
  the credential.

## Implementation Anchors

- `src/Testing/Concerns/InteractsWithAuthenticationContext.php`: the acting methods, `stopActing()` and the assertions.
- `src/Testing/ActingContext.php`: `current()`, `guard()`, `defaultPrincipal()`, `recordedOn()`, `act()`, `actIn()`,
  `forget()`, `assertBound()`.
- `src/Guards/AbstractGuard.php`: `user()`, `authenticateAs()`, `forgetUser()`;
  `src/Guards/Concerns/BindsContextualState.php`: `clearContextualState()`;
  `src/Guards/Concerns/RebindsCollaborators.php`: `setRequest()`, `bindOnFirstRead()`;
  `src/AuthenticationServiceProvider.php`: `wireGuardRebinds()`.
- `src/Testing/FakeOneTimeCodeSender.php`, `src/Testing/FakePasswordResetLinkSender.php`,
  `src/Testing/FakeIdentifierChangeNotifier.php`, `src/Testing/FakeBreachedPasswordChecker.php`: the fakes.

## Authoritative Tests

- `tests/Unit/Testing/ActingContextTest.php`
- `tests/Feature/Testing/ActingContextTest.php`
- `tests/Feature/Testing/InteractsWithAuthenticationContextTest.php`
- `tests/Feature/Testing/MachineInteractsWithAuthenticationContextTest.php` (a machine acted as with and without scopes)
- `tests/Feature/Guards/BindsContextualStateTest.php` (`authenticateAs()` limits a machine to the scopes given),
  `tests/Feature/Guards/AbstractGuardTest.php` (`authenticateAs()` refuses scopes for a human)
- `tests/Integration/Testing/QueuedJobInteractsWithAuthenticationContextTest.php`
- `tests/Feature/Guards/AbstractGuardRequestResolutionTest.php` (`bindOnFirstRead()`)
- `tests/Unit/Testing/FakeOneTimeCodeSenderTest.php`, `tests/Unit/Testing/FakePasswordResetLinkSenderTest.php`,
  `tests/Unit/Testing/FakeIdentifierChangeNotifierTest.php`, `tests/Unit/Testing/FakeBreachedPasswordCheckerTest.php`

## Change Triggers

- A change to how guards are created or rebound to a request (`wireGuardRebinds()`, `setRequest()`), to how Laravel's
  HTTP kernel binds a request, to how `user()` resolves a request, or to `authenticateAs()`.
- A new package guard driver, or a change to how a session records its owner or principal.
- A new delivery or checker contract whose fake belongs in the testing surface.
