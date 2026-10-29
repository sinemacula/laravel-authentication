# Testing Helpers

## Purpose

This note describes how an application's tests act as an identity, a principal or a device's session on a package
guard, how that context survives the requests a test sends through the HTTP kernel, how it ends, what the bound-context
assertions compare, and the fakes the package ships for its delivery contracts.

## Invariants

- Production code paths are untouched. The helpers use only the guard's public, trusted `authenticateAs()`,
  `forgetUser()` and its collaborator accessors; `setRequest()`, `forgetGuardState()`, the service provider and the
  guards' own rebinding callbacks behave exactly as without the helpers.
- A guard acted on is bound again on every `request` rebinding, after the guard's own `setRequest()` reset: the guard
  registers its callback when it is created, and the helpers register theirs once per guard instance afterwards, so
  each request the kernel binds is authenticated as the test acted, before any middleware runs.
- Each guard has at most one acting context, keyed by its name and tied to the guard instance acted on. Acting again on
  the guard replaces it; acting on another guard leaves it alone.
- The context is bound as given: no ownership, activity, revocation or session-deadline check. A machine identity
  bound this way is limited to no scope (`[]`), as every trusted bind of one is.
- Acting makes the guard the default (`shouldUse()`), as Laravel's `actingAs()` does, and a model created for the test
  is no longer reported as just created, so a route returning it answers `200`, as with `be()`.
- A queued job a worker runs starts signed out (`ForgetGuardStateBeforeJob` calls `setRequest()` directly, not through
  a rebinding); the next request the test sends is acted as again.
- The assertions read the guard through its public accessors, so the first one on a request resolves it as application
  code would. Identity, principal, tenant and device match when both are absent, when they are the same instance, or
  when they are of the same class with identifiers that are equal as strings. Scopes and type compare exactly.
- Laravel's `actingAs()` is unchanged: it binds through `setUser()` for code running in the test, and a request through
  the kernel starts over.

## Success Path

1. `actingAsIdentity()`, `actingAsPrincipal()` or `actingOnDevice()` resolves the package guard named (or the default),
   works out the identity, principal and device, and hands them to the container's `Testing\ActingContext`.
2. The context stores them for the guard, registers its `request` rebinding callback for that guard instance once, and
   binds them at once through `authenticateAs()`.
3. Each request the test sends rebinds `request`: the guard resets, then the callback binds the context again
   (`Authenticated`, `PrincipalAssigned` and, with a device, `DeviceAuthenticated`, as a bearer request).
4. `actingOnDevice()` reads the device's owner key and principal columns without a query, loads the owner through the
   guard's provider and checks it is the exact owner (`DeviceOwnership::isOwner()`), and resolves the recorded principal
   through the guard's resolver with the recorded identifier as the hint, checking it is the one recorded
   (`PrincipalReference::isRecordedOn()`); a device recording no principal acts as the owner's default one. The guard
   is the one the device records unless the test names it.

## Failure / Edge Cases

- A guard of another driver (Laravel's `session`) is refused with an `InvalidArgumentException` naming it.
- `actingAsIdentity()` without a principal, for an identity with no default one, throws an `InvalidArgumentException`,
  as `setUser()` does.
- `actingOnDevice()` throws an `InvalidArgumentException` when a guard is named that the device does not record, when
  the guard's provider does not find the device's exact owner (no owner key, a missing row, another model type), or
  when the guard's resolver does not resolve the principal the device records.
- Acting ends on `stopActing()` (which also signs the guard out for the rest of the current request) and on Laravel's
  `Logout` for the guard, which `logout()`, `Auth::sessions()->signOut()` and so a sign-out endpoint dispatch. The
  listener is registered on the application's dispatcher, so a test that fakes `Logout` (`Event::fake()` with no list)
  must call `stopActing()` itself.
- `Auth::forgetGuards()` creates new guard instances, whose own reset callbacks are registered after the helpers'; the
  helpers therefore leave a new instance alone until the test acts again, instead of binding it before its own reset.
- A context acted as wins over a credential the request carries: the guard is already bound, and settled, when the
  request is resolved.

## Implementation Anchors

- `src/Testing/Concerns/InteractsWithAuthenticationContext.php`: the acting methods, `stopActing()` and the assertions.
- `src/Testing/ActingContext.php`: `current()`, `guard()`, `defaultPrincipal()`, `recordedOn()`, `act()`, `forget()`,
  `assertBound()`.
- `src/Guards/AbstractGuard.php`: `authenticateAs()`, `forgetUser()`; `src/Guards/Concerns/RebindsCollaborators.php`:
  `setRequest()`; `src/AuthenticationServiceProvider.php`: `wireGuardRebinds()`.
- `src/Testing/FakeOneTimeCodeSender.php`: the code sender fake.

## Authoritative Tests

- `tests/Unit/Testing/ActingContextTest.php`
- `tests/Feature/Testing/ActingContextTest.php`
- `tests/Feature/Testing/InteractsWithAuthenticationContextTest.php`
- `tests/Feature/Testing/MachineInteractsWithAuthenticationContextTest.php`
- `tests/Integration/Testing/QueuedJobInteractsWithAuthenticationContextTest.php`
- `tests/Unit/Testing/FakeOneTimeCodeSenderTest.php`

## Change Triggers

- A change to how guards are created or rebound to a request (`wireGuardRebinds()`, `setRequest()`), or to
  `authenticateAs()`.
- A new package guard driver, or a change to how a device records its owner or principal.
- A new delivery or checker contract whose fake belongs in the testing surface.
