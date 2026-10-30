# Provider Composition

## Purpose

This note describes how the package's service provider composes with an application's and other packages' providers: why
every binding it makes is a default that another binding is never replaced by, and why the package owns Laravel's `auth`
binding and what it takes over from the manager it replaces.

## Invariants

- Every binding `AuthenticationServiceProvider::register()` makes is conditional (`singletonIf()`, `scopedIf()`,
  `bindIf()`): `PrincipalResolver`, `AudiencePolicy`, `AttemptLimiter`, `AdditionalFactorPolicy`, `ScopeRegistry`,
  `BreachedPasswordChecker`, `PasswordResetLinkSender`, the `IdentifierNormalisers` and `SignInMethodManager`
  registries, the `auth` middleware, and the internal `WebAuthn`, `Rehashing` and `JwtTokenServiceFactory`. A binding
  made before the provider registers is kept, so a factor package's `AdditionalFactorPolicy` is never replaced by
  `NeverRequireAdditionalFactor`, nor an authorization package's `ScopeRegistry` by `AcceptAnyScope`, whichever order
  the providers are listed in; a binding made after replaces the default, as any later binding does. The internals are
  conditional so the rule has no exceptions, not because they are extension points.
- `Application::bound()` counts deferred services, so a deferred provider's service is never shadowed by a default the
  package binds once the deferred map is installed, and a default bound before it is replaced when the deferred provider
  loads on first resolution.
- `OneTimeCodeSender` and `IdentifierChangeNotifier` have no default: the flows that need one check `bound()` and fail
  closed, so the order cannot matter.
- A guard without a `principal_resolver` override takes the global `PrincipalResolver` it is built with and follows
  every later rebinding of it (`wireGuardRebinds()`), so a resolver bound before the package registers, or rebound at
  runtime, is the one the guard, its refresh exchange and its session service use.
- The package owns the `auth` binding: its guards, the contextual accessors and the `Auth` facade rely on its
  `AuthManager`. At boot the provider extends `auth`: a manager that is already the package's, or a subclass of it, is
  kept as it is; any other is replaced by a new package `AuthManager`, which takes over its state through
  `inheritStateFrom()`:
  - the guard creators (`Auth::extend()`, `Auth::viaRequest()`) and the user provider creators (`Auth::provider()`);
  - the user resolver, whether its own default, the one `shouldUse()` sets, or one set with `resolveUsersUsing()`;
  - the guards already resolved, which stay the same instances, so `auth.driver` and anything holding a guard still see
    the guard the package's manager returns, and the guard's own `request` rebinding keeps reaching it.
- An anonymous closure bound to the replaced manager is bound to the package's instead. `viaRequest()` binds its
  creator, Laravel 13 binds each anonymous `extend()` closure, and the default user resolver is the manager's own, so
  without this a guard built through the new manager would create its user provider through the old one, which knows
  none of the drivers registered after the swap (the package's `model` driver among them). A closure bound to anything
  else, a static closure and a first-class callable (which keeps the object whose method it is) are taken as they are.
- The facades' cached `auth` root is forgotten when the manager is swapped, so a provider that used `Auth::` before the
  package booted does not leave the facade on the replaced manager, where the package's own `jwt`, `api_key` and `model`
  drivers would otherwise be registered.

## Success Path

- A factor, authorization or IAM package binds its policies in `register()`, in any order relative to this package's
  provider; sign-in, scope validation and principal resolution use them.
- A package registers a sign-in method with `callAfterResolving(SignInMethodManager::class, ...)` in `register()` (or on
  the resolved registry in `boot()`), so the method lands on the registry the package uses in either order.
- A package registers guard and provider drivers or a user resolver with `Auth::extend()`, `Auth::viaRequest()`,
  `Auth::provider()` or `Auth::resolveUsersUsing()` from `register()` or `boot()`; they keep working through the
  package's manager.
- An application that customises the manager extends the package's `AuthManager` and binds it to `auth` in a
  `register()`; the package keeps it and registers its drivers on it.

## Failure / Edge Cases

- A default resolved while providers are still registering keeps a deferred provider's binding of it from loading:
  Laravel installs deferred services after registering the eager providers, and loads a deferred provider only for a
  service that has no instance yet. Resolve nothing while registering. An eager `bind()` or `singleton()` is not
  affected: it drops the resolved instance, so it replaces the default for every caller that resolves it afterwards
  (one that already holds the default keeps it).
- `make(SignInMethodManager::class)->extend()` in a `register()` that runs before the package's is lost: the registry is
  not shared yet, so `make()` builds one that nothing else sees. Hence `callAfterResolving()`.
- Identifier normalisers are configuration (`authentication.identifiers.normalisers`). Laravel merges a package's
  configuration one level deep, so a value set under `authentication.identifiers` before the package registers, when the
  application has not published the configuration, replaces the package's normalisers; a package adds its normaliser in
  `boot()`.
- A subclass of Laravel's manager loses its own behaviour (its methods, its overrides, and whatever its closures rely on
  them for) when the package replaces it: the package owns the binding, and a manager of the application's extends the
  package's instead. The swap is not a decorator.
- An object that captured the replaced manager itself before the swap keeps it; the container's `rebound('auth')`
  callbacks run when `auth` had already resolved. Rebinding `auth` after the package boots is not supported: when `auth`
  resolved before the package booted, the swap is applied to that instance once (Laravel keeps no extender for a
  resolved instance), so a later binding is not swapped.

## Implementation Anchors

- `src/AuthenticationServiceProvider.php`: `register()`, `ownAuthManager()`, `wireGuardRebinds()`.
- `src/AuthManager.php`: `inheritStateFrom()`.
- `src/Sessions/SignInMethodManager.php`: `extend()`.

## Authoritative Tests

- `tests/Feature/ProviderBindingOrderTest.php`
- `tests/Feature/AuthenticationServiceProviderTest.php` `testBootingReplacesAResolvedLaravelManagerAndItsFacadeRoot`
- `tests/Integration/Providers/SiblingPoliciesRegisteredFirstTest.php`,
  `tests/Integration/Providers/SiblingPoliciesRegisteredLastTest.php` (`SiblingPoliciesTestCase`)
- `tests/Feature/AuthManagerOwnershipTest.php`
- `tests/Feature/AuthManagerCustomisationTest.php`
- `tests/Feature/AuthManagerReplacementTest.php`
- `tests/Feature/AuthManagerTest.php` `testInheritStateFrom*`

## Change Triggers

- A new binding in the provider's `register()`, which must be conditional too.
- A change to how the `auth` binding is extended, or to the state Laravel's `AuthManager` holds (its creators, its user
  resolver, its guards), which `inheritStateFrom()` must follow.
- A change to how a sign-in method or an identifier normaliser is registered.
