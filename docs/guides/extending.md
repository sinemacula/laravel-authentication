# Extending and the suite

## Extensibility

Concrete classes in this package are `final` except `AuthManager` (the package's subclass of Laravel's manager), the
shipped `Models\Device` model, and the extension points noted below. Extension is through **composition and DI**, not
inheritance:

| Extension point                   | How                                                                                                              |
|-----------------------------------|------------------------------------------------------------------------------------------------------------------|
| Custom identity / principal model | Implement `Identity`, `Principal` (and optional capability interfaces)                                           |
| Custom device model               | Implement `EloquentDevice`, use the `ActsAsDevice` trait (and `PrunesDevices` to be pruned)                      |
| Ending device-less access tokens  | Implement `HasTokensValidAfter` on the identity or principal, or use `ProvidesTokensValidAfter`                  |
| Custom principal resolution       | Implement `PrincipalResolver`, bind per-guard or globally                                                        |
| Custom identity retrieval         | Subclass `ModelProvider` (non-final)                                                                             |
| Custom `auth` middleware          | Subclass `Http\Middleware\Authenticate` (non-final)                                                              |
| Guard and provider drivers        | Register them with `Auth::extend()` / `Auth::provider()` as usual: the package's manager inherits them           |
| Guard-scoped JWT settings         | Override `jwt.*` keys in `auth.guards.<name>.jwt`                                                                |
| Sign-in methods                   | Implement `SignInMethod`, register it with `SignInMethodManager::extend()` under a name the package does not use |
| Additional factors (MFA)          | Bind your own `AdditionalFactorPolicy` in the container; call `factorRemoved()` when a factor is removed         |
| Passkeys as a further factor      | Call `Auth::passkeys()->factorOptions()` and `verifyFactor()` from your further-factor package                   |
| Audience decisions                | Implement `AudiencePolicy` and bind it in the container                                                          |
| Attempt limits                    | Implement `AttemptLimiter` and bind it in the container                                                          |
| Identifier normal forms           | Implement `IdentifierNormaliser`, register it by type in the config                                              |
| One-time code delivery            | Implement `OneTimeCodeSender` and bind it in the container                                                       |
| Breached-password checks          | Implement `BreachedPasswordChecker` and bind it in the container                                                 |
| Password reset links              | Implement `PasswordResetLinkSender` and bind it in the container                                                 |
| Identifier change notices         | Implement `IdentifierChangeNotifier` and bind it in the container                                                |
| Code sign-in for another type     | Register `CodeSignIn` for the type with `SignInMethodManager::extend()`                                          |
| Credential scope validation       | Implement `ScopeRegistry` and bind it in the container                                                           |

The `password` method is the package's own: `attempt()`, `validate()` and the password rehash use it directly, so
`extend('password', ...)` throws an `InvalidArgumentException` rather than replace it for `signIn()` alone. Register a
different password scheme under a name of its own and allow that name in the guard's audience. The package's other
methods (`phone_code`, `email_code` and `passkey`) are reserved the same way, as are `api_key` and `client_credentials`,
which an audience lists for machine credentials and which never resolve to a sign-in method. Names are lower case
(a letter, then letters, digits or underscores), and a method resolves only by the exact name it was registered under,
so one method never has a second spelling for a guard to allow or a device to record.

An `AttemptLimiter` of your own counts a subject's `account` in one counter that every guard shares, held to each
guard's `per_identifier` limit (and not counted where that limit is `null`), as well as the identifier's and the IP
address's counters of the guard. Without that, the account bounds under [Rate limits](configuration.md#rate-limits) and
[Additional factors](signing-in.md#additional-factors) do not hold: a limiter keyed only by guard, identifier and IP
address (one built on Laravel's `RateLimiter`, say) lets every spelling of an identifier, and every guard, guess an
account's password and its further factor anew. It records in each granted reservation's `windows` everything its
`release()` needs to give the slots back (string keys and values), and gives them back from the windows alone. A sign-in
that waits for a further factor stores the windows of each reservation it holds and, when it completes, gives each back
through a reservation rebuilt from its own windows, whose subject carries the guard, the flow, the identifier type and
the IP address but no identifier or account. Two reservations may record the same key (a method that checks two secrets
reserves the account twice), and each is given back.

`AbstractGuard` is not final and may be extended for entirely new guard types.

The package replaces Laravel's `auth` manager with its own subclass when it boots, after every service provider has
registered, and carries over the guard and provider drivers registered on the manager it replaces
(`AuthManager::inheritDriversFrom()`), so `Auth::extend()` and `Auth::provider()` calls made in your providers'
`register()` keep working.

## Suite integration

The package authenticates; its siblings decide everything else, each through a seam here, and none is required. Every
seam has a default that works alone.

### Further factors (`laravel-mfa`)

- Bind `Contracts\AdditionalFactorPolicy` (the default, `NeverRequireAdditionalFactor`, never asks). It is asked about
  every admitted sign-in, from `signIn()` and `start()`, and again on a switch of principal, with the guard, identity,
  principal, tenant, method, client and the device the client proved (see
  [Additional factors](signing-in.md#additional-factors)).
- When it asks for a factor, the sign-in waits: `SignInResult::requiresFactor()` and its `PendingFactor` token, then
  `Auth::sessions()->pending()`, `complete()` or `discard()` once the factor is verified or fails. `attempt()` cannot
  wait, so it fails as `additional_factor_required`.
- A factor removed ends the identity's other sessions: `Auth::sessions()->factorRemoved($identity, Auth::device())`.
- Passkeys verify as a factor through `Auth::passkeys()->factorOptions($identity)` and `verifyFactor()`, which count and
  report nothing: the factor's outcome is the factor package's to limit and report.
- Factor state is the factor package's, keyed by the device id (`Auth::device()?->getDeviceIdentifier()`, the `did`
  every session token carries); the device records none.
- A factor the factor package has just verified proves a recent authentication before an identifier change:
  `Reauthentication::confirmedAt($verifiedAt)` (see [Changing identifiers](identifier-changes.md)).
- When every sign-in requires a further factor, a password is no longer the only factor, and `passwords.min_length`
  may be lowered from 15 to 8, as NIST SP 800-63B allows (see [Password policy](passwords.md#password-policy)).

### Authorization (`laravel-authorization`)

- `Auth::principal()`, `Auth::tenant()` and `Auth::type()` are the subject an authorization decision is about.
- `Auth::scopes()` is the ceiling the request's credential grants: `null` for a human's session, which no credential
  limits, the granted list for an API key or a client credentials token, and `[]` for a machine bound without one.
  Intersect the principal's permissions with it; a scope never grants anything by itself (see
  [Credential scopes](machine-credentials.md#credential-scopes)).
- Bind `Contracts\ScopeRegistry` to hold the scopes a credential is issued with to real permissions (the default,
  `AcceptAnyScope`, accepts any well-formed scope).

### Single sign-on (`laravel-sso`)

- When the identity provider's callback has proven the identity, start the session with
  `Auth::sessions($guard)->start($identity, $principal, 'sso', $context)`: the guard's audience must list the method
  name, the identity is reloaded through the guard's provider, activity, the audience policy and the additional-factor
  policy all apply, and no attempt limit or timebox does, since nothing is guessed. No registration is needed.
- For an assertion the package should verify itself, implement `Contracts\SignInMethod`, register it with
  `SignInMethodManager::extend()` and sign in through `signIn()`, which adds the limits and the timebox (see
  [Writing a sign-in method](signing-in.md#writing-a-sign-in-method)).
- Either way the device records the method, so the guard's audience can stop allowing it and its sessions stop
  refreshing.

### Audit (`laravel-audit-log`)

- Every package event implements `Contracts\AuthenticationEvent` and carries one `Events\EventContext`, so one listener
  records them all: the guard, the client, snapshots of the identity, principal, tenant and device identifiers, the
  method, and the credential and its scopes, never a secret (see [Events](events.md#events)).
- Events that report a write are dispatched once it commits on the written row's connection, and never for a rolled-back
  one, so a queued audit listener records only what happened.
