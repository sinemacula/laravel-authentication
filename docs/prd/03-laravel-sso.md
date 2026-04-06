# PRD: 03 Laravel SSO

A driver-based single sign-on package for Laravel that lets developers integrate enterprise identity providers (Auth0, Okta, Azure AD, Google Workspace, FusionAuth, and any standards-compliant OIDC provider) through configuration alone, without provider-specific SDKs or rewriting integration code when switching providers.

---

## Governance

| Field     | Value                                                                                                                                                                                              |
|-----------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Created   | 2026-04-05                                                                                                                                                                                         |
| Status    | draft                                                                                                                                                                                              |
| Owned by  | Sine Macula                                                                                                                                                                                        |
| Traces to | User-provided spec (no prioritization artifact — Blueprint workflow skipped intake/discover/problem-map/prioritize phases; spec derived from architectural discussion in conversation) |

---

## Overview

Enterprise customers increasingly demand single sign-on as a non-negotiable purchase condition, and Laravel developers building SaaS products need to support multiple identity providers (Auth0, Okta, Azure AD, Google Workspace, FusionAuth, custom OIDC) without dragging provider-specific SDKs into their codebase or rewriting integration code each time a new provider is required. Laravel Socialite is designed for social login (Twitter, Facebook, GitHub) and does not cleanly model the enterprise SSO use case; provider SDKs each impose their own conventions and dependencies.

`sinemacula/laravel-sso` provides a thin, driver-based abstraction over OAuth2 and OpenID Connect that ships with built-in drivers for Auth0 and a Generic OIDC driver capable of integrating with any standards-compliant provider through URL configuration alone. The package returns a normalized user value object regardless of provider, emits success and failure events for the consuming application to react to, and never assumes anything about how the application creates sessions, persists users, or manages authenticated state. Custom drivers register through a Laravel-style manager pattern (`Sso::extend()`).

The package is being developed inside the `laravel-iam` monorepo alongside five other identity and access management packages, and will be extracted into a standalone repository at `sinemacula/laravel-sso` once v1.0.0 is complete. It must remain fully standalone with zero hard dependencies on any other Sine Macula package — it must work with Laravel's SessionGuard, Sanctum, Passport, `sinemacula/laravel-authentication`, or any custom authentication system.

---

## Target Users

| Persona                          | Description                                                                                                                  | Key Need                                                                                                                                                  |
|----------------------------------|------------------------------------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------|
| Enterprise Laravel developer     | Building an internal Laravel application that must integrate with the company's existing workforce identity provider        | A way to authenticate users against Auth0, Okta, or Azure AD without learning each vendor's SDK and without coupling the codebase to one provider        |
| SaaS Laravel developer           | Building a multi-tenant SaaS product where enterprise customers require SSO as a purchase condition before signing contracts | A single integration that works with whichever identity provider each customer uses, configured per tenant through environment or database configuration |
| Migrating Laravel developer      | Maintaining a Laravel application currently coupled to one SSO provider and tasked with switching providers                  | A consistent abstraction so switching providers becomes a configuration change, not a multi-week rewrite                                                  |

**Primary user:** SaaS Laravel developer.

---

## Goals

- A single package integrates with multiple SSO providers through configuration alone, without code changes when switching or adding providers.
- Zero required runtime dependencies beyond Laravel itself — no provider-specific SDKs are pulled in transitively.
- The Generic OIDC driver covers at least 80% of standards-compliant identity providers without requiring a custom driver to be written.
- The package returns a consistent normalized user shape regardless of which provider answered the request, while still exposing the raw provider response for advanced use cases.
- The package is fully decoupled from session creation, user persistence, and authenticated state — consuming applications retain full control over those concerns.

## Non-Goals

- Not a social login package — Twitter, Facebook, and consumer-facing OAuth use cases remain Laravel Socialite's domain.
- Not opinionated about session management after a successful SSO exchange — the consuming application creates the session.
- Not shipping SAML 2.0 support in v1; SAML may be a separate future package if demand warrants it.
- Not providing a UI for SSO provider selection, login buttons, or branded login screens.
- Not managing the authenticated state of the user — that responsibility belongs to the application's auth system.
- Not providing user attribute mapping beyond the normalized `SsoUser` shape; richer mapping is the consuming application's concern.
- Not handling just-in-time user provisioning logic — the application decides when and how to create local user records.

---

## Problem

**User problem:** Laravel developers integrating enterprise SSO today must either adopt a heavy authentication framework, hand-write OAuth2 flows against each provider's documentation, or pull in multiple incompatible vendor SDKs. Each SDK has its own conventions for token exchange, user info retrieval, and error handling. Switching identity providers — or supporting multiple in one application — means rewriting integration code and re-learning a new SDK's idioms. Laravel Socialite is the closest existing tool, but it is purpose-built for social login providers and does not cleanly express enterprise SSO scenarios such as Auth0 tenants, Azure AD tenants, custom OIDC discovery, or per-tenant provider configuration.

**Business problem:** Enterprise customers require SSO as a hard purchase condition and will not sign contracts without it. SaaS companies that cannot offer SSO are blocked from selling upmarket. Building SSO in-house per provider is expensive, slow, and bloats the codebase with vendor SDKs and bespoke OAuth code that becomes a maintenance burden as the OAuth2/OIDC ecosystem evolves. A consistent, lightweight abstraction reduces both the upfront integration cost and the long-term maintenance load.

**Current state:** Developers either install provider-specific SDKs (`auth0/auth0-php`, `fusionauth/fusionauth-client`, etc.) directly, hand-roll OAuth2 against the provider's REST API, or attempt to repurpose Laravel Socialite — none of which yield a clean, multi-provider abstraction usable across an entire SaaS portfolio.

**Evidence:** Architectural discussion in conversation; user-provided spec. No formal Blueprint discovery or problem-map artifacts were produced for this PRD.

---

## Proposed Solution

A Laravel developer installs `sinemacula/laravel-sso` via Composer, publishes a single configuration file, and configures one or more SSO drivers — for example, an Auth0 driver pointing at their Auth0 tenant and a Generic OIDC driver pointing at a customer's Okta tenant. They select a default driver via an environment variable, or pick a driver at runtime when handling a callback for a specific tenant.

When a user returns from the identity provider with an authorization code, the developer hands the code to the configured driver and receives back a normalized `SsoUser` value object exposing identity, email, name, and the raw provider response. The developer is responsible for everything that happens next: looking up or provisioning a local user record, creating a session, issuing a token, or whatever else the application's authentication flow requires. The package emits events on success and failure so cross-cutting concerns like audit logging or analytics can subscribe without modifying the auth flow.

Adding a new provider that the Generic OIDC driver does not handle is a matter of writing a small driver class and registering it through `Sso::extend()` in a service provider — no fork of the package, no monkey-patching.

### Key Capabilities

- Exchange an OAuth2 authorization code for a normalized user value object via any configured driver.
- Retrieve a normalized user directly from an existing access token without re-running the code exchange.
- Configure multiple SSO drivers in a single application and select which one to use at runtime.
- Integrate with any standards-compliant OIDC provider (Okta, Azure AD, Google Workspace, FusionAuth, GitHub, etc.) by configuring URLs alone, with no driver code required.
- Register custom SSO drivers via an `extend()` API without modifying the package.
- Subscribe to SSO login success and failure events to plug application-specific behaviour into the flow.
- Install the package without pulling in provider-specific SDKs.
- Receive a consistent normalized user shape regardless of provider.
- Access the full raw provider response when the normalized fields are not enough.
- Use the package alongside any Laravel authentication system (SessionGuard, Sanctum, Passport, `sinemacula/laravel-authentication`, or a custom solution) without modification.
- Override the default driver via environment variable.

---

## Requirements

### Must Have (P0)

- **Authorization code exchange:** A developer can exchange an OAuth2 authorization code for a normalized user value object using any configured SSO driver.
  - **Acceptance criteria:** Calling the package's code-exchange capability with a valid authorization code and a configured driver name returns a value object exposing at minimum a stable user identifier, email, name, and the raw provider response. Calling with an invalid or expired code surfaces a clear, catchable failure.

- **Token-based user retrieval:** A developer can retrieve a normalized user directly from an existing access token without re-running an authorization code exchange.
  - **Acceptance criteria:** Calling the package's user-from-token capability with a valid access token returns the same normalized value object shape as the code-exchange path. Invalid or expired tokens surface a clear, catchable failure.

- **Driver-based architecture:** A developer can configure multiple SSO drivers in a single application and select which to use at runtime.
  - **Acceptance criteria:** With at least two drivers configured in `config/sso.php`, calling the package by driver name resolves the correct driver. The default driver is configurable via environment variable. Switching the default driver requires no code changes.

- **Built-in Auth0 driver:** A developer can integrate with Auth0 using a built-in driver, configured by tenant URL, client ID, and client secret.
  - **Acceptance criteria:** With Auth0 credentials configured, the Auth0 driver successfully exchanges an authorization code (verified against a mocked Auth0 response) and returns a normalized user.

- **Built-in Generic OIDC driver:** A developer can integrate with any standards-compliant OAuth2/OIDC provider through a single Generic OIDC driver, configured by URL alone.
  - **Acceptance criteria:** With token endpoint, userinfo endpoint, client ID, and client secret configured, the Generic OIDC driver successfully exchanges an authorization code (verified against mocked responses simulating Okta, Azure AD, and Google Workspace shapes) and returns a normalized user. Adding a new standards-compliant provider requires only configuration changes, not new driver code.

- **Custom driver extension:** A developer can register a custom SSO driver without modifying the package.
  - **Acceptance criteria:** Calling an `extend()`-style API on the package's manager from a service provider registers a new named driver. The custom driver is then resolvable by name through the same configuration and selection mechanism as the built-in drivers.

- **Normalized user contract:** A developer receives the same value object shape regardless of which driver answered the request.
  - **Acceptance criteria:** Every built-in driver returns an object implementing the same user contract exposing identifier, email, name, and raw response. A consuming application can swap between drivers without changing how it reads the returned object.

- **Raw provider response access:** A developer can access the full raw provider response when the normalized fields are insufficient.
  - **Acceptance criteria:** The returned user value object exposes the unmodified provider response payload alongside the normalized fields.

- **SSO login success and failure events:** A developer can subscribe to events for both successful and failed SSO login attempts.
  - **Acceptance criteria:** A successful code exchange dispatches a documented success event carrying the resolved user and driver name. A failed exchange dispatches a documented failure event carrying the driver name and failure context. Both events are subscribable through Laravel's standard event system.

- **Zero provider SDK dependencies:** A developer can install the package without pulling in any provider-specific SDK as a transitive dependency.
  - **Acceptance criteria:** `composer require sinemacula/laravel-sso` installs only Laravel framework dependencies. No vendor SDK (Auth0, FusionAuth, Okta, Microsoft Graph, etc.) appears in the resulting dependency tree.

- **Standalone from other Sine Macula packages:** A developer can use the package without installing any other `sinemacula/*` package.
  - **Acceptance criteria:** The package's `composer.json` declares no required dependency on `sinemacula/laravel-authentication`, `sinemacula/laravel-mfa`, `sinemacula/laravel-authorization`, `sinemacula/laravel-audit-log`, or `sinemacula/laravel-iam`. Tests pass with none of these packages installed.

- **Auth-system agnostic integration:** A developer can use the package with Laravel's SessionGuard, Sanctum, Passport, `sinemacula/laravel-authentication`, or a custom authentication system without modification.
  - **Acceptance criteria:** The package never creates sessions, never persists users, never reads or writes the Laravel auth guard, and exposes its capabilities purely as data-returning operations and events. Documentation demonstrates integration with at least two distinct auth systems.

- **Single configuration file:** A developer can configure all aspects of the package through one published configuration file.
  - **Acceptance criteria:** Running the package's vendor publish command produces exactly one configuration file (`config/sso.php`). All driver definitions, default driver selection, and provider URLs live in this file.

- **Environment-driven default driver:** A developer can override the default SSO driver via an environment variable.
  - **Acceptance criteria:** Setting the documented environment variable changes the default driver returned when no explicit driver name is supplied, without code changes or cache clears beyond Laravel's standard config cache rebuild.

### Should Have (P1)

- **State and nonce support in Generic OIDC driver:** A developer can rely on the Generic OIDC driver to validate `state` and `nonce` parameters according to the OIDC specification.
  - **Acceptance criteria:** The Generic OIDC driver supports passing and validating `state` and `nonce` values during code exchange. Mismatches surface a catchable failure.

- **Documented provider configuration recipes:** A developer can find ready-made configuration examples for the most common providers in the package documentation.
  - **Acceptance criteria:** README or accompanying documentation includes complete, copy-pasteable Generic OIDC configuration blocks for Okta, Azure AD, and Google Workspace.

- **Helpful failure context:** A developer can diagnose SSO failures from the failure event without needing to add ad-hoc logging.
  - **Acceptance criteria:** The failure event payload includes the driver name, the failure stage (e.g. token exchange, userinfo retrieval), and the upstream error message or status where available.

### Nice to Have (P2)

- **Token refresh capability:** A developer can refresh an expired access token using a refresh token via any driver that supports it.
- **PKCE support in Generic OIDC driver:** A developer can opt into Proof Key for Code Exchange (PKCE) for public-client flows.
- **ID token claim extraction helper:** A developer can extract verified claims from an OIDC ID token via a documented helper.

---

## Success Criteria

| Metric                                                                                          | Baseline                | Target                                                                              | How Measured                                                                                                                       |
|-------------------------------------------------------------------------------------------------|-------------------------|-------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------|
| Number of standards-compliant providers usable through the Generic OIDC driver via config alone | N/A — new capability    | At least 80% of common standards-compliant providers (target list: Okta, Azure AD, Google Workspace, FusionAuth, Keycloak)  | Manual verification against mocked responses for each provider in the integration test suite                                      |
| Number of provider-specific SDKs in the dependency tree                                         | N/A — new capability    | Zero                                                                                | `composer show --tree` after `composer require sinemacula/laravel-sso` in a fresh Laravel application                              |
| Static analysis cleanliness                                                                     | N/A — new capability    | PHPStan level 8 strict, zero errors                                                 | `composer check` (qlty static analysis) in CI                                                                                      |
| Test coverage on manager, drivers, and value objects                                            | N/A — new capability    | At least 90% line coverage                                                          | Clover coverage report from `composer test-coverage` in CI                                                                         |
| Number of hard runtime dependencies on other `sinemacula/*` packages                            | N/A — new capability    | Zero                                                                                | Inspection of `composer.json` `require` block                                                                                      |
| Auth-system integrations demonstrated in documentation                                          | N/A — new capability    | At least two distinct Laravel auth systems (e.g. SessionGuard and Sanctum)          | Manual review of README and accompanying documentation prior to release                                                            |

---

## Dependencies

- PHP 8.3+
- Laravel 13+
- Laravel's HTTP client (`Illuminate\Http\Client\Factory`), included with Laravel — used for all OAuth2/OIDC HTTP traffic.

---

## Assumptions

- Identity providers in scope expose standards-compliant OAuth2 and OpenID Connect endpoints.
- Consuming applications are responsible for creating sessions, persisting users, and managing authenticated state — the package's role ends at returning a normalized user.
- Consuming applications are willing to handle the redirect-back leg of the OAuth2 flow themselves (e.g. a controller that receives the callback and hands the code to the package).
- The Laravel HTTP client is sufficient for all required OAuth2/OIDC traffic — no provider in scope requires features only available in a vendor SDK.
- Provider-specific quirks beyond standards-compliant OIDC will be handled by writing dedicated drivers (built-in for Auth0, custom for anything else) rather than by adding provider-specific branches inside the Generic OIDC driver.

---

## Risks

| Risk                                                                                                            | Impact                                                                                                                                                       | Likelihood | Mitigation                                                                                                                                                                                                                                              |
|-----------------------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------|------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Provider-specific quirks the Generic OIDC driver cannot uniformly handle                                        | Some providers require custom drivers, eroding the "config-only" promise                                                                                     | Medium     | Document exactly which providers are validated against the Generic OIDC driver; expose `Sso::extend()` so consumers can add custom drivers without forking; ship the Auth0 driver as a built-in example of how to handle a provider-specific case      |
| OAuth2/OIDC specification evolution breaks driver compatibility                                                 | Drivers may need updates as providers adopt new spec versions or deprecate flows                                                                             | Low        | Pin driver behaviour to documented OAuth2/OIDC spec sections; cover spec-defined flows with tests using mocked HTTP responses; release notes call out spec-related changes                                                                              |
| Security risks of handling authorization codes, access tokens, and refresh tokens                               | Mishandled tokens could leak credentials or enable account takeover                                                                                          | Medium     | Use only standard OAuth2/OIDC flows; never log or persist tokens by default; surface failures via events so consumers can implement security monitoring; document `state`/`nonce` usage in P1                                                          |
| Vendor lock-in via the raw response escape hatch                                                                | Consumers depending heavily on raw provider fields may struggle to switch providers later                                                                   | Medium     | Document the raw response as an escape hatch, not a default; encourage consumers to read normalized fields where possible                                                                                                                               |
| Consumer confusion between this package and Laravel Socialite                                                    | Developers may install the wrong package or expect social login support                                                                                      | Low        | README opens with a clear scope statement and a comparison to Socialite; documentation explicitly states the package is for enterprise SSO, not social login                                                                                            |
| Standalone-from-other-`sinemacula`-packages constraint slips during monorepo development                        | Accidental cross-package coupling would prevent clean extraction at v1.0.0                                                                                   | Medium     | Package's `composer.json` is the source of truth and is reviewed at every release; CI verifies the package works installed in isolation; periodic dry-run extraction during development                                                                 |

---

## Out of Scope

- SAML 2.0 support (potential future separate package).
- Social login providers (Twitter, Facebook, consumer Google login) — Laravel Socialite's domain.
- Session creation, cookie management, or `Auth::login()` calls — application-level concern.
- User persistence or local user model creation — application-level concern.
- Just-in-time user provisioning logic and rules — application-level concern.
- User attribute mapping richer than the normalized `SsoUser` shape — application-level concern.
- Active Directory or LDAP integration — separate concern, not in this package.
- SCIM provisioning — out of scope.
- A login UI, branded login screens, or provider selection screens.
- Multi-tenant provider configuration storage (e.g. per-tenant database-driven driver config) — application-level concern; the package supports it through runtime driver selection but does not own the storage.

---

## Release Criteria

- All automated tests pass on the supported PHP and Laravel matrix.
- `composer check` (qlty static analysis, PHPStan level 8 strict, code style) is clean.
- Test coverage on manager, drivers, and value objects is at least 90% (Clover report).
- Integration tests cover the Auth0 driver against mocked HTTP responses.
- Integration tests cover the Generic OIDC driver against mocked HTTP responses simulating at least Okta, Azure AD, and Google Workspace.
- A fresh `composer require sinemacula/laravel-sso` in a clean Laravel application installs zero provider-specific SDKs and zero other `sinemacula/*` packages.
- README documents installation, configuration, adding a custom driver via `Sso::extend()`, and example event listeners for both success and failure events.
- README includes Generic OIDC configuration recipes for Okta, Azure AD, and Google Workspace.
- README includes at least two worked examples integrating the package with different Laravel auth systems (e.g. SessionGuard and Sanctum).
- Package is verified to function as a standalone install during monorepo development, in preparation for extraction to `sinemacula/laravel-sso` after v1.0.0.

---

## Traceability

| Artifact             | Path                                                                                                                                                                                              |
|----------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Intake Brief         | User-provided spec (no prioritization artifact — Blueprint workflow skipped intake/discover/problem-map/prioritize phases; spec derived from architectural discussion in conversation) |
| Relevant Spikes      | None                                                                                                                                                                                              |
| Problem Map Entry    | None                                                                                                                                                                                              |
| Prioritization Entry | None                                                                                                                                                                                              |

---

## References

- Ecosystem PRDs in this repository: `docs/prd/01-laravel-authentication.md`, `docs/prd/02-laravel-mfa.md`, `docs/prd/04-laravel-authorization.md`, `docs/prd/05-laravel-audit-log.md`, `docs/prd/06-laravel-iam.md`.
- Target standalone repository (post-extraction): `sinemacula/laravel-sso`.
