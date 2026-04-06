# PRD: 02 Laravel MFA

A standalone, driver-based multi-factor authentication package for Laravel that works with any authentication system via the standard `Authenticatable` contract.

---

## Governance

| Field     | Value                                                                                                                |
|-----------|----------------------------------------------------------------------------------------------------------------------|
| Created   | 2026-04-05                                                                                                           |
| Status    | draft                                                                                                                |
| Owned by  | Sine Macula                                                                                                          |
| Traces to | User-provided spec (no prioritization artifact — Blueprint workflow skipped intake/discover/problem-map/prioritize)  |

---

## Overview

Laravel has no first-party MFA solution, and the available community packages are typically tied to specific authentication implementations (Breeze, Jetstream, Sanctum-only patterns), opinionated about which factor types to support, or bundle heavyweight dependencies. The result is that teams routinely build MFA from scratch — error-prone work in a security-critical area — or adopt heavy frameworks they did not otherwise need. With MFA increasingly required by SOC2, PCI, and HIPAA, this is a recurring blocker for enterprise-ready Laravel applications.

`sinemacula/laravel-mfa` provides a lightweight, driver-based MFA layer that any Laravel application can adopt regardless of how it currently authenticates users. It depends only on Laravel itself and the standard `Illuminate\Contracts\Auth\Authenticatable` contract, so it composes with Laravel's SessionGuard, Sanctum, Passport, custom guards, and `sinemacula/laravel-authentication` without preference or coupling. TOTP, email codes, and backup codes work out of the box; SMS works with a single gateway binding the consumer provides. Custom factor drivers can be registered through a Laravel-style manager `extend()` API.

This package is being developed inside the `laravel-iam` monorepo alongside five sibling packages and will be extracted to a standalone `sinemacula/laravel-mfa` repository after v1.0.0 ships. Throughout development and after extraction, the package must remain standalone — it must not introduce a hard runtime dependency on `sinemacula/laravel-authentication` or any other package in the ecosystem.

---

## Target Users

| Persona                                  | Description                                                                                                                  | Key Need                                                                                                                          |
|------------------------------------------|------------------------------------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------|
| Security-conscious Laravel developer     | Builds Laravel applications subject to compliance regimes (SOC2, PCI, HIPAA) and needs standard MFA without bespoke effort   | A reliable, auditable MFA implementation with multiple factor types that can satisfy compliance review                            |
| Existing-app integrator                  | Owns a Laravel application already running on Sanctum, Passport, SessionGuard, or a custom guard, and needs to add 2FA      | A drop-in MFA layer that does not require rewriting or migrating the existing authentication stack                                |
| Step-up authentication implementer       | Needs to require MFA only for sensitive operations (admin actions, payments, PII access) rather than at every login         | Granular middleware-driven enforcement that can be applied to specific routes and re-verified on demand                           |

**Primary user:** Security-conscious Laravel developer.

---

## Goals

- Developers can add MFA to any Laravel application without modifying their existing authentication stack.
- TOTP, email-code, and backup-code factors work out of the box with zero required runtime dependencies beyond Laravel.
- SMS-code factor works with a single consumer-provided gateway binding, with no SMS provider hardcoded.
- All factor drivers are pluggable through a Laravel-style manager `extend()` API.
- Package passes PHPStan level 8 strict and PSR-12 conformance with no suppressions added for delivery convenience.
- Manager, drivers, and middleware reach at least 90% line coverage in the test suite.
- Package remains standalone with zero hard runtime dependencies on any other `sinemacula/laravel-iam` ecosystem package.

## Non-Goals

- Not a general-purpose notification system; the package handles MFA delivery only.
- Not shipping concrete SMS provider implementations (Twilio, Vonage, AWS SNS, etc.); consumers bring their own gateway implementation.
- Not an authentication system on its own; it layers on top of an existing Laravel auth stack.
- Not a WebAuthn / FIDO2 / Passkeys implementation.
- Not opinionated about MFA UI; no Blade views, Livewire components, or frontend assets are shipped.
- Not a role- or permission-based MFA enforcement engine; route-level enforcement only.

---

## Problem

**User problem:** Laravel developers who need MFA today are forced to either adopt a starter kit that locks them into its authentication patterns (Breeze, Jetstream), pull in a heavy auth framework, or hand-roll MFA themselves. Hand-rolled MFA is high-risk because of the cryptographic and timing-attack surface, and most existing community packages are tied to specific authentication implementations or factor types.

**Business problem:** MFA is a baseline requirement for most enterprise SaaS sales and is mandated by SOC2, PCI, and HIPAA. Building MFA in-house is expensive, slow, and audit-risky. Adopting an inflexible package creates vendor lock-in and rework when the underlying auth strategy changes. Not shipping MFA at all is a deal-breaker for enterprise deals.

**Current state:** Developers either (a) accept the starter-kit MFA bundled with Breeze or Jetstream and inherit those patterns, (b) adopt a heavy authentication framework they would not otherwise have chosen, or (c) build custom MFA against `pragmarx/google2fa` or similar libraries and reimplement attempt tracking, expiry, backup codes, and middleware enforcement themselves.

**Evidence:** User-provided spec derived from architectural discussion in conversation. No prioritization artifact exists; Blueprint intake/discover/problem-map/prioritize phases were skipped for this PRD.

---

## Proposed Solution

A consuming developer installs the package via Composer, publishes the configuration and migrations, and runs the migrations. They configure which factor drivers their application supports (TOTP, email, SMS, backup codes, or any custom driver they have registered). For SMS, they bind their chosen gateway implementation against the package's gateway contract; for email, Laravel's built-in mail system is used; for TOTP, they install the suggested TOTP library as a runtime dependency.

To enforce MFA on a route, the developer attaches the MFA middleware to the route or route group. When an authenticated request hits a protected route without a valid MFA verification, the middleware throws a structured exception containing the list of factors available to the current user. The consuming application catches that exception (or relies on its global handler) and renders whatever UI it wants — a verification page, a JSON response, an API error — using the factor data the exception carries.

For sensitive operations or step-up flows, the developer applies the middleware to the relevant routes only. For routes that should bypass MFA enforcement (such as the verification endpoints themselves), the developer marks them as skipped. Throughout, the developer can query the current user's MFA state (set up, required, expired) and customise expiry windows and attempt limits per-factor or globally.

### Key Capabilities

- Add MFA enforcement to any Laravel application without changing the existing auth stack.
- Verify users via TOTP, email-delivered codes, SMS-delivered codes, or backup codes.
- Register custom factor drivers via a manager `extend()` API.
- Apply or skip MFA enforcement on a per-route or per-route-group basis.
- Inspect a user's MFA state (set up / required / expired) at any time.
- Receive structured exception data describing available factors when MFA is required or expired.
- Use MFA on any identity type (User, Admin, Guest, etc.) via polymorphic association.
- Plug in any SMS provider through a single gateway contract.
- Customise factor and attempt models, expiry windows, and attempt limits via configuration.
- Publish and modify the MFA migrations to fit application schema requirements.

---

## Requirements

### Must Have (P0)

- **Standalone integration:** Developer can install the package into any Laravel 13+ application using any auth stack (SessionGuard, Sanctum, Passport, custom guard, or `sinemacula/laravel-authentication`) without modifying the auth stack.
  - **Acceptance criteria:** Integration tests demonstrate successful MFA enforcement against at least three distinct authentication setups (SessionGuard, Sanctum, and a custom guard implementing only `Illuminate\Contracts\Auth\Authenticatable`) with no package code paths conditional on the guard in use.

- **TOTP factor driver:** Developer can require users to set up and verify MFA using a time-based one-time password (TOTP) compatible with standard authenticator apps.
  - **Acceptance criteria:** A user can register a TOTP secret and successfully verify a code generated by a standard RFC 6238 authenticator app; invalid and expired codes are rejected; the TOTP runtime dependency is declared in `suggest`, and a clear, actionable error is raised at runtime if the dependency is missing when the driver is used.

- **Email code factor driver:** Developer can require users to set up and verify MFA using a code delivered via Laravel's mail system.
  - **Acceptance criteria:** Triggering email verification dispatches a mail message via Laravel's mail subsystem containing a generated code; submitting the matching code within the configured expiry window verifies; submitting a wrong code or a code after expiry is rejected.

- **SMS code factor driver with pluggable gateway:** Developer can require users to verify MFA using a code delivered over SMS through a gateway implementation they provide.
  - **Acceptance criteria:** The package defines a single SMS gateway contract; the default binding is a null implementation that throws a clear, actionable error explaining how to bind a real gateway; an integration test demonstrates verification end-to-end using a fake gateway implementation registered through the standard Laravel container.

- **Backup code factor driver:** Developer can issue backup codes that users can use to recover access when their primary factor is unavailable.
  - **Acceptance criteria:** Backup codes can be generated, stored, and verified; each code can be used at most once; verifying a used or invalid code is rejected; backup-code generation and verification are implemented in pure PHP with no third-party runtime dependencies.

- **Custom driver extension API:** Developer can register a custom MFA factor driver and have it participate in MFA enforcement on equal footing with built-in drivers.
  - **Acceptance criteria:** Calling the package's manager `extend()` API with a driver name and resolver registers the driver; subsequent verification requests for that driver are routed to it; tests cover registration, resolution, and verification of a custom driver.

- **Route enforcement middleware:** Developer can attach a single middleware to any route or route group to require a valid MFA verification before the request is handled.
  - **Acceptance criteria:** A request from an authenticated user without a valid MFA verification triggers an `MfaRequiredException`; a request with a valid, non-expired verification proceeds; a request with an expired verification triggers an `MfaExpiredException`.

- **Route skip mechanism:** Developer can mark specific routes as exempt from MFA enforcement (for example, the verification endpoints themselves).
  - **Acceptance criteria:** A route flagged as skipped is reachable by an authenticated user even when MFA enforcement would otherwise apply; integration tests cover skipping verification endpoints to avoid enforcement loops.

- **Structured MFA exceptions:** Developer can render any UI they want when MFA is required or expired, using the factor data carried on the exception.
  - **Acceptance criteria:** `MfaRequiredException` and `MfaExpiredException` both carry the list of factors available to the current user in a structured, documented form; both exceptions extend `Symfony\Component\HttpKernel\Exception\HttpException`; tests verify the data shape on each exception.

- **MFA state inspection:** Developer can query whether the current user has MFA set up, should be required to use MFA, and whether the current verification has expired.
  - **Acceptance criteria:** The package exposes a documented public API surface for these three queries; tests cover all relevant state combinations (no factors, factors but not verified, verified, verified-but-expired).

- **Polymorphic identity support:** Developer can use MFA with any Eloquent identity type (User, Admin, Guest, etc.) through polymorphic association without subclassing or model gymnastics.
  - **Acceptance criteria:** Integration tests demonstrate MFA enforcement working against at least two distinct Eloquent identity classes within the same application.

- **Constant-time code verification:** Developer can rely on the package to compare submitted codes in constant time to mitigate timing attacks.
  - **Acceptance criteria:** All built-in drivers use constant-time comparison for code verification; static analysis or unit tests assert non-equality comparisons are not used in the verification path.

- **Publishable, customisable migrations:** Developer can publish the package's migrations and modify them before running them on their database.
  - **Acceptance criteria:** Two migrations (one for factors, one for attempts) are publishable via Laravel's standard `vendor:publish` workflow; both run cleanly on a fresh SQLite, MySQL, and PostgreSQL database in the test matrix; primary keys are ULIDs.

- **Customisable factor and attempt models:** Developer can swap the default factor and attempt Eloquent models for their own subclasses via configuration without modifying package code.
  - **Acceptance criteria:** Configuration values are read at boot to resolve factor and attempt models; tests verify a custom subclass replaces the default and is used by all package internals.

- **Per-factor and global expiry configuration:** Developer can configure how long an MFA verification remains valid, both as a global default and per factor driver.
  - **Acceptance criteria:** Configuration supports a global expiry value and per-driver overrides; tests verify both that the global default applies when no override is set and that per-driver overrides take precedence.

- **Per-factor maximum attempt configuration:** Developer can configure how many failed verification attempts are allowed per factor before further attempts are rejected.
  - **Acceptance criteria:** Configuration supports per-driver maximum-attempt values; once the configured threshold is reached, further verification attempts for that factor are rejected; tests cover the threshold edge cases.

### Should Have (P1)

- **Documented Twilio binding example:** Developer can follow a documented worked example to bind a real-world SMS gateway (Twilio or Vonage) against the SMS gateway contract.
  - **Acceptance criteria:** README contains a complete worked example showing how to implement and bind an SMS gateway against the package's contract.

- **Configurable code length and alphabet:** Developer can configure the length and character alphabet of generated codes for email, SMS, and backup-code drivers.
  - **Acceptance criteria:** Configuration supports per-driver code length and alphabet; defaults are documented; tests verify generated codes match the configured constraints.

### Nice to Have (P2)

- **Replay protection on email and SMS codes:** Codes already used for a successful verification cannot be re-used inside their expiry window.

- **Rate limiting helpers for verification endpoints:** Documented guidance for rate-limiting MFA verification endpoints using Laravel's built-in rate limiter.

---

## Success Criteria

| Metric                                         | Baseline               | Target                                                              | How Measured                                                                          |
|------------------------------------------------|------------------------|---------------------------------------------------------------------|---------------------------------------------------------------------------------------|
| Auth-stack independence                        | N/A — new capability   | Works with at least three distinct auth stacks without modification | Integration tests against SessionGuard, Sanctum, and a custom `Authenticatable` guard |
| Hard runtime dependencies beyond Laravel       | N/A — new capability   | 0                                                                   | Inspection of `composer.json` `require` section in CI                                 |
| Built-in factor drivers ready out of the box   | N/A — new capability   | 4 (TOTP, email, SMS, backup codes)                                  | Driver registry inspection in tests                                                   |
| PHPStan level 8 strict                         | N/A — new capability   | 0 errors, 0 baseline suppressions added during this PRD             | `composer check` (qlty / PHPStan) in CI                                               |
| PSR-12 conformance                             | N/A — new capability   | 0 violations                                                        | PHP-CS-Fixer / CodeSniffer in CI                                                      |
| Test coverage (manager, drivers, middleware)   | N/A — new capability   | >=90% line coverage on these packages                               | Clover coverage report from `composer test-coverage`                                  |
| Migrations green on fresh install              | N/A — new capability   | 100% pass on SQLite, MySQL, PostgreSQL                              | Migration step in CI matrix                                                           |
| Documented SMS gateway worked example          | N/A — new capability   | At least one complete example in README                             | README review at release                                                              |

---

## Dependencies

- PHP 8.3+
- Laravel 13+
- `Illuminate\Contracts\Auth\Authenticatable` (Laravel standard contract)
- Optional (suggested) runtime dependency: a TOTP library satisfying RFC 6238, used by the TOTP driver only and detected at runtime with a clear error if missing
- Optional consumer-provided dependency: an SMS gateway implementation conforming to the package's gateway contract, required only if the SMS driver is used

---

## Assumptions

- Consuming applications use Eloquent for their identity models (consistent with Laravel idioms).
- Consuming applications can run database migrations against a relational store supported by Laravel.
- Consuming applications already have a working authentication mechanism — this package layers MFA on top, it does not authenticate users.
- Constant-time string comparison primitives available in PHP 8.3 (`hash_equals`) are sufficient mitigation against timing attacks for the verification surface.
- Application developers are responsible for rendering MFA UI; they can catch the package's exceptions and translate them into the response format their application uses.
- Polymorphic relationships against Eloquent identities are an acceptable design choice for consumers (no flat single-table requirement).

---

## Risks

| Risk                                                                                                  | Impact                                                                                                                                          | Likelihood | Mitigation                                                                                                                                                                                                |
|-------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------|------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| SMS gateway abstraction is too thin and consumers struggle to integrate real providers                 | Consumers either give up on the SMS driver or implement gateways that subtly misbehave on retries / delivery failures                          | Medium     | Provide a documented worked example for at least one mainstream provider (Twilio or Vonage); ship a fake gateway for tests; verify the contract surface against a second provider mentally before release |
| The suggested TOTP library becomes unmaintained                                                        | TOTP driver becomes a maintenance liability; consumers stuck on an unmaintained dependency                                                      | Low        | Treat the TOTP library as a soft dependency (in `suggest`) accessed through a thin internal seam so it can be swapped without API breakage; document the seam in the driver source                       |
| Timing attacks on code verification                                                                   | Attackers can mount side-channel attacks against verification endpoints                                                                          | Medium     | All verification paths use constant-time comparison; this is asserted as a P0 acceptance criterion and covered by tests                                                                                    |
| Migration conflicts with existing MFA tables in consumer applications                                  | Consumers with prior MFA tables cannot install the package without manual schema reconciliation                                                  | Medium     | Migrations are publishable, so consumers can edit table names or merge into existing schemas before running them; document the publishing workflow in the README                                          |
| Semantic confusion between "Email MFA driver" and "any notification channel"                          | Consumers expect to be able to delegate Email/SMS delivery through Laravel's `Notification` system rather than the package's drivers              | Low        | Document the design choice (drivers, not notification channels) explicitly in the README; explain how to wrap a driver in a custom one if delegation is desired                                            |
| Standalone constraint accidentally violated during monorepo development                                | Package picks up an implicit hard dependency on `sinemacula/laravel-authentication` and breaks for consumers using other auth stacks                       | Medium     | CI step asserts `composer.json` `require` section contains no `sinemacula/*` runtime dependencies; integration tests cover three distinct auth stacks (SessionGuard, Sanctum, custom guard)               |

---

## Out of Scope

- WebAuthn / FIDO2 / Passkeys (potential future package).
- Concrete SMS provider implementations (Twilio, Vonage, AWS SNS, etc.) — consumers bring their own gateway.
- Authentication itself (handled by the consuming application's auth stack).
- SSO / federated identity providers (belongs in `sinemacula/laravel-sso`).
- Role- or permission-based MFA enforcement decisions (belongs in `sinemacula/laravel-authorization`).
- UI components — Blade views, Livewire components, JavaScript widgets.
- MFA recovery workflows beyond backup codes (recovery email flows, support-ticket recovery, identity-proofing recovery).
- Audit logging of MFA events (belongs in `sinemacula/laravel-audit-log`).

---

## Release Criteria

- All automated tests pass on the supported PHP and Laravel matrix.
- PHPStan level 8 strict reports zero errors with no new baseline suppressions.
- PHP-CS-Fixer / CodeSniffer report zero PSR-12 violations.
- Manager, drivers, and middleware reach at least 90% line coverage in the coverage report.
- Integration tests cover each built-in driver: TOTP, Email, SMS (with a fake gateway), Backup codes.
- Integration tests cover at least three distinct authentication stacks (SessionGuard, Sanctum, custom guard).
- Published migrations apply cleanly on a fresh database in the CI matrix.
- README documents installation, configuration, route enforcement, route skipping, exception handling, custom driver registration, and a worked SMS gateway binding example.
- `composer.json` `require` section contains no `sinemacula/*` runtime dependencies, verified by a CI assertion.

---

## Traceability

| Artifact             | Path                                                                                                                                                  |
|----------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------|
| Intake Brief         | N/A — Blueprint workflow skipped intake/discover/problem-map/prioritize phases; spec derived from architectural discussion in conversation             |
| Relevant Spikes      | N/A                                                                                                                                                   |
| Problem Map Entry    | N/A                                                                                                                                                   |
| Prioritization Entry | N/A — User-provided spec (no prioritization artifact)                                                                                                  |

---

## References

- User-provided spec (no prioritization artifact — Blueprint workflow skipped intake/discover/problem-map/prioritize phases; spec derived from architectural discussion in conversation).
- Sibling PRDs in the `laravel-iam` ecosystem: `01-laravel-authentication.md`, `03-laravel-sso.md`, `04-laravel-authorization.md`, `05-laravel-audit-log.md`, `06-laravel-iam.md`.
- Target standalone repository (post-extraction): `sinemacula/laravel-mfa`.
