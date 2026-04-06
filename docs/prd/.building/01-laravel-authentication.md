# PRD: 01 sinemacula/laravel-authentication

A standalone Laravel package that provides contextual, stateless authentication primitives — distinguishing the authenticated identity from the acting principal and the device — while remaining fully compatible with Laravel's standard auth infrastructure.

---

## Governance

| Field     | Value                                                                                              |
|-----------|----------------------------------------------------------------------------------------------------|
| Created   | 2026-04-05                                                                                         |
| Status    | draft                                                                                              |
| Owned by  | Sine Macula — IAM ecosystem maintainers                                                            |
| Traces to | User-provided spec (no prioritization artifact — Blueprint intake/discover/problem-map/prioritize phases were skipped) |

---

## Overview

Laravel's default authentication assumes a one-dimensional model: a user logs in, and the framework tracks "who" they are. Enterprise and multi-tenant SaaS applications routinely need more: they need to distinguish the authenticated **identity** (who the human or service is) from the **principal** (the capacity in which that identity is currently acting — e.g. an employee of a tenant organization, an external collaborator, an API client) and from the **device** (which client made the request, when, and with what refresh credential). Today, developers either bolt custom logic onto Laravel's defaults, build entirely bespoke auth systems, or adopt opinionated starter kits that lock them into specific patterns. None of these scale across teams or audits.

`sinemacula/laravel-authentication` provides the contextual auth primitives — Identity, Principal, Device, plus stateless guards and a contract-based principal resolver — without forcing any storage or domain decisions on the consuming application. It supports both a 2D model (Identity = Principal) and a full 3D model (Identity → Principal → Organization) within the same application via different guards. It is fully compatible with Laravel's `Auth` facade, `auth` middleware, Blade directives, and standard auth events, so consumers can adopt it without abandoning the framework's idioms.

The package is being developed inside the `laravel-iam` monorepo alongside five sibling packages (MFA, SSO, authorization, audit log, and an umbrella package). Once the monorepo reaches v1.0.0, `sinemacula/laravel-authentication` will be extracted to a standalone repository and published to Packagist as an independent library with zero hard runtime dependencies on its sibling packages. This split is a release dependency, not a stretch goal.

---

## Target Users

| Persona                            | Description                                                                                                                                                  | Key Need                                                                                                                                                               |
|------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Enterprise Laravel developer       | Engineer building a multi-tenant SaaS application on Laravel 13+ that must satisfy SOC2/GDPR auditing and tenant isolation requirements.                    | A way to express "who is acting, in what capacity, on which device" through Laravel's standard auth surface, without writing the contextual layer from scratch.       |
| IAM ecosystem package maintainer   | Engineer building an MFA, SSO, authorization, or audit-logging package that needs a stable contextual auth layer to integrate against.                       | A contract-based contextual auth foundation they can depend on without inheriting opinionated domain models or pulling in unrelated transitive dependencies.           |

**Primary user:** Enterprise Laravel developer.

---

## Goals

- Developers can adopt contextual (Identity / Principal / Device) authentication on Laravel 13+ using the standard `Auth` facade, `auth` middleware, and Blade directives without modifying framework code.
- Developers can use the package in either a 2D model (Identity = Principal) or a 3D model (Identity → Principal → Organization) within the same application via different guards.
- The package fires all six standard Laravel authentication events (Attempting, Validated, Login, Logout, Failed, Authenticated) with the parameters Laravel expects, so existing event listeners continue to work unchanged.
- The package fires custom contextual lifecycle events (PrincipalAssigned, DeviceAuthenticated, Refreshed) at well-defined points so consumers can hook contextual behaviour without monkey-patching.
- The package has zero hard runtime dependencies on other `sinemacula` packages and can be installed and used standalone.
- Published code passes PHPStan level 8 strict and achieves at least 90% line coverage on guards, user providers, and the auth manager.

## Non-Goals

- Not replacing Laravel's `SessionGuard` for stateful web authentication; this package is stateless-only.
- Not providing multi-factor authentication, single sign-on, role/permission authorization, or audit logging — those belong to sibling packages in the IAM ecosystem.
- Not shipping opinionated Identity, Principal, or Organization Eloquent models; those are the consuming application's concern.
- Not attempting to be a complete IAM system on its own — the package delivers contextual auth primitives only.
- Not providing password reset, email verification, or registration flows — those remain application-level concerns.

---

## Problem

**User problem:** Laravel's default authentication answers a single question: "is this user logged in?". Enterprise and multi-tenant applications need to answer three questions simultaneously — *who* is authenticated, *in what capacity* are they acting, and *on which device*. Developers solving this today either write the contextual layer from scratch (expensive and error-prone), bolt custom logic onto Laravel's defaults (inconsistent across teams and projects), or adopt opinionated starter kits that lock them into specific tenancy or authorization patterns. None of these approaches survive a SOC2 or GDPR audit cleanly.

**Business problem:** Enterprise SaaS customers require contextual auth for compliance auditing, tenant isolation, and incident forensics. Without a reusable foundation, every Laravel-based SaaS team rebuilds this layer, producing inconsistent solutions, duplicated maintenance burden, and elevated audit risk. The IAM ecosystem (MFA, SSO, authorization, audit log) cannot be built on a stable foundation if the auth layer below it is bespoke per project.

**Current state:** Developers reach for Laravel's `SessionGuard` or `TokenGuard`, then layer custom middleware, custom user resolvers, and custom event listeners on top to track tenant context and device sessions. Other developers adopt large opinionated packages such as multi-tenancy frameworks that bundle auth with storage, routing, and migration assumptions. A third group writes entirely bespoke guards. None of these paths produce a contextual auth layer that other packages (MFA, SSO, authorization, audit log) can integrate against without coupling.

**Evidence:** No prior spike or problem-map artifacts exist. The need was captured directly from architectural discussion in the conversation that initiated this PRD; see the Traceability section for the note on Blueprint phases skipped.

---

## Proposed Solution

A consuming Laravel developer installs `sinemacula/laravel-authentication` via Composer, publishes its config and migration, and chooses one of two adoption paths:

1. **Simple (2D) adoption.** The developer points the package's stateless guard at their existing user model. `Auth::user()` returns the user as both identity and principal. `Auth::device()` returns the current device record. The developer gets device tracking, JWT and HTTP Basic auth, refresh token support, and contextual events with no further work.

2. **Contextual (3D) adoption.** The developer implements the package's contracts on their own Identity, Principal, and Organization models, wires up a principal resolver that knows how to look up "principal X for identity Y in organization Z", and configures a guard. `Auth::user()` continues to return the identity for backward compatibility, while extended methods (`Auth::principal()`, `Auth::organization()`, `Auth::scope()`, `Auth::isInternal()`, `Auth::isExternal()`, `Auth::device()`) expose the contextual state. Both 2D and 3D guards can coexist in the same application on different routes.

Throughout, every standard Laravel authentication touchpoint — `Auth::check()`, `Auth::user()`, `Auth::id()`, `auth` middleware, `@auth` Blade directive, all six standard auth events — continues to behave as Laravel developers expect. Custom contextual events fire alongside the standard events for consumers who need to react to principal assignment, device authentication, or token refresh.

### Key Capabilities

- Developer can authenticate a request with a JWT bearer token and receive both identity and principal context in return.
- Developer can authenticate a request with HTTP Basic credentials and receive both identity and principal context in return.
- Developer can refresh an authenticated session using a refresh token tied to a specific device record.
- Developer can attach device tracking (operating system, last login timestamp, refresh credential) to any authenticatable model in their application via a polymorphic relationship.
- Developer can use the standard `Auth` facade and `auth` middleware unchanged while gaining contextual methods on the same facade.
- Developer can listen to both Laravel's six standard auth events and three custom contextual events using Laravel's standard event dispatcher.
- Developer can scope a principal to an organization and ask whether that principal is internal or external to the organization.
- Developer can override the shipped Device model and the device table name through config to fit their domain.
- Developer can implement the package's contracts on their own models without inheriting any base class beyond what they choose.
- Developer can install the package without it pulling in any other `sinemacula` IAM package.

---

## Requirements

### Must Have (P0)

- **Stateless JWT guard:** Developer can configure a guard that authenticates requests via a JWT bearer token and exposes the resolved identity, principal, and device through the `Auth` facade.
  - **Acceptance criteria:** Given a valid JWT in the `Authorization: Bearer` header, `Auth::check()` returns `true`, `Auth::user()` returns the identity model, `Auth::id()` returns its key, `Auth::principal()` returns the principal, and `Auth::device()` returns the device record. Given an invalid, expired, or missing token, `Auth::check()` returns `false` and `Auth::user()` returns `null`.

- **Stateless Basic guard:** Developer can configure a guard that authenticates requests via HTTP Basic credentials and exposes identity, principal, and device.
  - **Acceptance criteria:** Given a valid `Authorization: Basic` header whose credentials match an existing identity, `Auth::check()` returns `true` and the same accessor methods listed above return the resolved values. Given invalid credentials, `Auth::check()` returns `false`. Credential validation completes in constant time regardless of whether the supplied identifier exists, verified via the validation path consistently invoking Laravel's timing-safe comparison helper.

- **Refresh token flow:** Developer can exchange a refresh credential bound to a device for a new authenticated session without re-supplying primary credentials.
  - **Acceptance criteria:** Given a valid refresh credential for an existing device, the package issues a new access token, updates the device's last-login timestamp, fires a `Refreshed` event, and continues to return the same identity and principal. Given an invalid or revoked refresh credential, the refresh attempt fails and no new session is issued.

- **Laravel `Guard` contract compliance:** Developer can use the package's guards anywhere Laravel expects an instance of `Illuminate\Contracts\Auth\Guard`.
  - **Acceptance criteria:** Each shipped guard implements every method on `Illuminate\Contracts\Auth\Guard` (`check`, `guest`, `user`, `id`, `validate`, `hasUser`, `setUser`) and passes Laravel's published contract expectations in an integration test that uses the standard `Auth` facade and `auth` middleware against the package guards without modification.

- **Standard Laravel auth events:** Developer can listen to all six of Laravel's standard authentication events and receive them with the parameters Laravel's first-party guards emit.
  - **Acceptance criteria:** A successful authentication emits `Attempting`, `Validated`, `Login`, and `Authenticated` in the order Laravel emits them. A failed authentication emits `Attempting` and `Failed`. A logout emits `Logout`. Each event payload contains the guard name and the resolved authenticatable in the same shape Laravel's first-party guards use, verified by an integration test that registers listeners through Laravel's standard event dispatcher.

- **Custom contextual events:** Developer can listen to package-specific events that fire at contextual lifecycle points distinct from the standard auth events.
  - **Acceptance criteria:** A successful authentication that resolves a principal emits a `PrincipalAssigned` event carrying the identity and the principal. A successful authentication that binds a device emits a `DeviceAuthenticated` event carrying the device record. A successful refresh emits a `Refreshed` event. Each event is dispatched through Laravel's standard event dispatcher and is observable by listeners registered via `Event::listen`.

- **Contextual `Auth` facade methods:** Developer can call contextual accessors on the `Auth` facade in addition to its standard methods.
  - **Acceptance criteria:** When a request is authenticated through a package guard, calling `Auth::principal()`, `Auth::device()`, `Auth::organization()`, `Auth::scope()`, `Auth::isInternal()`, and `Auth::isExternal()` on the `Auth` facade returns the corresponding contextual values. When the request is unauthenticated, the same methods return `null` (or `false` for the boolean accessors) without throwing.

- **Principal resolver contract:** Developer can implement a principal resolver for their own identity and principal models without writing custom guard code.
  - **Acceptance criteria:** The package exposes a documented contract for principal resolution. A consumer providing an implementation of that contract through the service container receives that implementation when a guard authenticates an identity, and the resolver's return value is exposed via `Auth::principal()`. No domain-specific query, model, or table name is hard-coded inside the guard.

- **Polymorphic device tracking:** Developer can attach device tracking to any authenticatable model in their application — including users, guests, and admins — without subclassing.
  - **Acceptance criteria:** The shipped device migration creates a `devices` table with `authenticatable_type` and `authenticatable_id` columns and a ULID primary key. A device record can reference any Eloquent model the consumer designates as authenticatable, and the relationship resolves correctly through Laravel's polymorphic morph map.

- **Configurable Device model and table names:** Developer can override the shipped Device model class and any table name introduced by the package through configuration.
  - **Acceptance criteria:** Setting a custom Device class in the package config causes guards and the shipped relationships to resolve devices through the custom class. Setting a custom table name in config causes the shipped migration and Eloquent model to use that table name. Both overrides are verified by tests that swap defaults and observe the swap take effect.

- **Standalone installability:** Developer can install the package via Composer without it pulling in any other `sinemacula/laravel-*` IAM package as a runtime dependency.
  - **Acceptance criteria:** The published `composer.json` declares zero `require` entries for `sinemacula/laravel-mfa`, `sinemacula/laravel-sso`, `sinemacula/laravel-authorization`, `sinemacula/laravel-audit-log`, or `sinemacula/laravel-iam`. A clean Laravel 13 application can install the package and run its test suite without any of those packages being present in the vendor tree.

- **Coexistence of 2D and 3D guards:** Developer can configure both a simple 2D guard (Identity = Principal) and a contextual 3D guard (Identity → Principal → Organization) in the same Laravel application.
  - **Acceptance criteria:** A test application configures one route protected by a 2D guard and another protected by a 3D guard. Authenticating against the 2D route exposes identity and principal as the same model; authenticating against the 3D route exposes a principal and organization distinct from the identity. Both routes return correct results in the same test run.

### Should Have (P1)

- **Migration safety check:** Developer can detect and resolve naming collisions between the shipped device migration and pre-existing tables in their application.
  - **Acceptance criteria:** Running the shipped migration against a database that already contains a table with the configured device table name surfaces a clear, actionable error message before the migration mutates state.

- **Documented adoption guide:** Developer can read a step-by-step guide that walks them from a fresh Laravel 13 install to an authenticated request using either the 2D or 3D model.
  - **Acceptance criteria:** The published README contains an installation section, a configuration section, and at least one worked example for each of the 2D and 3D adoption paths. A new developer following the guide on a fresh Laravel 13 application reaches an authenticated `Auth::check() === true` state without consulting source code.

- **Internal vs external principal helper:** Developer can ask whether a principal is internal or external to its current organization through a single method call.
  - **Acceptance criteria:** `Auth::isInternal()` returns `true` when the resolved principal is marked internal to its organization and `false` otherwise. `Auth::isExternal()` returns the inverse. Both methods return `false` when no principal is resolved.

### Nice to Have (P2)

- **Test helpers:** Developer can authenticate a fake identity, principal, device, and organization in feature tests through helper methods analogous to Laravel's `actingAs`.
- **Artisan command for issuing tokens:** Developer can issue a JWT for an identity from the command line for local development and debugging.

---

## Success Criteria

| Metric                                                                                      | Baseline                | Target                                                                                                           | How Measured                                                                                                                                       |
|---------------------------------------------------------------------------------------------|-------------------------|------------------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------|
| Compatibility with Laravel 13 standard auth surface                                         | N/A — new capability    | 100% of `Auth::check`, `Auth::user`, `Auth::id`, `auth` middleware, `@auth` directive, and standard event tests pass against the package guards | Integration test suite that exercises each surface through Laravel's standard facades and middleware against a package-configured guard            |
| Standard Laravel auth events emitted                                                        | N/A — new capability    | All 6 events (Attempting, Validated, Login, Logout, Failed, Authenticated) fire with expected payloads          | Event-listener integration tests asserting event class, order, and payload shape per authentication path                                           |
| Custom contextual events emitted                                                            | N/A — new capability    | All 3 events (PrincipalAssigned, DeviceAuthenticated, Refreshed) fire at the documented lifecycle points        | Event-listener integration tests asserting event class and payload at each lifecycle point                                                         |
| Hard runtime dependencies on other `sinemacula` IAM packages                                | N/A — new capability    | 0                                                                                                                | Inspection of the published `composer.json` `require` block plus a clean-install integration test                                                  |
| Static analysis cleanliness                                                                 | N/A — new capability    | PHPStan level 8 strict reports zero errors on `src/`                                                             | `composer check` output in CI                                                                                                                      |
| Test coverage on guards, user providers, and the auth manager                               | N/A — new capability    | At least 90% line coverage on those components                                                                   | `composer test-coverage` clover report aggregated for the relevant namespaces                                                                      |
| Developer time-to-first-authenticated-request on a fresh Laravel 13 application following the README | N/A — new capability | A developer can reach `Auth::check() === true` by following only the README, without reading package source     | Manual walkthrough by a developer who has not contributed to the package, recorded as a release-gate check before tagging v1.0.0                  |

---

## Dependencies

- PHP 8.3 or later.
- Laravel 13 or later (Illuminate auth, events, and contracts).
- A stateless authentication mechanism available to the consuming application — either a JWT issuance/verification path or HTTP Basic credentials over TLS.
- Composer-installable package distribution (Packagist after the monorepo split; path repository inside the `laravel-iam` monorepo until then).

---

## Assumptions

- Consumers are building stateless APIs or stateless portions of applications; session-backed web auth remains served by Laravel's `SessionGuard`.
- Consumers control their own Identity, Principal, and Organization models and are willing to implement the package's contracts on those models.
- Laravel 13's `Illuminate\Contracts\Auth\Guard` contract surface and standard auth event signatures remain stable across patch and minor releases.
- Consumers using the 3D model can supply or build a principal resolver that knows how to look up a principal for an identity within an organization.
- The `firebase/php-jwt`-class of stateless token mechanisms is acceptable to consumers as a runtime dependency for the JWT path.

---

## Risks

| Risk                                                                                                       | Impact                                                                                                                                              | Likelihood | Mitigation                                                                                                                                                                                              |
|------------------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------|------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Laravel core auth contract or event signatures change in a minor release                                   | Package breaks against newer Laravel without warning; consumers cannot upgrade Laravel cleanly                                                      | Low        | CI matrix tests against the latest Laravel 13 minor on every push; consumer-facing contract usage is covered by integration tests so a contract shift fails CI immediately.                              |
| Consumers misunderstand the Identity vs Principal distinction and conflate the two                        | Misuse of the contextual API in production, leading to incorrect tenant isolation or audit trails                                                   | Medium     | README leads with the conceptual model and a worked 2D example before introducing 3D; the simple 2D path is supported as a first-class adoption mode so misunderstanding does not cause silent breakage. |
| Polymorphic `authenticatable_type` lookups on the device table degrade at scale                            | Slow auth on large device tables; user-visible latency on every authenticated request                                                                | Medium     | Ship the device migration with indexes on `(authenticatable_type, authenticatable_id)` and the refresh-credential lookup column; document expected query shape so consumers can monitor it.              |
| Timing attacks on credential validation reveal which identifiers exist                                    | Identity enumeration via response timing                                                                                                            | Low        | Credential validation paths consistently use Laravel's timing-safe comparison helper, even when the supplied identifier does not exist; covered by acceptance criteria on the Basic guard requirement.   |
| The shipped device migration collides with a `devices` table already present in a consumer's application | Migration fails or overwrites consumer data                                                                                                          | Medium     | Default table name is configurable, and the P1 migration safety check surfaces a clear error before the migration mutates state.                                                                         |
| Splitting the monorepo into a standalone `sinemacula/laravel-authentication` repository leaves consumers stranded   | Consumers cannot upgrade or cannot find the published package after the split                                                                       | Medium     | Document the migration path from monorepo path-repository to Packagist install in the README and the v1.0.0 release notes; treat the split as a release dependency rather than a stretch goal.           |

---

## Out of Scope

- Identity, User, Principal, and Organization Eloquent models — these are the consumer's domain.
- Multi-factor authentication — handled by `sinemacula/laravel-mfa`.
- Single sign-on drivers (OAuth, SAML, OIDC) — handled by `sinemacula/laravel-sso`.
- Roles, permissions, policies, and authorization gates — handled by `sinemacula/laravel-authorization`.
- Activity logging and audit trails — handled by `sinemacula/laravel-audit-log`.
- Password reset, email verification, and registration flows — application-level concerns.
- Stateful, session-backed web authentication — Laravel's `SessionGuard` remains the right tool.
- Rate limiting, throttling, and account lockout — application-level concerns.
- Token issuance UI, admin dashboards, or device management screens — application-level concerns.
- Cryptographic key management and rotation tooling — application-level concerns.

---

## Open Questions

- None. All scope decisions are captured in the Requirements, Non-Goals, and Out of Scope sections.

---

## Release Criteria

- All package tests pass under the CI matrix against Laravel 13 and PHP 8.3.
- PHPStan level 8 strict reports zero errors on `src/`.
- Test coverage on guards, user providers, and the auth manager is at least 90%.
- Integration tests verify that the standard `Auth` facade, `auth` middleware, `@auth` Blade directive, and all six standard Laravel auth events behave correctly against the package's guards.
- Integration tests verify that all three custom contextual events (`PrincipalAssigned`, `DeviceAuthenticated`, `Refreshed`) fire at the documented lifecycle points.
- A clean-install integration test confirms that the package installs into a fresh Laravel 13 application without pulling in any other `sinemacula/laravel-*` IAM package.
- The README documents installation, configuration, both the 2D and 3D adoption paths, and the migration path from the `laravel-iam` monorepo to the standalone `sinemacula/laravel-authentication` repository.
- The package is extracted from the `laravel-iam` monorepo into a standalone repository at `sinemacula/laravel-authentication` and published to Packagist. Until the monorepo reaches v1.0.0 and the split completes, the package is consumed via a path repository from the monorepo; the split itself is a hard release dependency for v1.0.0 of the standalone package.

---

## Traceability

| Artifact             | Path                                                                                                                                                                       |
|----------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Intake Brief         | User-provided spec (no prioritization artifact — Blueprint workflow skipped intake/discover/problem-map/prioritize phases; spec derived from architectural discussion in conversation) |
| Relevant Spikes      | None — Blueprint discover phase skipped                                                                                                                                    |
| Problem Map Entry    | None — Blueprint problem-map phase skipped                                                                                                                                 |
| Prioritization Entry | None — Blueprint prioritize phase skipped                                                                                                                                  |

---

## References

- Traces to: User-provided spec for the `laravel-iam` ecosystem (PRD 01 of 6).
- Sibling PRDs (forthcoming in this batch): `02-laravel-mfa.md`, `03-laravel-sso.md`, `04-laravel-authorization.md`, `05-laravel-audit-log.md`, `06-laravel-iam.md`.
- Monorepo: `/Users/ben/Projects/Sine Macula/Repositories/laravel-iam` (source of truth until the post-v1.0.0 split).
