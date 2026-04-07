# PRD: 05 Laravel Audit Log

An event-driven audit logging package for Laravel that captures authentication and arbitrary activity events through a
pluggable, storage-agnostic provider contract.

---

## Governance

| Field     | Value                                                                      |
|-----------|----------------------------------------------------------------------------|
| Created   | 2026-04-05                                                                 |
| Status    | draft                                                                      |
| Owned by  | Sine Macula — laravel-iam ecosystem                                        |
| Traces to | User-provided spec (no prioritization artifact — see Traceability section) |

---

## Overview

Laravel applications routinely need auditable trails of authentication and authorization events to satisfy compliance
frameworks (SOC2, GDPR, HIPAA, PCI) and to support incident investigation. Today, developers either bolt together custom
listeners against Laravel's auth events, repurpose general-purpose activity loggers that lack auth-specific context, or
scatter logging calls through their auth flows where edge cases are easy to miss. The result is inconsistent audit
coverage across services and wasted engineering effort rebuilding the same plumbing on every project.

`sinemacula/laravel-audit-log` solves this by providing a thin, contracts-first audit framework focused on
authentication events but extensible to arbitrary activities. It auto-discovers Laravel's standard authentication events
and dispatches structured activity records (type, actor, optional entity, metadata, count) through a pluggable provider.
Storage is intentionally not prescribed: v1 ships contracts plus a working default driver that writes to Laravel's log
facade, allowing developers to start capturing data immediately and graduate to a persistent provider on their own
schedule.

This package is being developed inside the `laravel-iam` monorepo alongside five sibling packages (
laravel-authentication, laravel-mfa, laravel-sso, laravel-authorization, and the laravel-iam umbrella). After v1.0.0 is
complete, it will be extracted to a standalone repository at `sinemacula/laravel-audit-log`. The package must remain
fully standalone and must not depend on `sinemacula/laravel-authentication` or any other ecosystem package — it must
work with any Laravel auth system (Sanctum, Passport, SessionGuard, custom guards). v1 ships contracts plus the log
driver only; a default Eloquent provider may follow in a later release once usage patterns are clearer.

---

## Target Users

| Persona                           | Description                                                                                                        | Key Need                                                                                                       |
|-----------------------------------|--------------------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------|
| Security engineer                 | Responsible for compliance posture (SOC2, GDPR, HIPAA, PCI) on a Laravel application                               | A consistent, complete authentication audit trail that can be exported, retained, and reviewed during audits   |
| Enterprise Laravel developer      | Building a production Laravel app that must answer "who accessed what, when, and from where" questions             | A drop-in audit framework that captures auth events without requiring a bespoke logging layer                  |
| Developer debugging an auth issue | Investigating intermittent or environment-specific authentication problems in development or staging               | Visibility into the full auth lifecycle (attempts, validation, login, logout, failures) without modifying code |
| Package maintainer (laravel-iam)  | Building higher-level ecosystem packages that need to emit structured audit events without forcing storage choices | A neutral activity contract they can target so consumers retain full control over persistence                  |

**Primary user:** Enterprise Laravel developer.

---

## Goals

- Developers can install the package and immediately capture all six standard Laravel auth events (Attempting,
  Validated, Login, Logout, Failed, Authenticated) without writing listener code.
- Developers can use the package with any Laravel auth system (Sanctum, Passport, SessionGuard,
  `sinemacula/laravel-authentication`, or a custom guard) without modification.
- Developers can ship to production with zero storage lock-in by implementing a single provider contract for their
  chosen storage layer.
- Developers can run the package out of the box with no configuration and have activities visible via Laravel's log
  facade.
- Developers can selectively disable individual auth event listeners through configuration to manage overhead under high
  traffic.
- Developers can log arbitrary activities (not only auth events) through a single facade entry point.
- The package passes PHPStan level 8 strict and ships with at least 90% test coverage on the activity manager and
  listener classes.

## Non-Goals

- Not a general-purpose activity log — the focus is authentication and authorization activities, even though arbitrary
  activities are supported.
- Not shipping a database schema or migration in v1 — storage is the consumer's choice.
- Not competing with Spatie's `activitylog` for non-auth activities.
- Not a log analytics, search, or visualization tool.
- Not providing a UI for viewing activities.
- Not enforcing or shipping a retention policy.
- Not providing real-time alerting on activities.

---

## Problem

**User problem:** Laravel ships no first-party audit logging for authentication events. Developers needing an audit
trail either write custom listeners (which drift across codebases and miss edge cases), adopt a generic activity logger
that lacks auth-specific semantics, or sprinkle logging calls through their auth flow (which is brittle and easy to
forget on new code paths). Investigations and audits then become a manual exercise of correlating unstructured
application logs.

**Business problem:** Compliance frameworks (SOC2, GDPR, HIPAA, PCI) require demonstrable audit trails for
authentication events including successes, failures, logout, and credential validation. Engineering teams repeatedly
reinvent the same logging plumbing on each project, burning hours that should be spent on product work. Inconsistent
audit logs across services make security incident investigation slower and more expensive, and gaps in coverage can
result in failed audits or remediation findings.

**Current state:** Developers commonly do one of: (1) install Spatie's `activitylog` and manually wire it into auth
flows; (2) write their own event listener classes against Laravel's auth events with project-specific persistence; (3)
rely on free-form application logs and `tail`/`grep` during investigations. None of these approaches provide a
consistent, reusable, auth-aware structure across projects.

**Evidence:** User-provided spec derived from architectural discussion in conversation. No spike or problem map artifact
exists for this PRD.

---

## Proposed Solution

After installing the package, a developer publishes an optional config file (or skips it entirely and accepts defaults),
and authentication activities begin flowing through the package automatically. Out of the box, activities are written to
Laravel's standard log facade, so the developer sees structured audit lines in their existing log destination
immediately — useful in development and as a baseline in production until a real provider is configured.

When the developer is ready to persist activities for compliance or investigation purposes, they implement a single
provider contract that receives a structured activity object (type code, actor identity, optional entity reference,
metadata payload, occurrence count) and decides how and where to store it. They register the provider through the
package's binding and the package switches over without any change to listeners or call sites. The same provider also
handles arbitrary application-level activities that the developer logs through the package's facade — for example "user
X viewed post Y" — with optional metadata and count increments to consolidate repeated events.

The package's identity resolution is also pluggable. By default, the package does not assume a specific authentication
system; it returns no actor identity unless one is explicitly passed at the call site. Higher-level packages (such as
`sinemacula/laravel-iam`) can register a custom identity resolver that delegates to their own auth context, but the
audit log package never depends on them.

### Key Capabilities

- Developer can capture authentication-related activities (login, logout, credential validation, failed authentication,
  principal assignment, token refresh) automatically by installing the package, with no listener code required.
- Developer can log arbitrary activities through a facade by passing an activity type, optional entity, and metadata
  payload.
- Developer can implement a single contract to persist activities to any storage of their choice (database, log files,
  external service) without forcing a package-level choice.
- Developer can run the package with no configuration and have activities written to Laravel's log facade.
- Developer can choose a no-op provider to disable persistence entirely while leaving the rest of the package wired up.
- Developer can define their own activity taxonomy by implementing the activity enum contract and ship it alongside or
  instead of the bundled defaults.
- Developer can override the actor identity for a specific log call when the current authentication context does not
  apply (e.g., system jobs, impersonation).
- Developer can selectively enable or disable each authentication listener through configuration.
- Developer can extend or replace the bundled default authentication activity enum.
- Developer can plug in a custom identity resolver to integrate with their authentication system of choice.
- Developer can attach arbitrary metadata to any activity record.
- Developer can record an occurrence count on an activity (e.g., "viewed five times") instead of creating duplicate
  records.
- Developer can associate any activity with an optional entity (e.g., "user X viewed post Y").

---

## Requirements

### Must Have (P0)

- **Auto-capture of standard Laravel auth events:** Developer can install the package and have all six standard Laravel
  auth events captured automatically.
  - **Acceptance criteria:** With the default configuration, dispatching each of `Illuminate\Auth\Events\Attempting`,
      `Validated`, `Login`, `Logout`, `Failed`, and `Authenticated` results in a corresponding activity being delivered
      to the registered provider, verified by integration tests against a fresh Laravel install.

- **Pluggable activity provider contract:** Developer can persist activities to any storage by implementing a single
  provider contract.
  - **Acceptance criteria:** A test-double provider implementing the contract receives a structured activity object
      containing at minimum: activity type code, actor (nullable), entity (nullable), metadata (array), and occurrence
      count. Swapping providers requires no changes to listener or call-site code.

- **Default no-op provider:** Developer can run the package with persistence disabled.
  - **Acceptance criteria:** Selecting the no-op provider in configuration causes no activity to be persisted while
      listeners still execute without error, verified by unit test.

- **Default log-facade provider:** Developer can run the package with no configuration and see activities in their
  application logs.
  - **Acceptance criteria:** On a fresh install with no configuration changes, dispatching any captured auth event
      produces a structured log entry through Laravel's log facade, verified by integration test asserting against the
      log writer.

- **Default authentication activity taxonomy:** Developer can use a bundled enum covering the standard authentication
  activity types without defining their own.
  - **Acceptance criteria:** The package ships an activity enum that includes at minimum: LOGGED_IN, LOGGED_OUT,
      CREDENTIALS_VALIDATED, FAILED_AUTHENTICATION, PRINCIPAL_ASSIGNED, TOKEN_REFRESHED, all addressable by name and
      integer code.

- **Custom activity enum support:** Developer can define their own activity types alongside or instead of the bundled
  defaults.
  - **Acceptance criteria:** A consumer can implement the activity enum contract with a custom set of types and pass
      instances of it to the facade; the provider receives the custom type code unchanged, verified by unit test.

- **Facade for arbitrary activity logging:** Developer can log non-auth activities through a single facade entry point.
  - **Acceptance criteria:** A facade method accepts an activity type, optional entity, and metadata, and routes the
      resulting activity to the configured provider, verified by unit test.

- **Actor override at call site:** Developer can override the actor identity for an individual log call.
  - **Acceptance criteria:** A facade call with an explicit actor argument results in the provider receiving that
      actor instead of the value returned by the identity resolver, verified by unit test.

- **Pluggable identity resolver contract:** Developer can integrate the package with any auth system by implementing an
  identity resolver.
  - **Acceptance criteria:** The package exposes a resolver contract; the default implementation returns null; binding
      a custom implementation causes all listeners and facade calls without an explicit actor to use the custom
      resolver's value, verified by unit test.

- **Per-listener configuration toggles:** Developer can enable or disable each authentication listener independently
  through configuration.
  - **Acceptance criteria:** Disabling a listener in the published config prevents that listener from being
      registered; the corresponding auth event no longer produces an activity, verified by integration test.

- **Standalone — no ecosystem dependencies:** Developer can install and use the package without any other Sine Macula
  package.
  - **Acceptance criteria:** `composer.json` declares no `require` entries against any `sinemacula/laravel-*` package;
      the package's tests run successfully against a Laravel skeleton with no other Sine Macula packages installed.

- **Metadata, entity, and count support on activities:** Developer can record additional context on every activity.
  - **Acceptance criteria:** The activity object exposes metadata (array), entity (nullable identifier or model
      reference), and occurrence count (integer, default 1) fields, all settable through the facade and visible to
      providers, verified by unit test.

- **PHPStan level 8 strict and PSR-12 clean:** Developer can rely on the package passing the project's static analysis
  and style gates.
  - **Acceptance criteria:** `composer check` exits clean against PHPStan level 8 strict, PHP-CS-Fixer, and
      CodeSniffer rules.

### Should Have (P1)

- **Documented best practices for sensitive metadata:** Developer can find guidance on scrubbing sensitive data before
  logging.
  - **Acceptance criteria:** README and reference documentation include a dedicated section on metadata hygiene and
      PII scrubbing recommendations.

- **Reference provider examples:** Developer can find example provider implementations for common storage targets.
  - **Acceptance criteria:** Documentation includes worked examples of a database-backed provider and an
      external-service-backed provider, including edge cases such as null actors.

- **Auto-discovery integration:** Developer does not have to manually register the service provider in modern Laravel
  applications.
  - **Acceptance criteria:** `composer.json` declares Laravel package auto-discovery for the service provider and
      facade; installation in a fresh Laravel app requires no manual config.

### Nice to Have (P2)

- **Test harness for provider implementers:** Developer can validate a custom provider against a shared contract test
  suite.
- **Future Eloquent provider:** A bundled database-backed provider may ship in a later release once consumer usage
  patterns are clearer (out of scope for v1).

---

## Success Criteria

| Metric                                                                     | Baseline             | Target                                                                                                 | How Measured                                                                           |
|----------------------------------------------------------------------------|----------------------|--------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------|
| Standard Laravel auth events captured by default                           | N/A — new capability | All 6 events (Attempting, Validated, Login, Logout, Failed, Authenticated) captured on a fresh install | Integration test suite asserting one activity dispatched per event with default config |
| Test coverage on activity manager and listener classes                     | N/A — new capability | >= 90% line coverage                                                                                   | Clover coverage report from `composer test-coverage`                                   |
| PHPStan level 8 strict pass rate                                           | N/A — new package    | 100% (zero errors)                                                                                     | `composer check` output                                                                |
| Out-of-the-box install requires no configuration                           | N/A — new capability | Zero config files, zero env vars required to capture activities to the log facade                      | Manual install on a fresh Laravel app, verified by README install walkthrough          |
| Hard runtime dependencies on other `sinemacula/*` packages                 | N/A — new package    | 0                                                                                                      | Inspection of `composer.json` `require` block                                          |
| Compatibility with Laravel auth drivers                                    | N/A — new package    | Verified working with SessionGuard, Sanctum, and Passport                                              | Integration tests against each driver in CI                                            |
| Consumer-implemented provider switchover requires no listener/call changes | N/A — new capability | Zero changes to listener or facade call sites required when swapping providers                         | Documented swap procedure and integration test demonstrating provider switch           |

---

## Dependencies

- PHP 8.3+
- Laravel 13+
- Laravel's event dispatcher (for auth event listeners)
- Laravel's logging facade (for the default log driver)

---

## Assumptions

- Laravel 13's authentication event names and payload shapes remain stable through the v1 lifecycle of this package.
- Consumers are willing to implement a provider contract themselves in production environments, in exchange for full
  control over storage.
- The default log-facade driver is acceptable for development and short-term production use while a persistent provider
  is built.
- The standard `Illuminate\Contracts\Auth\Authenticatable` interface is a sufficient abstraction for representing actors
  across the supported auth systems.
- Higher-level ecosystem packages (notably `sinemacula/laravel-iam`) will register a custom identity resolver to
  integrate with their auth context; this package does not need to know about them.

---

## Risks

| Risk                                                                                                                        | Impact                                                                                    | Likelihood | Mitigation                                                                                                                                                                    |
|-----------------------------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------|------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Contracts-only approach leaves developers without a working solution out of the box                                         | Slow adoption; developers bounce to alternatives that ship persistence by default         | Medium     | Ship the log-facade provider as a working default so the package is immediately useful with zero config; document the upgrade path to a persistent provider                   |
| Event listener overhead degrades performance under high authentication volume                                               | Increased request latency on auth-heavy endpoints; potential pressure on log destinations | Medium     | Allow each listener to be independently disabled via configuration; document the trade-offs in the README                                                                     |
| Sensitive data (passwords, tokens, PII) is recorded in metadata fields by mistake                                           | Compliance violation; breach exposure                                                     | Medium     | Document metadata hygiene best practices prominently; provide guidance on scrubbing in the README; default listeners must not include credential payloads in metadata         |
| Future Laravel auth event signature changes break listeners                                                                 | Listeners silently stop firing or throw on a Laravel upgrade                              | Low        | Pin compatibility to Laravel 13+; cover each listener with an integration test against the live Laravel event dispatcher; monitor Laravel release notes during upgrade cycles |
| Consumers implementing the provider contract miss edge cases (null actors, missing entities, exceptions during persistence) | Lost or malformed audit records; uncaught exceptions in the auth flow                     | Medium     | Ship a clear, narrow contract with documented null/exception semantics; provide reference provider examples; consider a contract test harness in P2                           |
| Package extraction from the monorepo to a standalone repository introduces hidden coupling to other ecosystem packages      | Extraction is delayed or requires breaking changes to consumers                           | Low        | Enforce zero ecosystem dependencies in `composer.json` from day one; CI verifies the package builds and tests pass without any other `sinemacula/*` package installed         |

---

## Out of Scope

- Persistent storage implementations (consumers implement their own provider for database, Elasticsearch, external
  services, etc.).
- Activity viewing or query UI.
- Log shipping or forwarding (consumers should use Laravel's log channel drivers for that).
- Non-auth activity logging as a primary product focus (consumers can log arbitrary activities, but the package is not
  positioned as a general activity logger).
- Real-time alerting based on captured activities.
- Retention policies, archival, or log rotation (consumers' provider implementations handle this).
- Compliance report generation.
- A bundled Eloquent provider in v1 (may ship in a later release once usage patterns are clearer).
- Any dependency on `sinemacula/laravel-authentication` or other ecosystem packages.
- A graphical or CLI tool for browsing activities.

---

## Open Questions

_None._

---

## Release Criteria

- All unit and integration tests pass (`composer test`).
- `composer check` exits clean (PHPStan level 8 strict, PHP-CS-Fixer, CodeSniffer).
- Test coverage on activity manager and listener classes is at or above 90%, measured by clover report.
- Integration tests verify each of the six standard Laravel auth events triggers the expected activity through the
  configured provider.
- Integration tests verify the package works against SessionGuard, Sanctum, and Passport.
- `composer.json` has zero `require` entries on any other `sinemacula/laravel-*` package.
- Default log-facade provider works on a fresh Laravel install with no configuration.
- README documents installation, configuration, the process of implementing a custom provider, and example usage.
- Reference documentation includes worked provider examples (database-backed and external-service-backed).
- README documents metadata hygiene and PII scrubbing best practices.
- Package is ready for extraction from the `laravel-iam` monorepo to a standalone repository at
  `sinemacula/laravel-audit-log` after v1.0.0 ships.

---

## Traceability

| Artifact             | Path                                                                                                                                                                                   |
|----------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Intake Brief         | User-provided spec (no prioritization artifact — Blueprint workflow skipped intake/discover/problem-map/prioritize phases; spec derived from architectural discussion in conversation) |
| Relevant Spikes      | None                                                                                                                                                                                   |
| Problem Map Entry    | None                                                                                                                                                                                   |
| Prioritization Entry | None                                                                                                                                                                                   |

---

## References

- Sibling PRDs in the laravel-iam monorepo: `01-laravel-authentication.md`, `02-laravel-mfa.md`, `03-laravel-sso.md`,
  `04-laravel-authorization.md`, `06-laravel-iam.md`
- Target standalone repository (post-extraction): `sinemacula/laravel-audit-log`
- Monorepo root: `/Users/ben/Projects/Sine Macula/Repositories/laravel-iam`
