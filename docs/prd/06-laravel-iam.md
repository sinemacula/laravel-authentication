# PRD: 06 Laravel IAM (Umbrella Package)

A bundled identity and access management solution for Laravel that brings five standalone IAM packages together under a single install with automatic integration glue and a unified entry point.

---

## Governance

| Field     | Value                                                                                       |
|-----------|---------------------------------------------------------------------------------------------|
| Created   | 2026-04-05                                                                                  |
| Status    | draft                                                                                       |
| Owned by  | Sine Macula                                                                                 |
| Traces to | User-provided spec — sinemacula/laravel-iam umbrella package (architectural discussion)     |

---

## Overview

Building an enterprise-grade Laravel application today requires a developer to assemble at least five separate auth-related concerns: contextual authentication, multi-factor authentication, single sign-on, authorization (RBAC and policies), and audit logging. Each concern is typically solved by a different vendor's package, with different conventions, configuration styles, upgrade cycles, and integration assumptions. The result is brittle glue code, inconsistent developer experience, and high evaluation cost for teams choosing a Laravel auth stack.

The `sinemacula/laravel-iam` package is the umbrella distribution for the Sine Macula IAM ecosystem. It bundles the five standalone packages — `laravel-authentication`, `laravel-mfa`, `laravel-sso`, `laravel-authorization`, and `laravel-audit-log` — at lock-step versions, wires them together with sensible integration defaults, and exposes a single unified `Iam::` facade as a clear entry point. Developers who want a complete IAM stack install one package and run one install command. Developers who want only one or two capabilities still use the individual sub-packages directly.

The entire ecosystem is being developed inside this `laravel-iam` monorepo (the current repository) first. The five sub-packages will be extracted into their own independent repositories once v1.0.0 is complete; the umbrella package will remain in this repository after the split and will require the sub-packages via Composer (Packagist). During pre-v1.0.0 monorepo development, sub-packages are referenced via Composer path repositories so they can be developed and tested together. **The repository split is a hard release dependency — the umbrella cannot ship v1.0.0 until the sub-packages have been extracted and published independently.** This umbrella package is the sixth and final PRD in the ecosystem; the prior five PRDs cover the standalone sub-packages.

---

## Target Users

| Persona                                  | Description                                                                                                                                                | Key Need                                                                                                                                |
|------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------|
| Enterprise Laravel developer (greenfield)| Engineer starting a new SaaS or enterprise Laravel project who needs a complete IAM solution from day one without manually integrating multiple packages    | A single install that produces a working contextual auth + MFA + SSO + authorization + audit log stack with no manual wiring             |
| Team lead evaluating Laravel auth        | Technical lead comparing Laravel auth solutions for a procurement or architectural decision and weighing single-vendor vs multi-vendor tradeoffs            | A single coherent product to evaluate, with one vendor, one support surface, one upgrade story, and one license to clear                 |
| Migrating developer                      | Developer moving an existing Laravel app off a legacy auth stack (Sanctum + Spatie permission + ad-hoc MFA + custom audit logging) to a unified replacement | A drop-in comprehensive replacement that covers all the existing concerns under one roof, with the option to adopt incrementally        |
| Incremental adopter                      | Developer on an existing project who already uses one Sine Macula sub-package and wants to add more without re-architecting                                 | The ability to start with the umbrella in an existing project, or to start with one sub-package and switch to the umbrella later, freely |

**Primary user:** Enterprise Laravel developer (greenfield).

---

## Goals

- Developer can install a single Composer package and obtain a working IAM stack covering authentication, MFA, SSO, authorization, and audit logging.
- Developer can complete first-time setup of all five sub-packages with one install command.
- Developer can use one unified facade as a single entry point to all IAM features without losing access to the individual sub-package facades.
- Developer can rely on cross-package integrations (MFA enforced on login, authorization resolving the current principal, audit log capturing events from all packages, principals being authorizable) working out of the box with zero manual wiring.
- Developer can opt out of any individual integration via configuration without uninstalling sub-packages.
- Developer can substitute their own implementation of any integration glue binding via the service container.
- Developer can adopt the umbrella incrementally in an existing project or use it as a batteries-included starting point in a new project.
- Developer can rely on lock-step semver guarantees: every umbrella release locks all sub-packages to a known-good combination.
- Developer can upgrade individual sub-packages independently within a minor version range without waiting for an umbrella release.

## Non-Goals

- Not replacing the standalone sub-packages — each remains independently installable and supported.
- Not adding new IAM functionality beyond integration glue and the unified entry point.
- Not preventing or discouraging customization of individual sub-packages.
- Not providing UI scaffolding, blade components, or front-end assets.
- Not coupling the sub-packages to each other — sub-packages remain free of any dependency on the umbrella or on one another.
- Not providing migration tooling from third-party auth packages (e.g. Spatie permission, Fortify).
- Not providing a self-hosted identity provider, admin dashboard, or end-user management UI.
- Not providing multi-repository coordination tooling — repository management is handled by `symplify/monorepo-builder` or equivalent.

---

## Problem

**User problem:** A Laravel developer building an enterprise application has to assemble at least five separate concerns — contextual authentication, MFA, SSO, authorization, and audit logging — from different vendors. Each package has its own configuration conventions, naming conventions, service container bindings, and lifecycle. Integrating them is error-prone manual wiring: developers must hook MFA into login events themselves, ensure authorization knows which principal to use, register listeners so the audit log captures cross-cutting events, and keep all five packages on compatible versions. This wiring is undocumented, easy to get wrong, and easy to break on upgrade.

**Business problem:** Enterprise procurement and technical evaluation are significantly harder when a single business capability (IAM) requires five separate vendor relationships, five separate licenses, five separate upgrade cycles, and five separate support surfaces. Teams either avoid the complexity by choosing a single weaker package, or pay the integration cost up front and inherit the maintenance burden. There is no single coherent Laravel IAM offering that can be evaluated, procured, and adopted as one product. This raises the bar for adopting any individual sub-package, even when it is the best choice for its concern.

**Current state:** Developers typically assemble Laravel Sanctum (or Passport) for authentication, Spatie laravel-permission for RBAC, Laravel Fortify or a hand-rolled solution for MFA, a custom or third-party SSO library, and either a third-party audit logging package or hand-rolled event listeners. Cross-cutting integrations (MFA on login, audit logging across packages, authorization knowing the current actor) are written by hand in each project, with no canonical pattern. Upgrades require coordinating five packages independently and re-validating the integration glue each time.

**Evidence:** N/A — this PRD was authored from a user-provided architectural specification rather than from a Blueprint discovery and prioritization workflow. The architectural rationale is captured in conversation between the package author and the AI agent, and in the per-sub-package PRDs (01-05) in this same directory.

---

## Proposed Solution

A developer building a new Laravel application runs `composer require sinemacula/laravel-iam`. A single artisan command — `php artisan iam:install` — publishes the configuration files for all five sub-packages, publishes their migrations in the correct order, and runs the migrations. The developer now has a working IAM stack: users can register and authenticate, MFA can be enrolled and enforced, SSO providers can be configured, roles and policies can be assigned, and an audit log captures every meaningful event.

The developer uses a single unified `Iam::` facade as the entry point: `Iam::auth()` returns the authentication manager, `Iam::mfa()` returns the MFA manager, and so on. The same instances are still accessible via the individual `Auth::`, `Mfa::`, `Sso::`, `Authorization::`, and `AuditLog::` facades — the unified facade is a convenience layer, not a replacement.

When the developer enables MFA on a user, MFA enforcement on login works automatically; no listener registration is needed. When the developer writes an authorization check, the authorization layer automatically resolves the current principal from the auth context. When any sub-package emits a domain event, the audit log captures it without manual subscription. A user model that uses the package's principal trait automatically satisfies the authorization layer's `Authorizable` contract.

Any integration the developer does not want — for example, automatic MFA enforcement on login, or automatic audit log capture for a specific event class — can be disabled via the `iam.php` config file. Any integration the developer wants to customize can be replaced by binding their own implementation in the service container, just like any other Laravel binding.

A team adopting the package incrementally can start with one sub-package (for example `laravel-authentication` only) and later switch to the umbrella without changing application code. Conversely, a team that starts with the umbrella can later strip down to a single sub-package by removing the umbrella and requiring only the sub-package they keep.

### Key Capabilities

- Single-command installation of the entire IAM stack.
- Single artisan command (`iam:install`) to publish and migrate all sub-package assets in the correct order.
- Unified `Iam::` facade as a single entry point that delegates to the underlying sub-package managers.
- Automatic cross-package integration: MFA enforcement on authentication, authorization resolves current principal, audit log captures cross-package events, principal trait satisfies authorizable contract.
- Per-integration opt-out via configuration.
- Per-integration override via service container binding.
- Lock-step semver: every umbrella release pins each sub-package to a known-good version.
- Independent sub-package upgrades within a minor version range.
- Backwards-compatible coexistence with direct use of any sub-package.
- Documented migration path between umbrella usage and individual sub-package usage in either direction.

---

## Requirements

### Must Have (P0)

- **Single-package install:** Developer can install the entire IAM stack via `composer require sinemacula/laravel-iam` with no further package requires.
  - **Acceptance criteria:** On a fresh Laravel 13 application with PHP 8.3+, running `composer require sinemacula/laravel-iam` resolves and installs all five sub-packages at lock-step versions and the application boots without error.

- **Single install command:** Developer can run one artisan command to publish and migrate all sub-package assets in the correct order.
  - **Acceptance criteria:** Running `php artisan iam:install` on a fresh Laravel 13 application publishes the config file for every sub-package, publishes the migrations for every sub-package, runs the migrations in dependency order, and exits with code 0. Re-running the command is idempotent and does not duplicate published files or migrations.

- **Unified facade:** Developer can access every sub-package's manager via a single unified facade without losing access to the individual facades.
  - **Acceptance criteria:** A unified `Iam::` facade exposes accessor methods for auth, MFA, SSO, authorization, and audit log. Each accessor returns the same singleton instance that the sub-package's own facade returns. Existing code using the sub-package facades continues to work unchanged.

- **Automatic MFA enforcement on auth:** Developer can rely on MFA being enforced on authentication events without manually wiring listeners.
  - **Acceptance criteria:** When both `laravel-authentication` and `laravel-mfa` are present (which is always true under the umbrella), the umbrella registers MFA enforcement on authentication events automatically. An integration test demonstrates that an MFA-enrolled user attempting to authenticate is challenged for MFA without any application-level configuration.

- **Authorization principal resolution:** Developer can rely on the authorization layer automatically resolving the current principal from the auth context.
  - **Acceptance criteria:** When both `laravel-authentication` and `laravel-authorization` are present, the umbrella binds an integration glue resolver such that authorization checks performed without an explicit principal resolve to the current authenticated principal from `laravel-authentication`. An integration test demonstrates this end-to-end.

- **Audit log capture across packages:** Developer can rely on audit log capturing meaningful events from all sub-packages without manual subscription.
  - **Acceptance criteria:** When `laravel-audit-log` is present alongside any of the other sub-packages, the umbrella registers listeners so that authentication events, MFA events, SSO events, and authorization events are recorded in the audit log without application-level wiring. An integration test demonstrates this for at least one event type per sub-package.

- **Audit log identity resolution:** Developer can rely on the audit log automatically attributing entries to the current identity from the auth context.
  - **Acceptance criteria:** When both `laravel-authentication` and `laravel-audit-log` are present, the umbrella binds an integration glue resolver such that audit log entries are attributed to the current identity from `laravel-authentication` without manual wiring. An integration test demonstrates this end-to-end.

- **Principal is authorizable:** Developer can rely on a model using the principal trait being usable in authorization checks without implementing the authorizable contract manually.
  - **Acceptance criteria:** A model that applies the principal trait from `laravel-authentication` automatically satisfies the `Authorizable` contract from `laravel-authorization` when both packages are present under the umbrella. An integration test exercises an authorization check against a model using only the principal trait.

- **Per-integration opt-out:** Developer can disable any individual integration glue without uninstalling the affected sub-package.
  - **Acceptance criteria:** The published `iam.php` config file contains an `integrations` section with a boolean flag for each integration glue (MFA enforcement, principal resolution, audit log capture, identity resolution, principal-as-authorizable). Setting any flag to `false` disables that specific integration without affecting other integrations or the underlying sub-packages. An integration test demonstrates each opt-out.

- **Per-integration override:** Developer can replace any integration glue implementation by binding their own implementation in the service container.
  - **Acceptance criteria:** Each integration glue binding is registered as a contract-bound service. Binding a different implementation in the application's service provider replaces the default for that integration, with no other effects. Documentation lists every contract that can be overridden.

- **Lock-step versioning:** Developer can rely on each umbrella version pinning every sub-package to a tested-compatible version.
  - **Acceptance criteria:** The umbrella's `composer.json` requires each sub-package at an explicit version constraint that is bumped in lock-step. The release process documentation specifies that any sub-package release requires re-tagging the umbrella, and any umbrella release re-locks all sub-packages.

- **Independent minor upgrades:** Developer can upgrade an individual sub-package within its minor version range without waiting for an umbrella release.
  - **Acceptance criteria:** The umbrella's version constraints on sub-packages are caret constraints (`^1.x`) so that minor and patch versions of any sub-package can be installed without bumping the umbrella. An integration test installs the umbrella, then upgrades one sub-package within the same minor range, and confirms the application still boots and the integration tests still pass.

- **Coordinated major bumps:** Developer can rely on coordinated major version bumps when any sub-package introduces a breaking change.
  - **Acceptance criteria:** The release process documentation specifies that a major version bump in any sub-package requires a coordinated major version bump of the umbrella that pins the new major. The constraint syntax in the umbrella's `composer.json` prevents an unsupported major from being installed transparently.

- **Coexistence with direct sub-package use:** Developer can use the umbrella in a project that also installs sub-packages directly without conflicts.
  - **Acceptance criteria:** Installing the umbrella in a project that already requires one or more sub-packages directly does not produce duplicate service provider registrations, duplicate migrations, or duplicate config files. An integration test installs `laravel-authentication` directly first, then adds the umbrella, and confirms the application boots and the integration tests still pass.

- **Repository split prerequisite:** Developer can install the v1.0.0 umbrella from Packagist with all five sub-packages also published to Packagist as independent repositories.
  - **Acceptance criteria:** Before tagging v1.0.0 of the umbrella, the five sub-packages exist as independent repositories on the source host and as independent packages on Packagist. The umbrella's `composer.json` references the sub-packages as Packagist dependencies (not as path repositories). A release dry-run from a clean checkout of an external project succeeds end-to-end without local path overrides.

- **Strict static analysis:** Developer can rely on the entire monorepo passing PHPStan level 8 strict.
  - **Acceptance criteria:** Running `composer check` at the monorepo root succeeds with zero PHPStan errors at level 8 strict, zero PHP-CS-Fixer errors, and zero CodeSniffer errors across the umbrella package and all five sub-packages.

### Should Have (P1)

- **Cross-package integration test suite:** Developer can rely on a dedicated integration test suite that exercises cross-package behaviour end-to-end.
  - **Acceptance criteria:** The umbrella package contains an `integration` test suite distinct from the unit test suite. The integration suite covers at least one end-to-end scenario per integration glue (MFA on login, authorization principal resolution, audit log capture, audit log identity resolution, principal-as-authorizable). The integration suite runs as part of `composer test`.

- **Install command status output:** Developer can see clear feedback while `iam:install` runs.
  - **Acceptance criteria:** The `iam:install` command prints a step-by-step status line for each phase (publish config, publish migrations, run migrations) per sub-package and prints a final summary indicating success or the first failure.

- **Documented incremental adoption path:** Developer can follow documentation explaining how to adopt the umbrella in a new project, in an existing project that uses one sub-package, or how to switch from the umbrella to a single sub-package.
  - **Acceptance criteria:** The README contains a dedicated section titled "Adoption paths" with at least three labelled scenarios: greenfield, incremental adoption, and umbrella-to-sub-package downgrade.

- **Documented release process:** Developer (or maintainer) can follow a documented release process for tagging the umbrella and the sub-packages.
  - **Acceptance criteria:** A `RELEASING.md` document at the monorepo root specifies how to bump versions, how lock-step versioning is enforced, how to coordinate sub-package releases, and how the post-split release process differs from the pre-split process.

- **Documented monorepo-to-split migration:** Developer (or maintainer) can follow a documented procedure for splitting the sub-packages out of the monorepo at v1.0.0.
  - **Acceptance criteria:** A `MIGRATION-SPLIT.md` document specifies the exact steps to extract each sub-package into its own repository, publish it to Packagist, and switch the umbrella's `composer.json` from path repositories to Packagist constraints.

### Nice to Have (P2)

- **Install command dry-run mode:** Developer can preview what `iam:install` would publish and migrate without applying changes.

- **Interactive install prompts:** Developer can be prompted to select which integrations to enable during `iam:install`.

- **Diagnostic command:** Developer can run `php artisan iam:doctor` to verify the installed configuration, detect missing integrations, and report sub-package version drift.

- **Sub-package version reporter:** Developer can run an artisan command to print the installed version of each sub-package and the umbrella.

---

## Success Criteria

| Metric                                                                                  | Baseline                  | Target                                                  | How Measured                                                                                                                              |
|-----------------------------------------------------------------------------------------|---------------------------|---------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------|
| Single-package install succeeds on a fresh Laravel 13 + PHP 8.3 application             | N/A — new capability      | 100% success on the supported matrix                    | Automated CI matrix that runs `composer require sinemacula/laravel-iam` against fresh skeleton apps for each supported PHP/Laravel pair    |
| `iam:install` produces a working stack on a fresh Laravel application                   | N/A — new capability      | 100% success, idempotent on re-run                      | Automated end-to-end CI job that runs `iam:install`, then `iam:install` a second time, then runs the integration test suite                |
| Cross-package integration glue works without manual wiring                              | N/A — new capability      | All P0 integration glue requirements pass               | Dedicated `integration` PHPUnit suite, run as part of `composer test`                                                                      |
| Static analysis cleanliness across the monorepo                                         | N/A — new capability      | Zero errors at PHPStan level 8 strict                   | `composer check` at the monorepo root in CI                                                                                                |
| Repository split executed before v1.0.0 tag                                             | Monorepo (current state)  | Five independent repos published to Packagist           | Manual release checklist verified during the v1.0.0 release cut                                                                            |
| Lock-step version constraints enforced                                                  | N/A — new capability      | Every umbrella release pins each sub-package explicitly | Pre-release CI check that fails the build if any sub-package constraint in the umbrella `composer.json` does not match the release matrix  |
| Independent minor upgrade of a sub-package keeps the umbrella green                     | N/A — new capability      | 100% pass rate                                          | CI matrix job that bumps a single sub-package within its caret range and re-runs the integration suite                                     |
| Coexistence with direct sub-package use does not double-register providers or migrations| N/A — new capability      | Zero duplicate registrations                            | Integration test that installs a sub-package directly, then installs the umbrella, then asserts uniqueness of providers and migrations    |

---

## Dependencies

- `sinemacula/laravel-authentication ^1.0` (PRD 01)
- `sinemacula/laravel-mfa ^1.0` (PRD 02)
- `sinemacula/laravel-sso ^1.0` (PRD 03)
- `sinemacula/laravel-authorization ^1.0` (PRD 04)
- `sinemacula/laravel-audit-log ^1.0` (PRD 05)
- PHP 8.3+
- Laravel 13+
- Monorepo build tooling (`symplify/monorepo-builder` or equivalent) for the pre-split development phase
- Packagist publication of all five sub-packages as a hard prerequisite to v1.0.0

---

## Assumptions

- Each of the five sub-packages will be released as standalone, independently installable Composer packages with no hard dependency on each other or on the umbrella.
- Each sub-package exposes the contracts (resolvers, listeners, integration points) needed for the umbrella to wire integrations without modifying sub-package internals.
- The integration glue can be expressed as service container bindings and event listeners only, without requiring sub-package source modifications.
- Lock-step versioning is acceptable to consumers as the default; consumers who need finer-grained control will use sub-packages directly.
- The monorepo-to-multi-repo split at v1.0.0 is operationally feasible with `symplify/monorepo-builder` or an equivalent splitter.
- Laravel 13's service provider lifecycle is sufficient to register integration glue at the right point in the application boot order.
- The unified `Iam::` facade can delegate to the same singleton manager instances as the per-sub-package facades, so there is no risk of state divergence between facades.
- Sub-package PRDs (01-05) define each sub-package's public surface; this PRD does not redefine that surface.

---

## Risks

| Risk                                                                                                          | Impact                                                                                                                       | Likelihood | Mitigation                                                                                                                                                                                                                              |
|---------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------|------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Lock-step versioning creates coordination overhead for the maintainer                                          | Slower release cadence; pressure to skip releases of small sub-package fixes                                                 | High       | Automate the release process via CI; document a release cadence; allow independent minor releases of sub-packages within their caret range so not every sub-package patch forces an umbrella release                                    |
| Breaking change in one sub-package forces a coordinated major bump of all five and the umbrella                | Disruption for consumers; large coordinated work for maintainer                                                              | Medium     | Treat sub-package contracts as part of the public API and gate them with PHPStan level 8 + RFCs; document breaking-change policy clearly; bundle multiple breaking changes into infrequent coordinated major releases                    |
| Integration glue breaks silently if a sub-package changes a contract without updating the umbrella             | Cross-package integration silently stops working; consumer test suites do not catch it                                      | Medium     | Cover every integration glue point with an integration test in the umbrella; run the umbrella integration suite in CI on every sub-package PR; treat integration test failures as release-blocking                                       |
| Developers mix the unified `Iam::` facade with per-sub-package facades inconsistently                          | Codebase inconsistency; harder code review; no functional bug                                                                | Low        | Document the unified facade as a convenience layer, not a replacement; explicitly state that mixing is supported; do not deprecate per-sub-package facades                                                                                |
| Circular dependencies emerge if integration glue is layered incorrectly                                        | Sub-packages cannot remain standalone; install order breaks                                                                  | Medium     | Enforce architectural rule: standalone packages cannot depend on the umbrella, on each other, or on integration glue; integration glue lives only in the umbrella package; CI lint checks sub-package `composer.json` for forbidden deps |
| `iam:install` command order is wrong and migrations fail on a fresh app                                        | First-run install fails; bad first impression                                                                                | Medium     | Define explicit migration order in the install command; cover with a CI end-to-end install test on a fresh Laravel skeleton; make the command idempotent so partial failures can be retried                                              |
| Repository split at v1.0.0 is more complex than expected and delays release                                    | v1.0.0 release slips; consumers waiting for stable release are blocked                                                       | Medium     | Treat the split as a P0 release criterion with its own dedicated migration document and dry-run; rehearse the split on a copy of the repo before the real release                                                                        |
| Pre-split path-repository setup leaks into post-split production `composer.json` and breaks Packagist install  | Consumers cannot install the published umbrella                                                                              | Medium     | Maintain a clear separation between dev composer config (with path repositories) and the published composer config; cover with a CI job that installs the published umbrella from a clean external checkout without any local overrides |
| Lock-step versioning surprises consumers who expected each sub-package to evolve independently                 | Consumer dissatisfaction; perception that the umbrella is restrictive                                                        | Low        | Document the lock-step model up front in the README; emphasise that consumers can always uninstall the umbrella and use sub-packages directly with finer-grained constraints                                                            |

---

## Out of Scope

- Any new IAM functionality beyond integration glue and the unified entry point. New auth, MFA, SSO, authorization, or audit log features must be added to the appropriate sub-package, not the umbrella.
- UI scaffolding, Blade components, Livewire components, Inertia components, or any other front-end assets.
- Admin dashboards or end-user-facing IAM management interfaces.
- Migration tools or compatibility shims for third-party Laravel auth packages (Spatie permission, Fortify, Sanctum-only stacks, Passport, etc.).
- A self-hosted identity provider, OIDC server, or SAML server.
- A starter kit or application template that builds on top of the umbrella (this could be a separate package).
- Multi-repository coordination tooling — this is delegated to `symplify/monorepo-builder` or an equivalent splitter.
- Any feature already covered by, or properly belonging to, one of the five sub-packages.
- Cross-version compatibility shims that allow mixing major versions of sub-packages (lock-step versioning is the explicit model).
- Changes to PHPStan level, code style, or qlty configuration without explicit maintainer approval.

---

## Open Questions

_None. All design questions for this PRD are resolved by the user-provided architectural specification._

---

## Release Criteria

- All five sub-package test suites pass on the supported PHP/Laravel matrix.
- The umbrella integration test suite passes, exercising at least one end-to-end scenario per integration glue point (MFA on login, authorization principal resolution, audit log capture, audit log identity resolution, principal-as-authorizable).
- `php artisan iam:install` succeeds end-to-end on a fresh Laravel 13 + PHP 8.3 application and is idempotent on re-run.
- PHPStan level 8 strict, PHP-CS-Fixer, and CodeSniffer all pass cleanly across the entire monorepo via `composer check`.
- All six packages (umbrella + five sub-packages) are publishable at the same version.
- The five sub-packages have been extracted from the monorepo into their own independent repositories and published to Packagist as a prerequisite to the v1.0.0 tag of the umbrella.
- The umbrella's `composer.json` references the sub-packages as Packagist dependencies in the published artifact (path repositories only used in the development checkout).
- A clean external checkout can install the published umbrella from Packagist without any local overrides.
- README documents the umbrella's role, installation, the unified `Iam::` facade, when to use the umbrella vs an individual sub-package, and the supported adoption paths (greenfield, incremental, downgrade).
- `RELEASING.md` documents the release process, lock-step versioning rules, and the difference between pre-split and post-split releases.
- `MIGRATION-SPLIT.md` documents the monorepo-to-multi-repo split procedure.
- Monorepo build tooling (`symplify/monorepo-builder` or equivalent) is in place and exercised in CI before the split.
- Coordinated v1.0.0 tags are applied to the umbrella and to all five sub-package repositories.

---

## Traceability

| Artifact             | Path                                                                                                                                                                                                  |
|----------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Intake Brief         | User-provided spec (no prioritization artifact — Blueprint workflow skipped intake/discover/problem-map/prioritize phases; spec derived from architectural discussion in conversation)                |
| Relevant Spikes      | N/A — no spike artifacts; architectural rationale captured in conversation and in PRDs 01-05 in this directory                                                                                        |
| Problem Map Entry    | N/A — Blueprint problem map phase not run                                                                                                                                                             |
| Prioritization Entry | N/A — Blueprint prioritization phase not run                                                                                                                                                          |
| Related PRDs         | `docs/prd/01-laravel-authentication.md`, `docs/prd/02-laravel-mfa.md`, `docs/prd/03-laravel-sso.md`, `docs/prd/04-laravel-authorization.md`, `docs/prd/05-laravel-audit-log.md`                                  |

---

## References

- Traces to: User-provided architectural specification for the `sinemacula/laravel-iam` umbrella package
- Sibling PRDs: `01-laravel-authentication.md`, `02-laravel-mfa.md`, `03-laravel-sso.md`, `04-laravel-authorization.md`, `05-laravel-audit-log.md` in this same directory
- Project conventions: `/Users/ben/Projects/Sine Macula/Repositories/laravel-iam/CLAUDE.md`
