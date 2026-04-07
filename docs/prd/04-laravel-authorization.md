# PRD: 04 Laravel Authorization

A standalone Laravel package that combines role-based access control with AWS IAM-style policy evaluation, enabling
developers to express both simple permissions and fine-grained, conditional, resource-scoped authorization through a
single coherent API.

---

## Governance

| Field     | Value                                                                            |
|-----------|----------------------------------------------------------------------------------|
| Created   | 2026-04-05                                                                       |
| Status    | draft                                                                            |
| Owned by  | Sine Macula                                                                      |
| Traces to | User-provided spec — sinemacula/laravel-authorization (laravel-iam ecosystem #4) |

---

## Overview

Laravel ships with first-class authentication primitives but only a thin authorization layer in the form of Gates and
Policies. Developers building enterprise or multi-tenant applications quickly outgrow simple Gate closures and turn to
community packages such as Spatie's laravel-permission, which provides solid RBAC but cannot express conditional,
resource-scoped, or context-aware authorization rules. The result is that teams either oversimplify their access model,
hand-roll fragile policy engines, or stitch together multiple packages with overlapping concerns.

`sinemacula/laravel-authorization` provides a single, coherent authorization layer that supports both classic
role/permission checks and AWS IAM-style policy documents with effects, actions, resources, and conditions. The package
integrates with Laravel's native Gate facade so existing `can()` calls continue to work, and exposes a dedicated facade
for policy-driven decisions. Authorization decisions follow the AWS IAM 4-step evaluation order — implicit deny,
explicit deny, allow, implicit deny — so explicit denies always override allows regardless of source. This gives
developers a familiar mental model and an auditable, deterministic decision flow suitable for SOC2, GDPR, and similar
compliance regimes.

This package is being developed inside the `laravel-iam` monorepo at
`/Users/ben/Projects/Sine Macula/Repositories/laravel-iam` and will be extracted into its own standalone repository (
`sinemacula/laravel-authorization`) once v1.0.0 is complete. It must remain fully standalone — usable with any Laravel
application's authentication layer via the standard `Authenticatable` contract — and must not develop hard runtime
dependencies on the other packages in the ecosystem (laravel-authentication, laravel-mfa, laravel-sso,
laravel-audit-log, laravel-iam umbrella).

---

## Target Users

| Persona                      | Description                                                                                                                            | Key Need                                                                                                |
|------------------------------|----------------------------------------------------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------|
| Enterprise Laravel developer | Builds multi-tenant SaaS where different users have different capabilities across different resources                                  | Fine-grained, resource-scoped authorization that supports tenant isolation without bespoke code         |
| Authorization modeller       | Needs to express rules that simple RBAC cannot — e.g., "admins can delete posts, but only in their own organization, only on weekdays" | Conditional, context-aware policy evaluation that handles attributes such as IP, time, and tenant scope |
| Spatie permission migrator   | Currently uses Spatie's laravel-permission and has hit its expressiveness ceiling                                                      | A drop-up path that retains role/permission semantics while adding policy documents and explicit denies |

**Primary user:** Enterprise Laravel developer

---

## Goals

- Provide a single API that supports both simple RBAC (roles, permissions) and policy-based authorization (statements
  with effects, actions, resources, conditions) in the same application.
- Work with any Laravel application that implements the standard `Authenticatable` contract, with zero hard dependency
  on any specific authentication package.
- Apply AWS IAM-style 4-step evaluation logic so that explicit deny always overrides allow, regardless of whether the
  allow came from a role, a direct permission, or another policy statement.
- Integrate with Laravel's native Gate facade so developers can continue using `$user->can(...)` and `Gate::allows(...)`
  against permissions registered through this package.
- Maintain zero required runtime dependencies beyond Laravel itself.
- Achieve PHPStan level 8 strict cleanliness across the entire package.
- Achieve at least 90% line coverage on the policy evaluator, permission manager, and Eloquent traits.

## Non-Goals

- This package is not a full identity management system; it does not provision, manage, or store user accounts.
- This package does not handle authentication; the caller is responsible for resolving the current user.
- This package is not opinionated about role or permission naming conventions; the developer chooses the vocabulary.
- This package is not an AWS IAM clone or drop-in replacement; it borrows the evaluation model, not the wire format or
  service catalog.
- This package does not provide a UI, dashboard, or visual editor for managing policies.

---

## Problem

**User problem:** Laravel developers building anything beyond a basic role check have no first-party way to express
authorization rules that depend on resource ownership, tenant scope, time of day, request context, or any attribute
outside the role/permission tuple. They are forced to scatter conditional logic across controllers, policies, and
middleware, where it becomes brittle, untested, and impossible to audit. Migrating from one access model to another
typically means rewriting every policy file by hand.

**Business problem:** Enterprise and multi-tenant SaaS products have to demonstrate fine-grained access control to
satisfy SOC2, ISO 27001, GDPR, and similar regimes. Auditors expect deterministic decisions, an explicit-deny
capability, and the ability to trace any authorization outcome back to the rule that produced it. Hand-rolled or
RBAC-only solutions cannot demonstrate these properties without significant custom tooling, slowing down compliance
reviews and security sign-off and increasing the cost of every certification cycle.

**Current state:** Developers reach for Spatie's `laravel-permission` for RBAC, write hand-crafted Laravel `Policy`
classes for resource checks, and inevitably bolt on bespoke services or middleware when conditions become non-trivial.
Some teams build entire in-house policy engines, paying ongoing maintenance and audit cost for code that solves a
generic problem. Others over-grant permissions because the cost of expressing the correct rule is too high.

**Evidence:** User-provided spec (no prioritization artifact — Blueprint workflow skipped
intake/discover/problem-map/prioritize phases; spec derived from architectural discussion in conversation). Supporting
context: Spatie laravel-permission's documented RBAC-only model, Laravel core's Gate/Policy primitives requiring manual
wiring, and the AWS IAM evaluation logic as a widely-adopted reference for explicit-deny semantics.

---

## Proposed Solution

A developer installs the package, publishes the migrations, and immediately has tables for roles, permissions, policies,
and the polymorphic pivots that link them to any "authorizable" model. They opt their `User` (or any other identity
model — admin, guest, service account) into authorization by implementing the package's `Authorizable` contract and
applying the relevant traits.

For day-to-day RBAC work, the developer assigns roles and permissions through expressive helpers, then checks them with
a facade or via Laravel's Gate. A permission enum can be registered so the package automatically wires up corresponding
Gates, eliminating the boilerplate of registering each ability by hand.

When a use case demands more than RBAC, the developer authors a policy document — a structured set of statements, each
with an effect (Allow or Deny), one or more actions, one or more resources (with wildcard support), and an optional
condition map. Policies can be attached directly to any authorizable. At evaluation time, the developer asks the package
whether a given action on a given resource is permitted, optionally passing a context array that conditions can read
from. The package walks every applicable statement in deterministic order: it begins from an implicit deny, returns
immediately if any explicit deny matches, returns allow if any allow matches, and otherwise stays on implicit deny.
Roles and direct permissions feed the same evaluation, so an explicit deny in a policy will always override an allow
that came from a role.

When authorization fails, the developer receives a structured exception that includes the full evaluation result — which
statements matched, which were skipped, and why — so the failure can be logged, audited, or debugged without re-running
the check.

### Key Capabilities

- Developer can assign roles to any authorizable identity (user, admin, guest, service account) through a simple,
  expressive API.
- Developer can assign permissions directly to an identity, bypassing roles when finer control is required.
- Developer can assign permissions to roles, with identities inheriting them automatically.
- Developer can check whether an identity has a role or a permission via a dedicated facade or via Laravel's native Gate
  facade.
- Developer can author IAM-style policy documents containing statements with effect, actions, resources, and optional
  conditions.
- Developer can attach one or more policies directly to any authorizable identity.
- Developer can ask the package whether a given action on a given resource is authorized for an identity, optionally
  with a context array.
- Developer can combine RBAC and policy-based decisions in the same application and rely on explicit deny always
  winning.
- Developer can register a permission enum so the package auto-registers Laravel Gates for every case.
- Developer can use wildcards inside policy statement actions and resources (e.g., `posts:*`, `arn:posts:*:org-1`).
- Developer can write conditions that read from a context array (e.g., IP range, time of day, tenant id) and have them
  evaluated at decision time.
- Developer can override the default Role, Permission, and Policy Eloquent models via configuration.
- Developer can integrate the package with their own concept of "current principal" by binding a custom
  `PrincipalResolver`; the default returns null so the package is anonymous-safe.
- Developer can publish and customise the package migrations to fit their own database conventions.
- Developer can catch a structured `AuthorizationException` containing the full evaluation result whenever an
  authorization check fails.

---

## Requirements

### Must Have (P0)

- **Role assignment to identities:** Developer can assign, revoke, and query roles on any model that implements the
  package's `Authorizable` contract.
  - **Acceptance criteria:** Given an `Authorizable` model, when the developer calls the role assignment API with a
      role identifier, then the role is persisted in the appropriate pivot table and is returned by a subsequent
      role-query call. Revoking the role removes it from the pivot. Assigning a non-existent role surfaces a clear
      error.

- **Direct permission assignment to identities:** Developer can grant and revoke permissions on an identity without
  going through a role.
  - **Acceptance criteria:** Given an `Authorizable` model with no roles, when the developer assigns a permission
      directly, then a permission check for that identity returns true and the permission appears in the pivot. Revoking
      the permission causes the same check to return false.

- **Permission assignment to roles with inheritance:** Developer can attach permissions to a role and have every
  identity holding that role inherit those permissions automatically.
  - **Acceptance criteria:** Given a role with permission `posts:create` attached, when an identity is assigned that
      role, then a permission check for `posts:create` against the identity returns true even though the permission is
      not directly attached.

- **Role and permission checks via facade and Gate:** Developer can check roles and permissions using either the
  package's facade or Laravel's native `Gate::allows()` / `$user->can()` calls.
  - **Acceptance criteria:** Both invocation styles return the same boolean result for the same identity and the same
      permission. A permission that has been registered via the permission enum is callable through Laravel's Gate
      without any further wiring.

- **Policy document authoring:** Developer can define a policy document made up of one or more statements, each carrying
  an effect (Allow or Deny), one or more actions, one or more resources, and an optional condition map.
  - **Acceptance criteria:** A persisted policy round-trips through the package without losing any statement, effect,
      action, resource, or condition. Invalid policy documents (missing effect, missing actions, malformed structure)
      are rejected with a clear error.

- **Direct policy attachment to identities:** Developer can attach and detach policies on any `Authorizable` identity.
  - **Acceptance criteria:** After attaching a policy, the identity's set of attached policies includes it; after
      detaching, it does not. Attaching the same policy twice does not produce duplicates in the pivot.

- **AWS IAM-style 4-step policy evaluation:** Developer can ask the package whether a given action on a given resource
  is authorized for an identity, and the package returns a decision produced by the four-step evaluation order (implicit
  deny → explicit deny → allow → implicit deny).
  - **Acceptance criteria:** With no matching statements the result is deny. With only an allow statement matching the
      result is allow. With both an allow and a deny statement matching the result is deny. The returned evaluation
      result reports the matching statements and the rule that produced the final decision.

- **Combined RBAC and policy authorization with deny precedence:** Developer can mix role-based and policy-based
  authorization in the same application and rely on explicit policy denies overriding role-granted allows.
  - **Acceptance criteria:** Given an identity with a role granting `posts:delete` and a policy with an explicit deny
      on `posts:delete`, an authorization check for `posts:delete` returns deny. Removing the deny statement causes the
      same check to return allow.

- **Permission enum registration with Gate auto-wiring:** Developer can register a permission enum and have the package
  automatically register a Laravel Gate for every case.
  - **Acceptance criteria:** After registration, every case in the enum is callable via `Gate::allows(...)` without
      additional wiring, and the result reflects the identity's role/permission/policy state.

- **Wildcard matching in policy statements:** Developer can use wildcards in actions and resources within policy
  statements.
  - **Acceptance criteria:** A statement with action `posts:*` matches the actions `posts:create`, `posts:update`, and
      `posts:delete`. A statement with resource `arn:posts:*` matches `arn:posts:1` and `arn:posts:99`. Wildcards do not
      match across the segment separator unless the wildcard is the entire segment.

- **Condition evaluation against a context array:** Developer can attach conditions to policy statements that read from
  a developer-supplied context array at evaluation time.
  - **Acceptance criteria:** A statement that includes an IP-range condition allows when the supplied context contains
      an in-range IP and denies (or fails to match) when it does not. Missing context keys do not throw; they cause the
      condition to evaluate to false. The same applies to time-of-day and arbitrary equality conditions.

- **Configurable Role, Permission, and Policy models:** Developer can swap out any of the three core Eloquent models for
  their own subclass via the package configuration file.
  - **Acceptance criteria:** After publishing config and pointing the model classes at custom subclasses, all queries
      and pivots resolve through the developer's classes. The package does not type-hint the default classes anywhere a
      custom subclass would be rejected.

- **Polymorphic identity support:** Developer can apply roles and permissions to any identity model — not only `User` —
  through polymorphic pivot tables.
  - **Acceptance criteria:** Distinct identity models (e.g., `User`, `Admin`, `ServiceAccount`) can each implement
      `Authorizable` and be assigned the same role without any model-class collisions. The pivot rows correctly record
      the polymorphic type and id.

- **Pluggable principal resolver with anonymous default:** Developer can bind their own `PrincipalResolver`
  implementation; the default implementation returns null so the package never assumes an authentication system.
  - **Acceptance criteria:** With no resolver bound, calls that ask for "the current principal" return null without
      erroring. After binding a custom resolver, the same calls return whatever the resolver provides. The package's
      tests run with the default anonymous resolver.

- **Authorizable contract for caller models:** Developer can implement the package's `Authorizable` contract on any of
  their own Eloquent models to opt them into the authorization system.
  - **Acceptance criteria:** A model that implements the contract and uses the documented traits gains role,
      permission, and policy assignment APIs and can be the subject of an authorization check. A model that does not
      implement the contract is rejected with a clear error.

- **Structured authorization exception with evaluation result:** Developer can catch an `AuthorizationException`
  carrying the full evaluation result whenever an authorization check fails (when the developer chose the throwing
  variant of the API).
  - **Acceptance criteria:** The exception exposes the identity, the action, the resource, the final decision, and the
      matching statements. Logging the exception produces enough information to reconstruct the decision without
      re-running it.

- **Publishable migrations:** Developer can publish and customise the package's migrations.
  - **Acceptance criteria:** Running the publish command writes the migration files into the application's migrations
      directory. The published migrations run cleanly on a fresh database, create all required tables (roles,
      permissions, policies, role_permissions pivot, authorizable_roles pivot, authorizable_permissions pivot,
      authorizable_policies pivot), and use ULID primary keys.

- **Standalone operation:** Developer can install and use the package on any Laravel 13+ application without installing
  any other package from the laravel-iam ecosystem.
  - **Acceptance criteria:** The package's composer.json declares no `require` dependency on any other
      `sinemacula/laravel-*` package. The package's tests run in isolation from the monorepo's other packages. A fresh
      Laravel application with only this package installed can successfully assign roles, register permissions, attach
      policies, and run an authorization check.

### Should Have (P1)

- **Documentation with migration-from-Spatie example:** Developer can read a documented migration path from Spatie's
  laravel-permission to this package.
  - **Acceptance criteria:** README or supporting docs include a worked example showing how Spatie's `assignRole`,
      `givePermissionTo`, and `hasPermissionTo` calls translate to this package's API.

- **Worked policy-document examples in documentation:** Developer can read documented policy-document and
  condition-evaluation examples covering at least IP-range, time-of-day, and tenant-scope conditions.
  - **Acceptance criteria:** Documentation contains at least one runnable example for each of the three condition
      types listed above.

### Nice to Have (P2)

- **Helper for inspecting why a decision was reached:** Developer can request a human-readable explanation of an
  authorization decision for debugging.

---

## Success Criteria

| Metric                                                  | Baseline             | Target                                                                                    | How Measured                                                                                          |
|---------------------------------------------------------|----------------------|-------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------|
| Standalone install on a fresh Laravel app succeeds      | N/A — new capability | 100% success on Laravel 13+ / PHP 8.3+                                                    | CI matrix job that installs the package into a fresh Laravel skeleton and runs the example test suite |
| AWS IAM 4-step evaluation correctness                   | N/A — new capability | All four cases (no match, allow only, deny only, allow + deny) pass                       | Dedicated integration test suite covering each branch of the evaluator                                |
| Laravel Gate integration parity                         | N/A — new capability | `Gate::allows()` and the package facade return identical results                          | Integration test that asserts equality across both call styles for every requirement-level check      |
| PHPStan level 8 cleanliness                             | N/A — new capability | Zero errors at level 8 strict                                                             | `composer check` (qlty) on every CI run                                                               |
| Test coverage on evaluator, manager, and traits         | N/A — new capability | ≥ 90% line coverage on the three target classes / namespaces                              | `composer test-coverage` clover report inspected per release                                          |
| Hard runtime dependencies on other laravel-iam packages | N/A — new capability | Zero                                                                                      | Inspection of `composer.json` `require` block on every release                                        |
| Polymorphic identity support across distinct models     | N/A — new capability | At least two distinct identity models pass the same authorization check via the same role | Integration test that creates two unrelated `Authorizable` models and asserts identical results       |

---

## Dependencies

- Laravel 13 or newer.
- PHP 8.3 or newer.
- Laravel's Gate facade (provided by `illuminate/auth`).
- The `Illuminate\Contracts\Auth\Authenticatable` contract.

---

## Assumptions

- Consumers are responsible for providing their own authentication layer; this package never tries to identify a user on
  its own.
- Consumers are willing to publish migrations to install the schema; the package does not attempt to manage schema
  dynamically at runtime.
- Consumers accept ULID primary keys on the package's tables; primary key strategy is not configurable in v1.
- The AWS IAM 4-step evaluation order is a sufficient mental model for the target personas; consumers who need a
  fundamentally different decision algorithm are not in scope.
- The polymorphic pivot approach is acceptable; consumers requiring single-table inheritance or non-Eloquent persistence
  are not in scope.

---

## Risks

| Risk                                                                                      | Impact                                                                                      | Likelihood | Mitigation                                                                                                                                              |
|-------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------|------------|---------------------------------------------------------------------------------------------------------------------------------------------------------|
| Developers misunderstand the 4-step evaluation order and assume "last write wins"         | Insecure deployments where intended denies are silently overridden in the developer's mind  | Medium     | Document the evaluation order prominently with worked examples; surface the deciding rule in the evaluation result so audits make the order observable  |
| Performance degrades for identities holding many policies                                 | Slow page loads, timeouts on authorization-heavy endpoints in high-cardinality applications | Medium     | Keep evaluation work in-memory after a single load; document caching guidance; ship benchmarks; defer N+1 queries via documented eager-loading patterns |
| Database schema evolution between releases breaks policy semantics for upgraders          | Painful upgrades, data loss, or silent semantic drift in stored policies                    | Low        | Treat the policy document structure as a versioned contract; ship migration guides for any schema change; cover round-trip in tests                     |
| Gate integration collides with consumer's existing custom Gates or Policies               | Unexpected allow/deny outcomes when consumer has pre-existing Gate definitions              | Medium     | Document registration order; do not overwrite existing Gates silently; surface a clear log warning when a permission name is already registered         |
| Learning curve from RBAC to policy documents discourages adoption                         | Developers stick to RBAC features, never benefiting from the package's differentiator       | Medium     | Provide a Spatie-to-this-package migration walkthrough; ensure RBAC works in isolation so policies are an opt-in upgrade, not a precondition            |
| Naming or semantic drift between this package and the laravel-iam umbrella when extracted | Friction when the umbrella package wires the principal resolver to laravel-authentication   | Low        | Lock the `PrincipalResolver` contract surface before v1.0.0; cover the contract in the umbrella package's integration test                              |

---

## Out of Scope

- Authentication of users, sessions, tokens, or any other credential.
- User account provisioning, lifecycle management, or storage.
- Audit logging of authorization decisions (the consumer should integrate with `sinemacula/laravel-audit-log` or their
  own logging).
- Visual policy editor, dashboard, or admin UI of any kind.
- Direct import or wire-format compatibility with AWS IAM JSON policies (a future adapter is possible but is not part of
  this PRD).
- Attribute-based access control (ABAC) beyond what condition evaluation against a context array can express.
- Dynamic permission assignment driven by runtime rules; consumers should express such logic with conditions instead.
- Multi-tenancy primitives (tenant resolution, tenant scoping middleware); consumers should scope by tenant id via a
  condition or the context array.
- Out-of-the-box delegation of "the current principal" to `sinemacula/laravel-authentication`; that integration ships in
  the laravel-iam umbrella package and is not part of this standalone package.

---

## Release Criteria

- All tests pass on the supported Laravel and PHP matrix.
- PHPStan level 8 strict reports zero errors via `composer check`.
- Integration tests verify each branch of the AWS IAM 4-step evaluation (no match, allow only, deny only, allow + deny).
- Integration tests verify Laravel Gate integration parity for every P0 check.
- Integration test verifies the package installs and runs cleanly in a fresh Laravel application with no other
  laravel-iam packages present.
- Published migrations run cleanly on a fresh database and create every required table with ULID primary keys.
- README documents installation, RBAC usage, policy authoring, condition evaluation, and a Spatie migration example.
- Documentation includes at least one worked example for each of IP-range, time-of-day, and tenant-scope conditions.
- The package's `composer.json` declares no hard runtime dependency on any other `sinemacula/laravel-*` package.

---

## Traceability

| Artifact             | Path                                                                                                                                                                                   |
|----------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Intake Brief         | User-provided spec (no prioritization artifact — Blueprint workflow skipped intake/discover/problem-map/prioritize phases; spec derived from architectural discussion in conversation) |
| Relevant Spikes      | None (workflow phases skipped)                                                                                                                                                         |
| Problem Map Entry    | None (workflow phases skipped)                                                                                                                                                         |
| Prioritization Entry | None (workflow phases skipped) — package #4 of 6 in the laravel-iam ecosystem                                                                                                          |

---

## References

- Ecosystem monorepo: `/Users/ben/Projects/Sine Macula/Repositories/laravel-iam`
- Sibling PRDs in this ecosystem:
  - 01 — sinemacula/laravel-authentication
  - 02 — sinemacula/laravel-mfa
  - 03 — sinemacula/laravel-sso
  - 04 — sinemacula/laravel-authorization (this document)
  - 05 — sinemacula/laravel-audit-log
  - 06 — sinemacula/laravel-iam (umbrella)
- Conceptual reference: AWS IAM policy evaluation logic (used as the inspiration for the 4-step decision order; this
  package is not a wire-format clone).
