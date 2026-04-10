# Issue Planning Prompts

Paste any of the prompts below into a fresh Codex session to kick off a planning pass before
implementation.

## Architecture

### 1. Remove the split-brain JWT service model

```text
You are in planning mode only. Do not implement yet.

Repository: `sinemacula/laravel-authentication`
Goal: plan a minimal, testable change to remove the split-brain JWT service
model so JWT issuance and verification are consistently guard-scoped.

First, inspect the repository to understand how `AuthServiceProvider`,
`AuthManager`, `JwtGuard`, `JwtTokenService`, and `RefreshTokenExchange`
currently interact. Use sub-agents in parallel where useful:
- one to trace service container bindings and guard instantiation
- one to inspect JWT issuance/verification call sites
- one to map the relevant test coverage

Then return a planning document only, covering:
1. The current split-brain behavior and why it is risky
2. The target design and whether it should be fully guard-scoped or exposed via a guard-local factory/accessor
3. The files and contracts likely to change
4. Backward-compatibility and migration risks for existing consumers
5. Edge cases for multi-guard apps
6. The exact tests to add or update before implementation
7. A recommended implementation order

Do not write code yet.
```

### 2. Support per-guard principal resolvers

```text
You are in planning mode only. Do not implement yet.

Repository: `sinemacula/laravel-authentication`
Goal: plan support for per-guard principal resolvers without breaking current behavior.

Inspect how principal resolution is currently bound and consumed across guards,
config, and service provider setup. Use sub-agents in parallel where useful:
- one to trace resolver binding and guard construction
- one to inspect config loading and guard-specific config options
- one to review tests around multi-guard, tenant-aware, and principal-resolution behavior

Then return a planning document only, covering:
1. The current resolver model and its constraints
2. The minimal API/config shape for per-guard resolvers
3. Whether this should be additive, fallback-based, or replace the global binding model
4. The files likely to change
5. Compatibility and migration risks
6. The full test matrix needed to prove the change
7. A recommended implementation order

Do not write code yet.
```

### 3. Resolve the statelessness mismatch

```text
You are in planning mode only. Do not implement yet.

Repository: `sinemacula/laravel-authentication`
Goal: plan how to resolve the mismatch between the documented bearer-token story and the actual runtime behavior.

Inspect the auth flow, README claims, `JwtGuard`, `JwtTokenService`, refresh
behavior, and any tests that show whether the bearer path is truly stateless or
still storage-backed. Use sub-agents in parallel where useful:
- one to compare README/public docs against runtime behavior
- one to trace the access-token and refresh-token paths
- one to inspect tests that imply DB access, device lookup, or stateless semantics

Then return a planning document only, covering:
1. The exact mismatch between docs and implementation
2. A documentation-only correction path
3. A true stateless-mode path, if it should exist
4. The semantic and security tradeoffs of each option
5. Which option you recommend and why
6. The files/docs/tests that would need to change
7. A recommended implementation order

Do not write code yet.
```

### 4. Make the device persistence boundary explicit

```text
You are in planning mode only. Do not implement yet.

Repository: `sinemacula/laravel-authentication`
Goal: plan how to make the device persistence boundary explicit rather than implicitly Eloquent-backed.

Inspect the `Device` contract, `Device` model, migration,
`RefreshTokenExchange`, `UpdateDeviceTimestamp`, and the related tests. Use
sub-agents in parallel where useful:
- one to inspect the public contract and extension points
- one to trace refresh rotation and timestamp update assumptions
- one to review tests that currently depend on Eloquent-specific device behavior

Then return a planning document only, covering:
1. The current implicit assumptions about device persistence
2. The best design direction: formalize the Eloquent requirement or introduce a device store/repository abstraction
3. The files and interfaces likely to change
4. Compatibility and maintenance tradeoffs
5. The exact tests needed to lock in the chosen boundary
6. A recommended implementation order

Do not write code yet.
```

### 5. Preserve the active principal across refresh in multi-scope deployments

```text
You are in planning mode only. Do not implement yet.

Repository: `sinemacula/laravel-authentication`
Goal: plan a change so refresh preserves the original active principal and scope in multi-scope deployments.

Inspect how access tokens carry `pid`, how refresh tokens are issued and
exchanged, and how principal resolution behaves for identities with multiple
scoped assignments. Focus on `JwtTokenService`, `RefreshTokenExchange`, guard
restoration flow, and current tests. Use sub-agents in parallel where useful:
- one to trace token claims and refresh-token payload/rotation behavior
- one to inspect principal resolution and fallback behavior
- one to review existing tests around refresh, replay, and multi-principal scenarios

Then return a planning document only, covering:
1. The current refresh continuity gap
2. The desired refresh contract for single-scope vs multi-scope users
3. The best way to preserve principal context during refresh
4. Backward-compatibility and migration risks
5. Any token-format or storage changes required
6. The exact tests to add or update
7. A recommended implementation order

Do not write code yet.
```

## Code Quality

### 6. Replace global config reads with injected configuration objects

```text
You are in planning mode only. Do not implement yet.

Repository: `sinemacula/laravel-authentication`
Goal: plan a minimal, testable refactor to replace global config reads with
injected configuration objects in low-level auth components.

Inspect `ValidatesGuardCredentials`, `Device`, `UpdateDeviceTimestamp`, and any
surrounding call sites to see where config is read and how it flows through
guards, listeners, and models. Use sub-agents in parallel where useful:
- one to trace config reads and consumers
- one to inspect constructor/service wiring and DI opportunities
- one to review test coverage around those code paths

Then return a planning document only, covering:
1. Every current global config read worth refactoring
2. The smallest viable injected config/value-object design
3. The files likely to change
4. Risks to backward compatibility and framework integration
5. The exact tests to add or update
6. A recommended implementation order

Do not write code yet.
```

### 7. Bring documentation and implementation fully into alignment

```text
You are in planning mode only. Do not implement yet.

Repository: `sinemacula/laravel-authentication`
Goal: plan how to align the package documentation and runtime behavior, especially around the bearer/access-token path.

Inspect the README, public config/docs, `JwtGuard`, `JwtTokenService`, refresh
behavior, and the most relevant feature/integration tests. Use sub-agents in
parallel where useful:
- one to compare the docs to the actual auth flow
- one to inspect the bearer path and refresh path in code
- one to review tests that establish the true behavior

Then return a planning document only, covering:
1. The exact documentation mismatches
2. Which behavior should be treated as the source of truth
3. Whether the fix should be docs-only, code-only, or a combination
4. Risks of changing docs versus changing runtime behavior
5. The exact files/docs/tests to update
6. A recommended implementation order

Do not write code yet.
```

### 8. Add mutation testing and performance regression coverage

```text
You are in planning mode only. Do not implement yet.

Repository: `sinemacula/laravel-authentication`
Goal: plan a practical quality gate for mutation testing and performance regression coverage.

Inspect the existing PHPUnit suite, test layout, composer scripts, CI/tooling,
and the auth hot paths. Use sub-agents in parallel where useful:
- one to identify the most mutation-sensitive code paths
- one to identify the most performance-sensitive runtime paths
- one to inspect current test/CI tooling and likely integration points

Then return a planning document only, covering:
1. The best mutation-testing approach for this repo
2. The best benchmark/performance-regression approach for this repo
3. The minimum scenario set that should be covered first
4. Risks of flakiness, runtime cost, or false confidence
5. The exact tests/benchmarks/scripts to add
6. How these checks should fit into local workflow vs CI
7. A recommended implementation order

Do not write code yet.
```

### 9. Add short design docs for key security and lifecycle decisions

```text
You are in planning mode only. Do not implement yet.

Repository: `sinemacula/laravel-authentication`
Goal: plan a set of short design docs for the key security and lifecycle decisions that are currently encoded mostly in tests.

Inspect the code and tests around event ordering, refresh replay policy,
fail-closed `pid` / `did` handling, and access-only mode without devices. Use
sub-agents in parallel where useful:
- one to map each behavior to the core implementation
- one to identify the tests that best document each behavior
- one to propose where the docs should live and how they should be structured

Then return a planning document only, covering:
1. The proposed doc set and where each doc should live
2. What each doc should explain
3. Which code paths and tests each doc should cite
4. Any missing tests needed to make the docs authoritative
5. The maintenance risks and how to keep the docs current
6. A recommended implementation order

Do not write code yet.
```

## Efficiency

### 10. Make the access-token path truly zero-query or near-zero-query

```text
You are in planning mode only. Do not implement yet.

Repository: `sinemacula/laravel-authentication`
Goal: plan a path to make bearer access-token authentication zero-query or near-zero-query.

Inspect `JwtGuard`, `JwtTokenService`, `RefreshTokenExchange`,
device/principal resolution, and the tests that cover those flows. Use
sub-agents in parallel where useful:
- one to trace the current bearer auth flow and every storage hit
- one to inspect token claims and what would be needed for stateless verification
- one to review tests and likely benchmark coverage points

Then return a planning document only, covering:
1. The current query/storage cost of the bearer path
2. The design options: true stateless mode vs low-overhead hybrid mode
3. The security and revocation tradeoffs of each option
4. The files and contracts likely to change
5. The exact tests and benchmarks needed
6. Whether this should be opt-in and how it should be exposed
7. A recommended implementation order

Do not write code yet.
```

### 11. Cache identity/principal/device resolution where semantics allow

```text
You are in planning mode only. Do not implement yet.

Repository: `sinemacula/laravel-authentication`
Goal: plan a safe caching strategy for identity, principal, and device resolution without weakening auth semantics.

Inspect the guard flow, lookup paths, current invalidation points, and any
existing cache usage or abstractions. Use sub-agents in parallel where useful:
- one to map the current resolution and lookup path
- one to identify potential invalidation triggers and failure modes
- one to review tests that would need to protect revocation and active-state guarantees

Then return a planning document only, covering:
1. Which lookups are safe to cache and which are not
2. Proposed cache keys, TTL strategy, and invalidation rules
3. Failure modes and semantics that must not regress
4. The files and abstractions likely to change
5. The exact tests and benchmarks needed
6. Whether caching should be configurable or opt-in
7. A recommended implementation order

Do not write code yet.
```

### 12. Reduce lookup fan-out in 3D mode

```text
You are in planning mode only. Do not implement yet.

Repository: `sinemacula/laravel-authentication`
Goal: plan a change to reduce lookup fan-out in 3D mode while preserving current behavior.

Inspect the 3D identity → principal → tenant resolution path, guard
bootstrapping, resolver contracts, and integration tests. Use sub-agents in
parallel where useful:
- one to trace each lookup hop and query boundary
- one to inspect resolver and tenant-binding behavior
- one to review tests that must keep 2D and 3D modes stable

Then return a planning document only, covering:
1. Where the current lookup fan-out comes from
2. The best way to collapse or streamline the lookup chain
3. Whether this needs repository/query-layer changes, eager loading, or resolver redesign
4. The files and contracts likely to change
5. The exact tests and benchmarks needed
6. The main regression risks in 2D and 3D modes
7. A recommended implementation order

Do not write code yet.
```

### 13. Add benchmark evidence

```text
You are in planning mode only. Do not implement yet.

Repository: `sinemacula/laravel-authentication`
Goal: plan measurable benchmark evidence for the package's main auth hot paths.

Inspect the auth hot paths, refresh flow, device timestamp updates, current
tests, composer scripts, and CI/tooling. Use sub-agents in parallel where
useful:
- one to identify the highest-value benchmark targets
- one to inspect existing test and CI integration points
- one to propose realistic metrics, thresholds, and reporting shape

Then return a planning document only, covering:
1. What should be benchmarked first and why
2. The tooling and harness you recommend for this repo
3. The scenarios to measure: bearer auth, refresh exchange, device timestamp
   updates, 2D vs 3D resolution, and multi-guard/multi-tenant cases
4. What metrics and thresholds make sense
5. How to keep the benchmarks reliable and non-flaky
6. The exact files/scripts/tests to add
7. A recommended implementation order

Do not write code yet.
```
