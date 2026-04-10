# ISSUES

## Goal: 10/10 Architecture, Code Quality, and Efficiency

This document captures what would need to change for this repository to score 10/10 in architecture,
code quality, and efficiency, based on a full source and test-suite review.

## Architecture

### 1. Remove the split-brain JWT service model

Right now, the package binds a container-wide `JwtTokenService` in `AuthServiceProvider`, but each
`jwt` guard may also construct its own per-guard override instance from `auth.guards.<name>.jwt`.

That means there are potentially two sources of truth:

- thegloballyresolved`JwtTokenService`-theactualper-guardtokenserviceusedbyaspecific`JwtGuard`

To reach 10/10, JWT issuance and verification should be made consistently guard-scoped, or the
package should expose an explicit guard-local token-service factory/accessor.

Impact on functionality:

- Lowifimplementedcompatibly-Norequiredbehaviorchangeforexistingconsumers-Mostlyremovesambiguityin
  multi-guard apps

### 2. Support per-guard principal resolvers

The package currently binds a single application-wide `PrincipalResolver` implementation. That
works, but it is not ideal for apps with multiple trust boundaries, tenancy strategies, or
principal-resolution policies.

To reach 10/10, each guard should be able to declare its own resolver strategy, rather than forcing
all guards through a shared resolver binding.

Impact on functionality:

- Lowifadditive-Nobreakingruntimechangerequired-Improvescomposabilityinlargerapplications

### 3. Resolve the statelessness mismatch

The README describes the access-token path as effectively stateless and not requiring database hits,
but the bearer path in `JwtGuard` still resolves identity and often principal/device from storage.

That architectural mismatch is the main thing preventing a 10/10 score.

There are two valid ways to fix it:

1. MaketheREADMEandpackagepositioningfullymatchreality2.Addatrulystatelessaccess-tokenmode

Impact on functionality:

- Documentation-onlyfix:nofunctionalimpact-Truestatelessmode:yes,thischangessemanticsunlessmade
  opt-in

### 4. Make the device persistence boundary explicit

The package exposes a generic `Device` contract, but refresh rotation and device timestamp updates
effectively assume an Eloquent-backed persisted model.

To reach 10/10, that assumption should be made explicit in one of two ways:

- formalizetherequirementinthepublicdesign-introduceadedicateddevicestore/repositoryabstraction
  instead of relying on Eloquent-specific behavior in core flows

Impact on functionality:

- Lowifdoneadditively-Mostlyaclarityandextension-boundaryimprovement

### 5. Preserve the active principal across refresh in multi-scope deployments

Access tokens carry `pid`, so bearer authentication can restore the exact active principal and
scope. Refresh tokens do not currently carry equivalent principal context, so `RefreshTokenExchange`
can fall back to the identity's default principal-resolution path instead of preserving the original
scoped assignment.

That is acceptable in simple single-scope apps, but it is a real gap for enterprise deployments
where one identity can act in multiple organization, facility, or department-scoped roles.

To reach 10/10, refresh should preserve and validate the original active principal, rather than
merely re-resolving a principal from the identity.

Impact on functionality:

- Yes,butintherightdirection-Single-scopeappswouldlikelyseelittleornomeaningfulchange-Multi-scope
  apps would preserve session context correctly across refresh instead of potentially falling back
  to a default principal - Makes the package more enterprise-ready without moving authorization
  concerns into the authentication layer

## Code Quality

### 1. Replace global config reads with injected configuration objects

Several low-level components read configuration through facades or global config access:

- `ValidatesGuardCredentials`-`Device`-`UpdateDeviceTimestamp`

That is workable, but 10/10 code quality usually means fewer hidden dependencies and more explicit
configuration flow.

These pieces would be cleaner if small config value objects or constructor-injected primitives were
used instead.

Impact on functionality:

- Noneexternally-Internalrefactoronly

### 2. Bring documentation and implementation fully into alignment

The strongest code-quality weakness is not poor code style or weak tests. It is the gap between the
product story and the actual runtime behavior in the bearer path.

Closing that gap would materially improve the perceived and actual quality of the repository more
than cosmetic refactors would.

Impact on functionality:

- Noneifdocumentationiscorrected-Potentiallymeaningfulifruntimebehaviorischangedtomatchthedocs
  instead

### 3. Add mutation testing and performance regression coverage

The PHPUnit suite is already very strong, but a 10/10 code-quality score usually implies stronger
proof that the tests are not only broad, but also adversarial.

Mutation testing would validate the logic-spec quality of the test suite. Benchmark or regression
tests would validate hot-path stability.

Impact on functionality:

- None-Toolingandquality-processimprovementonly

### 4. Add short design docs for key security and lifecycle decisions

Some of the most important behavior is currently discoverable primarily through tests:

- eventordering-refreshreplaypolicy-fail-closed`pid`/`did`handling-access-onlymodewithoutdevices

Those behaviors are well-tested, but 10/10 quality would also make them easy to understand without
reverse-engineering the suite.

Impact on functionality:

- None-Documentationimprovementonly

## Efficiency

### 1. Make the access-token path truly zero-query or near-zero-query

This is the biggest efficiency improvement available.

Today, the bearer path in `JwtGuard` still resolves identity and often principal/device from
storage. That means access-token authentication is secure and reasonable, but not especially lean
for high-throughput APIs.

To reach 10/10 efficiency, the package would need either:

- afullystatelessaccess-tokenmode-oraverylow-overheadcachedresolutionstrategy

Impact on functionality:

- Yes,potentiallysignificant-Afullystatelessmodeweakensorchangesimmediaterevocation/deactivation
  semantics unless carefully designed - Best handled as an opt-in operating mode

### 2. Cache identity/principal/device resolution where semantics allow

If the package wants to preserve current semantics more closely, then caching is the safer
efficiency path.

That could reduce repeated identity/principal/device resolution costs without fully abandoning
current behavior.

The tradeoff is invalidation complexity.

Impact on functionality:

- Lowexternallyifimplementedcarefully-Moderateoperationalcomplexityduetocacheinvalidationconcerns

### 3. Reduce lookup fan-out in 3D mode

In 3D mode, a bearer request may trigger multiple logical lookups across identity, principal, and
device resolution.

A 10/10 efficiency design would try to collapse the contextual triple into a smaller number of
queries or a more intentional repository-level fetch plan.

Impact on functionality:

- Nointendeduser-facingchange-Internalperformanceimprovementonly

### 4. Add benchmark evidence

The current efficiency assessment is based on implementation structure, not measured benchmarks.

A perfect score would require actual throughput/latency evidence for:

- bearerauthentication-refreshexchange-devicetimestampupdates-2Dvs3Dresolutioncost-per-guard
  multi-tenant scenarios

Impact on functionality:

- None-Measurementandvalidationonly

## Would These Changes Affect Functionality?

### Architecture

Mostly no, if implemented additively. The two potentially functional architecture changes are
introducing a truly stateless bearer mode and preserving the same active principal across refresh in
multi-scope deployments.

### Code Quality

Mostly no. Almost everything here is documentation, dependency-explicitness, or testing/process
improvement.

### Efficiency

Yes, potentially.

This is the one category where a 10/10 score may conflict with the current semantics.

Specifically:

- trulystatelessaccess-tokenverificationisfaster-butcurrentbehaviorappearstopreservestronger
  immediate enforcement of active-state and resolution rules

That means the package likely needs explicit operating modes rather than a single fixed design if it
wants both maximum efficiency and current behavior guarantees.

## Summary

To get to 10/10 across the board:

- Architectureneedscleanerboundariesandaresolvedstoryaroundstatelessness-Architecturealsoneeds
  refresh continuity for multi-scope enterprise sessions - Code quality mainly needs stronger
  explicitness and design-level documentation, not major rewrites - Efficiency needs either caching
  or a truly stateless access path, and that is the area most likely to affect functionality

The short version is:

- Architecturecanreach10/10withmostlyadditivecleanup-Codequalitycanreach10/10withoutmeaningful
  behavioral change - Efficiency can reach 10/10, but likely only by introducing selectable modes or
  changing current runtime semantics
