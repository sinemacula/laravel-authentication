# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/), and this project adheres
to [Semantic Versioning](https://semver.org/).

## 1.0.0 (2026-08-24)


### Bug Fixes

* **benchmarks:** widen anonymous CacheFactory::store() phpdoc ([#34](https://github.com/sinemacula/laravel-authentication/issues/34)) ([9c5b6f0](https://github.com/sinemacula/laravel-authentication/commit/9c5b6f0c357d422fee40b47a6af3639411637027))

## [1.0.0] - Unreleased

Initial release of stateless contextual authentication for Laravel.

### Added

- JWT guard with self-verifying access tokens and refresh token rotation
- HTTP Basic guard with timing-safe credential validation
- Identity, Principal, Device, and Tenant contracts with trait-based defaults
- 2D (identity-is-principal) and 3D (identity -> principal -> tenant) adoption modes from the same guards
- Per-guard principal resolvers and JWT configuration
- Guard-scoped token issuance via `JwtTokenServiceFactory`
- Atomic refresh token rotation with CAS replay detection and device revocation
- `RefreshFailureReason` enum with 10 SIEM-ready failure codes
- Opt-in bearer identity resolution cache with store-backed and null implementations
- Device model with polymorphic identity relation, revocation, and debounced last-seen tracking
- `EloquentDevice` contract formalizing the Eloquent persistence boundary
- `ResolvesHintedPrincipal` contract for optimized principal lookup
- Migration collision guard to prevent table conflicts
- Security lifecycle design notes
- Hot-path benchmarks for JWT guard, Basic guard, refresh exchange, and device timestamp updates
- Quality gates with scoped mutation testing (85% MSI) and scheduled full mutation suite
- 100% line and method coverage across all source files
