# Project Overview

`sinemacula/laravel-authentication` - Stateless contextual authentication for Laravel. Distinguishes the authenticated *
*Identity** from the acting **Principal** and the issuing **Device**, exposed through Laravel's standard `Auth` facade,
middleware, and events.

- **Namespace:** `SineMacula\Laravel\Authentication`
- **Source:** `src/`
- **Type:** Library (Composer package)
- **PHP 8.3+ / Laravel 12 / 13**

## Architecture

Standalone Auth core. Sibling IAM packages (MFA, SSO, Authorization, Audit Log, IAM umbrella) live in their own
repositories - this package has zero runtime dependencies on them.

Core model: **Identity → Principal → Device**, with optional Tenant scope. Both 2D (identity-is-principal) and 3D (
identity → separate principal → tenant) adoption modes are supported by the same guards.

## Commands

```bash
composer install                          # Install dependencies
composer check                            # Static analysis via qlty (PHPStan 8, PHP-CS-Fixer, CodeSniffer)
composer check -- --all --no-cache --fix  # Full check with auto-fix
composer format                           # Format code via qlty

# Testing
composer test                             # All suites in parallel (Paratest)
composer test:coverage                    # All suites with clover coverage
composer test:unit                        # Unit suite only
composer test:feature                     # Feature suite only
composer test:integration                 # Integration suite only
composer test:performance                 # Performance budget suite (serial)
composer test:mutation                    # Scoped mutation gate (85% MSI)
composer test:mutation:full               # Full mutation suite (no thresholds)

# Benchmarks
composer bench                            # PHPBench hot-path benchmarks
composer bench:ci                         # PHPBench with CI artifact dump

# Single test file or method
vendor/bin/phpunit tests/Unit/SomeTest.php
vendor/bin/phpunit --filter testMethodName tests/Unit/SomeTest.php
```

## Conventions

- Default branch: `master`. Branch prefixes: `feature/`, `bugfix/`, `hotfix/`, `refactor/`, `chore/`
- Use Conventional Commits
- Never mention AI tools in commit messages or code comments
- PHPStan level 8 (strict). All code must pass `composer check` before handoff
- Run `composer test` before handoff when executable PHP changes are made
- Keep changes minimal and scoped to the request; avoid unrelated refactors
- Do not change static analysis or formatting configuration without approval
