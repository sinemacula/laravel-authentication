# Project Overview

`sinemacula/laravel-authentication` - Stateless contextual authentication for Laravel. Distinguishes the authenticated *
*Identity** from the acting **Principal** and the issuing **Device**, exposed through Laravel's standard `Auth` facade,
middleware, and events.

- **Namespace:** `SineMacula\Laravel\Authentication`
- **Source:** `src/`
- **Type:** Library (Composer package)
- **PHP 8.3+ / Laravel 12 / 13**

## Architecture

Standalone Auth core. Sibling IAM packages (MFA, SSO, Authorization, Audit Log, IAM umbrella) are documented in
`docs/prd/` and live in their own repositories - this package has zero runtime dependencies on them.

Core model: **Identity → Principal → Device**, with optional Tenant scope. Both 2D (identity-is-principal) and
3D (identity → separate principal → tenant) adoption modes are supported by the same guards.

## Commands

```bash
composer install              # Install dependencies
composer check                # Run qlty static analysis (PHPStan level 8, PHP-CS-Fixer, CodeSniffer, etc.)
composer check -- --all --no-cache --fix  # Checks with auto-fix
composer format               # Format code via qlty
composer test                 # Run tests (Paratest, parallel execution)
composer test-coverage        # Run tests with clover coverage report

# Single test file
vendor/bin/phpunit tests/Unit/SomeTest.php

# Single test method
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
