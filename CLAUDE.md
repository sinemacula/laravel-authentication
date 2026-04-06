# Project Overview

`sinemacula/laravel-iam` — Contextual identity and access management for Laravel. Implements a multi-dimensional
identity model (Identity → Principal → Device) with MFA, SSO, activity logging, and IAM-style permissions.

- **Namespace:** `SineMacula\Laravel\Iam`
- **Source:** `src/`
- **Type:** Library (Composer package)

## Architecture

The package is organised into five modules, each with its own service provider:

| Module        | Namespace                          | Responsibility                                      |
|---------------|------------------------------------|-----------------------------------------------------|
| Auth          | `SineMacula\Laravel\Iam\Auth`      | Core contextual auth: guards, identity, principals  |
| MFA           | `SineMacula\Laravel\Iam\Mfa`       | Multi-factor authentication with driver pattern     |
| SSO           | `SineMacula\Laravel\Iam\Sso`       | Single sign-on with driver pattern                  |
| Activity Log  | `SineMacula\Laravel\Iam\ActivityLog` | Event-driven auth activity auditing               |
| Permissions   | `SineMacula\Laravel\Iam\Permissions` | RBAC + IAM-style policy evaluation               |

All modules depend only on Auth (the core). No cross-dependencies between non-core modules.

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
