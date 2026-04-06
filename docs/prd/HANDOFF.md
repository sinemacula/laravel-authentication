# Build Handoff — laravel-iam Monorepo

This document is for the Build phase. It captures the current state of the repository, the target structure, and the conventions each package build must follow. Read this **before** opening any individual PRD.

## Directive: Rewrite, not refactor

A working prototype implementation exists at `src/` with 306 passing tests at PHPStan level 8. This prototype is **reference material only**.

- The PRDs in this directory are the authoritative specification
- Do not preserve the prototype line-for-line or incrementally transform it
- Do not treat the existing test suite as a baseline to preserve — Build will write fresh tests against the PRD's acceptance criteria
- Once a package is rewritten and its tests pass, the corresponding legacy directory in `src/` can be deleted
- The prototype proves the ideas work and shows tested integration patterns with Laravel's auth infrastructure — study it for gotchas, then build fresh

## Current repository structure (pre-rewrite)

```
laravel-iam/
├── src/                         ← single-composer prototype (LEGACY, reference only)
│   ├── Auth/
│   ├── Mfa/
│   ├── Sso/
│   ├── ActivityLog/             ← conceptually: AuditLog (see renames below)
│   ├── Permissions/             ← conceptually: Authorization (see renames below)
│   └── IamServiceProvider.php
├── tests/                       ← prototype tests (legacy)
├── config/                      ← prototype configs (legacy)
├── composer.json                ← top-level: SineMacula\Laravel\Iam\ → src/
└── docs/prd/                    ← PRDs to build from (this directory)
```

## Target repository structure (post-rewrite)

The monorepo adopts a `packages/` directory layout so each package has its own `composer.json`, making extraction to separate repositories a file-move operation rather than a restructure.

```
laravel-iam/
├── packages/
│   ├── laravel-authentication/
│   │   ├── composer.json            ← sinemacula/laravel-authentication
│   │   ├── src/                     ← SineMacula\Laravel\Authentication\
│   │   ├── tests/
│   │   ├── config/
│   │   └── README.md
│   ├── laravel-mfa/                 ← sinemacula/laravel-mfa — SineMacula\Laravel\Mfa\
│   ├── laravel-sso/                 ← sinemacula/laravel-sso — SineMacula\Laravel\Sso\
│   ├── laravel-authorization/       ← sinemacula/laravel-authorization — SineMacula\Laravel\Authorization\
│   ├── laravel-audit-log/           ← sinemacula/laravel-audit-log — SineMacula\Laravel\AuditLog\
│   └── laravel-iam/                 ← sinemacula/laravel-iam (umbrella) — SineMacula\Laravel\Iam\
├── composer.json                    ← top-level monorepo: path repositories to packages/*
├── phpunit.xml.dist                 ← top-level: runs all packages' tests
├── .qlty/                           ← unchanged, LOCKED (do not modify)
└── docs/prd/                        ← PRDs + this handoff (unchanged)
```

Each `packages/<name>/composer.json` declares its own dependencies, PSR-4 autoload, and dev dependencies. The top-level `composer.json` references each package via Composer path repositories so the whole monorepo can be installed and tested together during development.

## Package-to-PRD mapping

| # | PRD                             | Legacy location         | Target location                    | Target namespace                        | Composer package                      |
|---|---------------------------------|-------------------------|------------------------------------|------------------------------------------|-----------------------------------------|
| 01 | `01-laravel-authentication.md`            | `src/Auth/`             | `packages/laravel-authentication/`           | `SineMacula\Laravel\Authentication`               | `sinemacula/laravel-authentication`             |
| 02 | `02-laravel-mfa.md`             | `src/Mfa/`              | `packages/laravel-mfa/`            | `SineMacula\Laravel\Mfa`                | `sinemacula/laravel-mfa`              |
| 03 | `03-laravel-sso.md`             | `src/Sso/`              | `packages/laravel-sso/`            | `SineMacula\Laravel\Sso`                | `sinemacula/laravel-sso`              |
| 04 | `04-laravel-authorization.md`   | `src/Permissions/` ⟶ renamed | `packages/laravel-authorization/` | `SineMacula\Laravel\Authorization`     | `sinemacula/laravel-authorization`    |
| 05 | `05-laravel-audit-log.md`       | `src/ActivityLog/` ⟶ renamed | `packages/laravel-audit-log/`     | `SineMacula\Laravel\AuditLog`           | `sinemacula/laravel-audit-log`        |
| 06 | `06-laravel-iam.md`             | `src/IamServiceProvider.php` | `packages/laravel-iam/`            | `SineMacula\Laravel\Iam`                | `sinemacula/laravel-iam` (umbrella)   |

**Renames to note:**
- `Permissions` → `Authorization` (more precise — package does more than permissions)
- `ActivityLog` → `AuditLog` (enterprise terminology; avoids collision with `spatie/laravel-activitylog`)

## Cross-cutting build constraints

These apply to every package. The PRDs describe capabilities; these are the non-negotiable implementation constraints.

- **Target**: PHP 8.3+, Laravel 13+
- **Static analysis**: PHPStan level 8 strict (Larastan). Must pass clean.
- **Standards**: PSR-12, `declare(strict_types = 1)` in every file, `@author Ben Carey <bdmc@sinemacula.co.uk>`, `@copyright 2026 Sine Macula Limited.`
- **Attributes**: mixed usage — PHP/Laravel attributes where they add clarity (casts, scopes, simple metadata), traditional code for complex behaviour (relationships, dynamic logic)
- **Primary keys**: ULIDs
- **Foreign keys to identities**: polymorphic (`authenticatable_type` + `authenticatable_id`) — works with any identity type
- **Table names**: unprefixed defaults, configurable via a `table_names` config section
- **No soft deletes** by default (timestamps only)
- **Migrations**: publishable per package, no idempotency checks (assume clean install, document clearly)
- **.qlty/ is LOCKED**: do not modify any file under `.qlty/` — static analysis config is enforced and cannot be relaxed
- **No coupling**: no runtime dependency on `sinemacula/laravel-repositories`, `sinemacula/laravel-api-toolkit`, or any other `sinemacula/*` package (except where the umbrella explicitly requires the five sub-packages)
- **Standalone guarantee**: each sub-package must install and function in a fresh Laravel app without any of its sibling packages present
- **Cross-package integration**: via service container bindings only. Default bindings in each standalone package are no-ops or null implementations. The umbrella (`laravel-iam`) overrides them with real bridges.
- **Testing**: PHPUnit 12.x + Orchestra Testbench. Target ≥90% coverage on managers, guards, evaluators, drivers, and middleware.

## Build order

The packages can technically be built in any order (they're standalone), but this order minimises context-switching:

1. **`01-laravel-authentication`** first — it's the foundation; building it first lets you verify the standalone-with-no-cross-deps pattern before applying it to the others
2. **`02-laravel-mfa`**, **`03-laravel-sso`**, **`04-laravel-authorization`**, **`05-laravel-audit-log`** — independent, can be built in any order or in parallel
3. **`06-laravel-iam`** last — the umbrella glue depends on all five sub-packages existing

## Reference patterns worth studying in the legacy `src/`

Worth a few minutes of reading before you rewrite a given package, for the Laravel-integration gotchas the prototype already solved:

| Package | Look at | Why |
|---|---|---|
| laravel-authentication | `src/Auth/Guards/AbstractGuard.php` | Full Laravel auth event lifecycle — which events, when, with what parameters |
| laravel-authentication | `src/Auth/Guards/JwtGuard.php` | JWT payload validation using array-based access (avoids stdClass PHPStan issues) |
| laravel-authentication | `src/Auth/Providers/ModelProvider.php` | How to bridge Eloquent to Laravel's UserProvider contract cleanly |
| laravel-mfa | `src/Mfa/Drivers/` | Driver pattern with runtime `class_exists()` checks for optional dependencies |
| laravel-sso | `src/Sso/Drivers/Auth0Driver.php` | OAuth2 flow using Laravel's HTTP client, no SDK deps |
| laravel-authorization | `src/Permissions/Evaluation/PolicyEvaluator.php` | AWS IAM 4-step evaluation logic (implicit deny → explicit deny → allow → implicit deny) |
| laravel-audit-log | `src/ActivityLog/Listeners/` | Laravel auth event listener patterns — how to resolve the current identity safely |
| laravel-iam | `src/IamServiceProvider.php` | (Currently minimal; umbrella's integration glue is the main work) |

**Specifically worth avoiding** (lessons the prototype learned the hard way):

- Do NOT put `@phpstan-ignore` tags inside PHPDoc blocks followed by other tags — PHPStan parses `@phpstan-ignore` greedily and consumes subsequent tags. Use inline `// @phpstan-ignore identifier` at end of code line, or `/** @phpstan-ignore identifier */` on its own line immediately before the offending line.
- Do NOT return narrower types than parent interfaces (e.g., `array<string, mixed>` when the parent says `array`) — PHPStan flags this as `method.childParameterType`. Match the parent exactly.
- Laravel's `Guard::setUser()` is inferred as returning `$this` — returning `static` or `void` triggers `method.childReturnType`. Return `$this` explicitly.
- The qlty-bundled PHPStan does NOT load `phpstan-mockery` even if installed via extension-installer. Test mocks must either avoid generic Mockery chains or use `/** @phpstan-ignore method.notFound */` block comments (inline `//` comments get stripped by the formatter).

## Top-level monorepo composer.json post-rewrite

After all six packages are rewritten, the top-level `composer.json` changes from a single-package `require` to a workspace-style setup with path repositories to each `packages/*`. The `autoload` section is removed (each sub-package owns its own PSR-4 mapping). Development tooling (`phpunit`, `phpstan`, `php-cs-fixer`) stays at the top level and operates across all packages.

`phpunit.xml.dist` updates to discover tests under `packages/*/tests/` so the monorepo test suite continues to run all packages as one job.

## After v1.0.0 — the split

Once all six packages are rewritten, tested, and stable:

1. Each `packages/<name>/` directory is extracted to its own GitHub repository (`sinemacula/laravel-authentication`, etc.)
2. Path repositories in the top-level `composer.json` are replaced with Packagist references
3. The `laravel-iam` umbrella package stays in this repository; the other five leave
4. `MIGRATION-SPLIT.md` at the monorepo root documents the procedure

This split is a hard release dependency for v1.0.0 of the umbrella — it cannot ship until the sub-packages are independently published.

## Build-phase checklist per package

Before declaring a package rewrite complete, verify:

- [ ] All P0 requirements from the PRD are implemented with tests covering the acceptance criteria
- [ ] `composer check` passes (PHPStan level 8 strict, PHP-CS-Fixer, CodeSniffer)
- [ ] `composer test` passes with ≥90% coverage on manager/driver/guard/evaluator layers
- [ ] Package installs standalone in a fresh Laravel app (no sibling package dependencies)
- [ ] README covers installation, configuration, and at least one worked example per the PRD's key capabilities
- [ ] Publishable migrations (if any) run cleanly against fresh MySQL, PostgreSQL, and SQLite databases
- [ ] No runtime dependency on `sinemacula/*` sibling packages (`composer.json` inspection + CI check)
- [ ] `.qlty/` directory is untouched
- [ ] Corresponding legacy `src/` directory is deleted (or explicitly left for final cleanup)
