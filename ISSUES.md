# Issues

## PR #4 - refactor/guard-scoped-jwt-service

### php-tst-049: Reflection into private state (Medium)

1. **`tests/Feature/AuthServiceProviderGuardConfigTest.php`** -
   `readGuardProperty` uses reflection to read private
   `identifierField` on `BasicGuard`.

2. **`tests/Feature/Jwt/JwtTokenServiceFactoryTest.php`** -
   `readServiceProperty` uses reflection to read private
   properties of `JwtTokenService` in 6 of 10 test methods.

### auth-jwt-memoization: Auth::jwt() not memoized (Low)

`AuthManager::jwt(?string $guard)` calls
`JwtTokenServiceFactory::forGuard()` which constructs a new
`JwtTokenService` on every invocation. Guards hold their own
instance so the hot path (verification) is unaffected, but
repeated issuance calls in a single request pay the
construction cost each time. Consider adding a keyed cache
in the factory.

## PR #5 - feature/per-guard-principal-resolvers

### php-nam-030: One class per file (Medium)

Six inline resolver classes should be extracted to their
own files:

- `AuthServiceProviderGuardConfigBasicResolver`
- `AuthServiceProviderGuardConfigJwtResolver`
- `AuthServiceProviderGuardConfigGlobalResolver`
- `AuthServiceProviderTestGuardScopedResolver`
- `AuthServiceProviderTestReplacementResolver`
- `GuardScopedPrincipalResolverIntegrationResolver`

### php-nam-039: Redundant class name prefixes (Low)

Three resolver classes repeat the test-class name as a
prefix. If extracted to separate files, use shorter names
like `BasicResolverStub`, `JwtResolverStub`,
`GlobalResolverStub`.

### php-tst-014: Legacy @SuppressWarnings (Low)

`readObjectProperty` in `AuthServiceProviderGuardConfigTest`
and `AuthServiceProviderTest` uses `@SuppressWarnings`
annotation instead of a PHPUnit attribute.

## PR #7 - Formalize explicit Eloquent device boundary

### php-ana-004: #[\Override] on trait methods (N/A)

9 methods in `ActsAsDevice` trait implement
`Device`/`EloquentDevice` interface methods but cannot use
`#[\Override]` - PHP 8.3 causes a fatal error when the
using class doesn't implement the interface.
Scanner false positive.

### php-ana-004: #[\Override] on boot() (N/A)

`AuthServiceProvider::boot()` - Laravel's
`ServiceProvider` does not declare `boot()`, so
`#[\Override]` causes a fatal error.
Scanner false positive.

## PR #8 - Preserve principal context during refresh

### Reuses PRINCIPAL_UNRESOLVED for pid mismatch (Low)

When the refresh token carries `pid` and the resolved
principal doesn't match, the failure reuses
`RefreshFailureReason::PRINCIPAL_UNRESOLVED`. A dedicated
`PRINCIPAL_MISMATCH` reason would give better SIEM
attribution. Not a blocker.

### Complexity: Test method lines (Medium)

8 test methods exceed the 30-line threshold (31-61 lines).
Largest offenders:

- `testRefreshRotatesAndIssuesNewTokenPairOnSuccess` (61)
- `testRefreshRevokesDeviceOnRotationReuse...` (38)
- `testRefreshReturnsNullWhenPrincipalIsInactive` (37)

## PR #9 - refactor/injected-auth-config

### Rejected: inject runtime auth config

PR rejected. The `Config` facade is idiomatic Laravel and
the right tool for a Laravel package reading Laravel config.
The static property pattern
(`AbstractGuard::$sharedTimingConfig`,
`Device::$runtimeConfig`) introduced worse global state
than what it replaced. Changes have been stripped from the
branch and will be skipped during upcoming PR rebases.

## Cross-PR: Recurring patterns

### Test method complexity

Multiple PRs have test methods exceeding the 30-line
threshold. Most are integration tests with extensive
arrange/act/assert blocks. Extracting assertion or setup
helpers would reduce line counts but may hurt readability
for complex end-to-end scenarios.

### Reflection-based test assertions

Several test files use reflection to inspect private
properties. Converting to behavioural tests requires
database setup and full authentication flows, which is a
significant refactor.

### Inline test stub classes

Multiple test files define stub resolver classes inline.
Extracting to `tests/Unit/Stubs/` would fix
one-class-per-file and redundant naming violations
simultaneously.
