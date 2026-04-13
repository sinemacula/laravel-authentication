# Issues

## PR #4 - refactor/guard-scoped-jwt-service

### php-tst-049: Reflection into private state (Medium)

1. **`tests/Feature/AuthServiceProviderGuardConfigTest.php`** -
   `readGuardProperty` uses reflection to read private
   `identifierField` on `BasicGuard`.

2. **`tests/Feature/Jwt/JwtTokenServiceFactoryTest.php`** -
   `readServiceProperty` uses reflection to read private
   properties of `JwtTokenService` in 6 of 10 test methods.


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

## Cross-PR: Recurring patterns

### Reflection-based test assertions

Several test files use reflection to inspect private
properties. Converting to behavioural tests requires
database setup and full authentication flows, which is a
significant refactor.
