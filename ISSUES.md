# Issues

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
