<h1 align="center">Laravel Authentication</h1>

<div align="center">

[![Latest Stable Version](https://img.shields.io/packagist/v/sinemacula/laravel-authentication.svg)](https://packagist.org/packages/sinemacula/laravel-authentication)
[![PHP Version](https://img.shields.io/packagist/dependency-v/sinemacula/laravel-authentication/php.svg)](https://packagist.org/packages/sinemacula/laravel-authentication)
[![Laravel Version](https://img.shields.io/packagist/dependency-v/sinemacula/laravel-authentication/laravel/framework.svg?label=laravel)](https://packagist.org/packages/sinemacula/laravel-authentication)
[![Build Status](https://github.com/sinemacula/laravel-authentication/actions/workflows/tests.yml/badge.svg?branch=master)](https://github.com/sinemacula/laravel-authentication/actions/workflows/tests.yml)
[![Quality Gates](https://github.com/sinemacula/laravel-authentication/actions/workflows/quality-gates.yml/badge.svg?branch=master)](https://github.com/sinemacula/laravel-authentication/actions/workflows/quality-gates.yml)
[![Maintainability](https://qlty.sh/gh/sinemacula/projects/laravel-authentication/maintainability.svg)](https://qlty.sh/gh/sinemacula/projects/laravel-authentication)
[![Code Coverage](https://qlty.sh/gh/sinemacula/projects/laravel-authentication/coverage.svg)](https://qlty.sh/gh/sinemacula/projects/laravel-authentication)
[![Total Downloads](https://img.shields.io/packagist/dt/sinemacula/laravel-authentication.svg)](https://packagist.org/packages/sinemacula/laravel-authentication)
[![License](https://img.shields.io/github/license/sinemacula/laravel-authentication.svg)](LICENSE)

</div>

Stateless contextual authentication for Laravel. Distinguishes the authenticated **Identity** from the acting
**Principal** and the issuing **Device**, exposed through Laravel's standard `Auth` facade, middleware, and events.

Drops into Laravel's existing auth machinery - same `Auth::check()`, `Auth::user()`, `auth()->guard('api')`, same
middleware, same events. Adds contextual accessors (`Auth::identity()`, `Auth::principal()`, `Auth::device()`) and
ships a hardened JWT guard.

## Core Concept

| Concept       | What it is                                                                                 |
|---------------|--------------------------------------------------------------------------------------------|
| **Identity**  | Who logged in. The account behind the request - a person or a service account.             |
| **Principal** | Who the request is acting as. Often the same as the identity; can be a role or membership. |
| **Device**    | Which client obtained the login - a browser, a mobile app, a CLI session.                  |
| **Tenant**    | The isolation boundary the principal acts within. Optional, for multi-tenant apps.         |
| **Type**      | An optional label on the principal, or its tenant - e.g. `"staff"` vs `"client_admin"`.    |

Start **2D** (the identity is the principal) and grow into **3D** (identity → principal → tenant) without changing
guards. Access tokens are self-verifying JWTs; refresh is stateful, held per device, so replays and revoked sessions
are caught on the server.

## Features

- **JWT guard** with guard-bound, kid-rotated HMAC tokens, refresh rotation with replay detection, and a browser
  refresh cookie with CSRF checks.
- **Sign-in methods**: password, one-time code to a phone or email, and passkeys, behind one contract that SSO and
  custom methods plug into.
- **Sessions per device**: list, sign out, sign out everywhere, revoke on security changes, and switch principal.
- **Machine credentials**: API keys and OAuth 2.0 client credentials for non-human identities, with scopes.
- **Account lifecycle**: password policy, password reset, identifier verification and changing an email or phone.
- **Per-guard audiences**: which methods and principal types a guard admits, and lifetimes per principal type.
- **Database rate limits**, enumeration-resistant responses, and read-replica and Octane safety.
- **Events** for every sign-in, refresh, revocation and failure, with one shared context and never a secret.
- **Localisable messages**: the `401` and `429` messages translate through your `lang/{locale}.json`, and every other
  answer is a code your application words.
- **Extension points** for MFA, authorization, SSO and audit packages, each with a default that works without them.

## Installation

```bash
composer require sinemacula/laravel-authentication
```

## Configuration

Publish the config and the migrations, migrate, and generate a signing key:

```bash
php artisan vendor:publish --tag=authentication-config
php artisan vendor:publish --tag=authentication-migrations
php artisan migrate

echo "AUTHENTICATION_JWT_KEY=$(openssl rand -base64 48)" >> .env
```

Register a `jwt` guard and a `model` provider in `config/auth.php`:

```php
'guards' => [
    'api' => [
        'driver'   => 'jwt',
        'provider' => 'users',
    ],
],

'providers' => [
    'users' => [
        'driver' => 'model',
        'model'  => App\Models\AppUser::class,
    ],
],
```

See [Installation](docs/guides/installation.md) for keys and providers, and [Configuration](docs/guides/configuration.md)
for every option.

## Usage

Give your user model the contracts and traits:

```php
namespace App\Models;

use Illuminate\Database\Eloquent\Relations\MorphMany;
use Illuminate\Foundation\Auth\User;
use SineMacula\Laravel\Authentication\Concerns\ActsAsPrincipal;
use SineMacula\Laravel\Authentication\Concerns\Authenticatable;
use SineMacula\Laravel\Authentication\Contracts\HasDevices;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Models\Device;

class AppUser extends User implements Identity, Principal, HasDevices
{
    use Authenticatable, ActsAsPrincipal;

    public function devices(): MorphMany
    {
        return $this->morphMany(Device::class, 'authenticatable');
    }
}
```

Sign in through the guard's session service, and protect routes as with any Laravel guard:

```php
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;

Route::post('/login', function (Request $request) {
    $credentials = $request->validate([
        'email'    => ['required', 'string'],
        'password' => ['required', 'string'],
    ]);

    $result = Auth::sessions('api')->signIn('password', $credentials, SignInContext::fromRequest($request));

    abort_unless($result->isSignedIn(), 401);

    return [
        'access_token'  => $result->session->tokens->accessToken,
        'refresh_token' => $result->session->tokens->refreshToken,
    ];
});

Route::middleware('auth:api')->get('/me', fn () => Auth::identity());
```

### Guides

| Guide                                                     | Covers                                                                   |
|-----------------------------------------------------------|--------------------------------------------------------------------------|
| [Installation](docs/guides/installation.md)               | Keys, guards and providers, the `401`, localisation, access-only mode    |
| [Identity models](docs/guides/identity-models.md)         | 2D and 3D models, principal types, identifiers, verification, activity   |
| [Signing in](docs/guides/signing-in.md)                   | The session service, one-time codes, passkeys, custom methods, factors   |
| [Refreshing](docs/guides/refreshing.md)                   | Refresh, the refresh cookie and replay detection                         |
| [Sessions](docs/guides/sessions.md)                       | Switching principal, signing out, listing devices and revocation         |
| [Passwords](docs/guides/passwords.md)                     | Password policy, setting a password and password reset                   |
| [Changing identifiers](docs/guides/identifier-changes.md) | Changing an email address or phone number                                |
| [Machine credentials](docs/guides/machine-credentials.md) | Non-human identities, scopes, API keys and client credentials            |
| [Events](docs/guides/events.md)                           | Every event, its context and the failure outcomes                        |
| [Configuration](docs/guides/configuration.md)             | Every configuration key                                                  |
| [Operations](docs/guides/operations.md)                   | Read replicas, Octane, key rotation, pruning and the configuration check |
| [Testing](docs/guides/testing.md)                         | Acting as an identity in your tests, context assertions and fakes        |
| [Extending](docs/guides/extending.md)                     | Extension points and the MFA, authorization, SSO and audit seams         |

The security and lifecycle contracts behind them, for maintainers and reviewers, are in
[docs/design](docs/design/README.md).

## Requirements

- PHP ^8.3 (extensions: hash, mbstring, openssl; sodium, bundled with PHP, for EdDSA passkeys)
- Laravel ^12.40 || ^13.3

## Testing

```bash
composer test               # all suites in parallel (Paratest)
composer test:coverage      # all suites with clover coverage
composer test:unit          # unit suite only
composer test:feature       # feature suite only
composer test:integration   # integration suite only
composer test:performance   # performance budget suite (serial)
composer test:mutation      # scoped mutation gate
composer test:mutation:full # full mutation suite (no thresholds)
composer bench              # PHPBench hot-path benchmarks
composer check              # static analysis + style
composer format             # format the codebase
composer smells             # advisory code smells (duplication, complexity)
```

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for a list of notable changes.

## Contributing

Contributions are welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on branching, commits, code
quality, and pull requests.

## Security

If you discover a security vulnerability, please report it responsibly. See [SECURITY.md](SECURITY.md) for the
disclosure policy and contact details.

## License

Licensed under the [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0).
