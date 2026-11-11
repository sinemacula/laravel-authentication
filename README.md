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
**Principal** and the **Session** it signed in on, exposed through Laravel's standard `Auth` facade, middleware, and
events.

Drops into Laravel's existing auth machinery - same `Auth::check()`, `Auth::user()`, `auth()->guard('api')`, same
middleware, same events. Adds contextual accessors (`Auth::identity()`, `Auth::principal()`, `Auth::tenant()`,
`Auth::session()`) and a JWT guard.

## Core Concept

| Concept         | What it is                                                                                                                    |
|-----------------|-------------------------------------------------------------------------------------------------------------------------------|
| **Identity**    | Who logged in. The account behind the request - a person or a service account.                                                |
| **Principal**   | Who the request is acting as. Often the same as the identity; can be a role or membership.                                    |
| **Session**     | One sign-in, on one application, on one device: a browser, a mobile app, a CLI. Refresh and revocation live here.             |
| **Tenant**      | The isolation boundary a principal belongs to; a session acts in one, its active tenant (`Auth::tenant()`). Optional.         |
| **Application** | The app being signed into, e.g. `admin`, `console`, `mobile`. Each application is a guard with its own methods and lifetimes. |

Start **2D** (the identity is the principal) and grow into **3D** (identity -> principal -> tenant) without changing
guards. Access tokens are self-verifying JWTs; refresh is stateful, held per session, so replays and revoked sessions
are caught on the server.

## Features

- A JWT guard with guard-bound, kid-rotated HMAC tokens in a private profile that borrows RFC 9068's claims
  (`client_id`, `auth_time`, `amr`, an `at+jwt` header type) and OpenID Connect's `sid`. Refresh tokens rotate with
  replay detection and travel in the body or, for a browser application, in a host-only `HttpOnly` cookie with CSRF
  checks.
- One method per action, taking plain values. A controller reads the request with the package's helpers
  (`SignInContext::fromRequest()`, `ClientContext::fromRequest()`, `RequestBody::fields()`, the refresh transport's
  `extract()`, `PendingCredential::extract()`, `SignedLink::fromRequest()`, `ClientCredentialsRequest::extract()`) or
  builds the values itself (`PresentedRefreshToken::fromBody()`, say).
- Sign-in by password, one-time code to a phone or email, and passkeys, behind one contract that custom methods plug
  into; a further-factor package can use passkeys as a factor too.
- External sign-in: a result an external identity provider verified, handed over by a trusted adapter, signs in only
  the identity a link contract maps its connection, issuer and subject to, never by email.
- One-time codes as challenges with an id the check names, an attempt budget kept across resends, a delivery cap per
  destination and a binding to their purpose.
- Pending sessions: a sign-in that still owes a further factor or a choice of principal waits with a short-lived
  credential that allows only the actions it owes. An identity's factor policy and a tenant's authentication policy
  each set a requirement judged against the session's proofs, and a tenant may require single sign-on.
- Sessions with timestamped proofs, step-up, reauthentication and per-operation freshness; listing, sign-out and sign
  out everywhere; revocation on security changes, deactivation and deletion; and switching the principal or the active
  tenant.
- `Auth::caller()` reads who a request is from the access, refresh or pending credential its route authenticates with,
  so an application can scope its own route bindings.
- `Auth::context()` gives what a request is authenticated as in plain values for policy conditions, built from what the
  guard validated and never from input, with keys a sibling package or the application contributes under a namespace
  of its own.
- Machine credentials: API keys and OAuth 2.0 client credentials for non-human identities, with scopes.
- Account lifecycle: password policy, changing or establishing a password, password reset, identifier verification and
  changing an email or phone.
- Per-application settings: which sign-in methods and machine credentials each application allows (none until it
  lists them), whether identifiers must be verified, and its lifetimes.
- Access contracts: whether a principal may use an application and whether it may act in a tenant, answered by your
  application (by default any principal may use any application, in its own tenant only).
- Database rate limits, enumeration-resistant responses, and read-replica and Octane safety.
- Every token, pending credential, API key, code and link the package hands out is a `Secret` that refuses to be cast
  to a string, encoded, serialised or dumped until your code reveals it. `SecretResponse::json()` and the
  `authentication.no-store` route middleware answer with `Cache-Control: no-store`.
- Events for every sign-in, refresh, revocation and failure, with one shared context and never a secret.
- The `401` and `429` messages translate through your `lang/{locale}.json`; every other answer is a code your
  application words.
- Extension points for MFA, authorisation, SSO and audit packages, each with a default that works without them.

## Installation

```bash
composer require sinemacula/laravel-authentication
```

## Configuration

Publish the config and the migrations, migrate, generate a signing key, and name the issuer and audience every token
carries (a guard without them fails closed):

```bash
php artisan vendor:publish --tag=authentication-config
php artisan vendor:publish --tag=authentication-migrations
php artisan migrate

echo "AUTHENTICATION_JWT_KEY=$(openssl rand -base64 48)" >> .env
echo "AUTHENTICATION_JWT_ISSUER=https://auth.example.com" >> .env
echo "AUTHENTICATION_JWT_AUDIENCE=https://api.example.com" >> .env
```

Register a `jwt` guard and a `model` provider in `config/auth.php`. Each guard is an application, and allows only the
sign-in methods it lists:

```php
'guards' => [
    'api' => [
        'driver'      => 'jwt',
        'provider'    => 'users',
        'application' => ['methods' => ['password']],
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
use SineMacula\Laravel\Authentication\Contracts\HasSessions;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Models\Session;

class AppUser extends User implements Identity, Principal, HasSessions
{
    use Authenticatable, ActsAsPrincipal;

    public function sessions(): MorphMany
    {
        return $this->morphMany(Session::class, 'authenticatable');
    }
}
```

Sign in through the guard's session service, and protect routes as with any Laravel guard:

```php
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Secrets\SecretResponse;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;

Route::post('/login', function (Request $request) {
    $credentials = $request->validate([
        'email'    => ['required', 'string'],
        'password' => ['required', 'string'],
    ]);

    $result = Auth::sessions('api')->signIn('password', $credentials, SignInContext::fromRequest($request));

    abort_unless($result->isSignedIn(), 401);

    // The tokens are secrets: SecretResponse reveals them into the body and marks it not to be stored.
    return SecretResponse::json([
        'access_token'  => $result->session->tokens->accessToken,
        'expires_in'    => $result->session->tokens->expiresIn,
        'refresh_token' => $result->session->tokens->refreshToken,
    ]);
});

Route::middleware('auth:api')->get('/me', fn () => Auth::identity());
```

### Guides

| Guide                                                     | Covers                                                                                                                 |
|-----------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------|
| [Installation](docs/guides/installation.md)               | Keys, guards and providers, the `401`, localisation, access-only mode                                                  |
| [Identity models](docs/guides/identity-models.md)         | 2D and 3D models, identifiers, verification, activity                                                                  |
| [Signing in](docs/guides/signing-in.md)                   | The session service, pending sessions, one-time codes, passkeys, custom methods, factors                               |
| [Refreshing](docs/guides/refreshing.md)                   | Refresh, the refresh cookie, what a refresh judges and replay detection                                                |
| [Sessions](docs/guides/sessions.md)                       | Proofs, step-up, reauthentication, freshness, switching, signing out, listing sessions, revocation, the caller         |
| [Passwords](docs/guides/passwords.md)                     | Password policy, setting a password and password reset                                                                 |
| [Changing identifiers](docs/guides/identifier-changes.md) | Changing an email address or phone number                                                                              |
| [Machine credentials](docs/guides/machine-credentials.md) | Non-human identities, scopes, API keys and client credentials                                                          |
| [Events](docs/guides/events.md)                           | Every event, its context and the failure outcomes                                                                      |
| [Configuration](docs/guides/configuration.md)             | Every configuration key                                                                                                |
| [Operations](docs/guides/operations.md)                   | Read replicas, Octane, key rotation, pruning and the configuration check                                               |
| [Testing](docs/guides/testing.md)                         | Acting as an identity in your tests, context assertions and fakes                                                      |
| [Extending](docs/guides/extending.md)                     | Extension points and the MFA, authorisation, SSO and audit seams                                                       |

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
