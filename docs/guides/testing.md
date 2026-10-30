# Testing

## Acting as an identity, principal or device

Use `Testing\Concerns\InteractsWithAuthenticationContext` in a Laravel (or Testbench) test case to act on a package
guard (`jwt` or `api_key`). Unlike Laravel's `actingAs()`, the context also authenticates every request the test then
sends through the HTTP kernel:

```php
use SineMacula\Laravel\Authentication\Testing\Concerns\InteractsWithAuthenticationContext;

final class ProfileTest extends TestCase
{
    use InteractsWithAuthenticationContext;

    public function testTheProfileShowsTheMembership(): void
    {
        $this->actingAsPrincipal($membership, guard: 'api')
            ->getJson('/me')
            ->assertOk();

        $this->assertBoundIdentity($user)
            ->assertBoundPrincipal($membership)
            ->assertBoundTenant($tenant)
            ->assertBoundDevice(null)
            ->assertBoundScopes(null);
    }
}
```

| Method                                                                  | What it does                                                                                              |
|-------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------|
| `actingAsIdentity($identity, ?$principal, ?$device, ?$scopes, ?$guard)` | Acts as the identity, as the principal given or the resolver's default, on the device given or none       |
| `actingAsPrincipal($principal, ?$device, ?$scopes, ?$guard)`            | Acts as the principal, for the identity its `getIdentity()` returns                                       |
| `actingOnDevice($device, ?$guard)`                                      | Acts on a device's session: its owner, the principal it records and the guard it records                  |
| `stopActing(?$guard)`                                                   | Ends acting: signed out for the rest of the request, and the next request uses its own credential, if any |
| `assertBoundIdentity()`, `Principal()`, `Tenant()`, `Device()`          | What the guard has bound: `null` for nothing, otherwise the same class with the same identifier           |
| `assertBoundScopes(?array $scopes)`                                     | The scopes, exactly and in order: `null` for no ceiling (a human's session), `[]` for none (a machine)    |
| `assertBoundType(?string $type)`                                        | The principal's type: its own, else its tenant's                                                          |

`actingAsIdentity()` without a principal throws an `InvalidArgumentException` when the identity has no default one, as
`setUser()` does. `actingOnDevice()` finds the owner through the guard's provider and the principal through the guard's
resolver, and throws an `InvalidArgumentException` when either is not found or when a guard is named that the device
does not record.

Every method takes the guard last and uses the default guard when it is left out; acting makes the guard the default,
as `actingAs()` does. The context is bound through the guard's trusted `authenticateAs()`, so nothing is checked: a
test can act as a revoked device, an inactive principal or a machine, which is limited to the scopes given (`[]`, none,
when the test names none), as if its credential granted them, so a test of a scope-gated route needs no real API key
(`$this->actingAsIdentity($client, scopes: ['orders:read'], guard: 'api_keys')`); scopes for a human identity throw an
`InvalidArgumentException`. Each request
the test sends fires `Authenticated`, `PrincipalAssigned` and, with a device, `DeviceAuthenticated` (which records the
device's use), as a bearer request does, and a context acted as wins over a credential the request carries.

Acting on a guard ends with `stopActing()`, when the request signs out (Laravel's `Logout` for the guard, which
`Auth::logout()`, `Auth::sessions()->signOut()` and a sign-out endpoint dispatch), or when the test acts on that guard
again; each guard keeps its own context. With `Logout` faked (`Event::fake()` without a list of events fakes it) the
helpers cannot see a sign-out, so call `stopActing()`. `Auth::forgetGuards()` creates new guards, which are not acted
on until the test acts again. A queued job a worker runs (`queue:work`, or a
`Worker` in the test) still starts signed out, as in production, and the next request is acted as again.

## Fakes

Each fake binds a fresh instance in place of the package's or the application's binding with `fake()` (in the
application's container, or in the one given) and keeps what it is given instead of delivering it, so a test reads it
back: the readers below take an optional filter, `count()` counts everything, and `forget()` clears it.

| Fake                                   | Stands in for              | Reads back                                                                                                              |
|----------------------------------------|----------------------------|-------------------------------------------------------------------------------------------------------------------------|
| `Testing\FakeOneTimeCodeSender`        | `OneTimeCodeSender`        | `sent()`, `hasSent()`; `lastCodeFor($identifier, ?CodePurpose $purpose)`: the last code sent to the identifier          |
| `Testing\FakeIdentifierChangeNotifier` | `IdentifierChangeNotifier` | `sent()`, `hasSent()`; `noticesFor($identity)`: the notices about the identity's changes                                |
| `Testing\FakeBreachedPasswordChecker`  | `BreachedPasswordChecker`  | `checked()`, `hasChecked()`: the passwords it was asked about; `unavailable()` makes it throw as a service that is down |
| `Testing\FakePasswordResetLinkSender`  | `PasswordResetLinkSender`  | `sent()`, `hasSent()`; `lastTokenFor($identifier)`: the token last sent to the identifier                               |

`FakeOneTimeCodeSender::fake()` keeps every message instead of delivering it, so a test reads the code a request sent
and signs in with it:

```php
use SineMacula\Laravel\Authentication\Testing\FakeOneTimeCodeSender;

$sender = FakeOneTimeCodeSender::fake();

$this->postJson('/codes', ['phone' => '+447700900123'])->assertAccepted();

$code = $sender->lastCodeFor('+447700900123');   // the number as delivered, in E.164

$this->postJson('/sign-in/code', ['phone' => '+447700900123', 'code' => $code])->assertOk();
```

The message arrives when the delivery job runs: on a `sync` queue connection once the response is sent (a test's HTTP
request ends with it; call `$this->app->terminate()` after calling the service directly), on a faked queue when the test
runs the pushed job.

`Testing\FakeIdentifierChangeNotifier` does the same for the notices of changed identifiers:
`FakeIdentifierChangeNotifier::fake()` binds a fresh one and returns it, `noticesFor($identity)` lists the notices about
that identity's changes, and `sent()`, `hasSent()`, `count()` and `forget()` work as the sender fake's do. A notice
arrives when its queued job runs, as a code does.

`Testing\FakeBreachedPasswordChecker` stands in for your breached-password checker: `fake(['password123'])` binds a
fresh one that finds exactly those passwords breached, `unavailable()` makes it throw
`BreachedPasswordCheckUnavailableException` as a service that is down would (and `unavailable(false)` lets it answer
again), and it keeps every password it was asked about, so a test can tell whether a request reached the breached check
at all. `checked()` and `hasChecked()` take an optional filter, `count()` counts them, and `forget()` clears them:

```php
use SineMacula\Laravel\Authentication\Testing\FakeBreachedPasswordChecker;

$checker = FakeBreachedPasswordChecker::fake(['password123password']);

$this->putJson('/password', [...])->assertUnprocessable()->assertJson(['violations' => ['breached']]);

$checker->unavailable();   // fails closed: `breach_check_unavailable`, unless `when_unavailable` is `allow`
```

`Testing\FakePasswordResetLinkSender` stands in for the reset link sender: `fake()` binds a fresh one and returns it,
and it keeps every link instead of delivering it, so a test reads the token a request sent and resets with it.
`lastTokenFor($identifier)` is the token last sent to the identifier as delivered (in normal form); `sent()` and
`hasSent()` take an optional filter over the links, `count()` counts them, and `forget()` clears them. A reset code
arrives in `FakeOneTimeCodeSender`, read with `lastCodeFor($identifier, CodePurpose::PASSWORD_RESET)`:

```php
use SineMacula\Laravel\Authentication\Testing\FakePasswordResetLinkSender;

$links = FakePasswordResetLinkSender::fake();

$this->postJson('/password/forgot', ['email' => 'ada@example.test'])->assertAccepted();

$token = $links->lastTokenFor('ada@example.test');

$this->postJson('/password/reset', ['email' => 'ada@example.test', 'token' => $token, 'password' => 'a new passphrase'])->assertNoContent();
```
