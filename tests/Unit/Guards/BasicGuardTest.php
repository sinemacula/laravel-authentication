<?php

declare(strict_types = 1);

namespace Tests\Unit\Guards;

use Illuminate\Auth\Events\Attempting;
use Illuminate\Auth\Events\Authenticated;
use Illuminate\Auth\Events\Failed;
use Illuminate\Auth\Events\Login;
use Illuminate\Auth\Events\Validated;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Http\Request;
use Illuminate\Support\Timebox;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use Mockery\MockInterface;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\IdentityProvider;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\PrincipalResolver;
use SineMacula\Laravel\Authentication\Events\PrincipalAssigned;
use SineMacula\Laravel\Authentication\Guards\BasicGuard;

/**
 * Unit tests for the BasicGuard contextual guard.
 *
 * Exercises HTTP Basic credential extraction, timing-safe credential
 * validation via the inherited Timebox path, identity-as-principal
 * resolution, and the login/logout state cycle. Uses a plain PHPUnit
 * TestCase because the BasicGuard takes its identifier field via the
 * constructor (no facade dependency). The Request collaborator is a
 * real Symfony/Illuminate `Request` instance built via
 * `Request::create(...)` (per php-tst-034 fakes preference for
 * Symfony value objects).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 *
 * @internal
 */
#[CoversClass(BasicGuard::class)]
final class BasicGuardTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    /** @var string The guard name forwarded to BasicGuard's constructor. */
    private const string GUARD_NAME = 'basic-test';

    /** @var string The email used across the happy-path Basic credentials fixtures. */
    private const string ALICE_EMAIL = 'alice@example.com';

    /** @var \Mockery\MockInterface&\SineMacula\Laravel\Authentication\Contracts\IdentityProvider The mocked identity provider collaborator. */
    private MockInterface $provider;

    /** @var \Mockery\MockInterface&\SineMacula\Laravel\Authentication\Contracts\PrincipalResolver The mocked principal resolver collaborator. */
    private MockInterface $resolver;

    /** @var \Illuminate\Contracts\Events\Dispatcher&\Mockery\MockInterface The mocked event dispatcher collaborator. */
    private MockInterface $events;

    /** @var \Illuminate\Support\Timebox&\Mockery\MockInterface The mocked timebox collaborator. */
    private MockInterface $timebox;

    /**
     * Build fresh collaborator mocks before each test.
     *
     * @return void
     */
    protected function setUp(): void
    {
        parent::setUp();

        $this->provider = \Mockery::mock(IdentityProvider::class);
        $this->resolver = \Mockery::mock(PrincipalResolver::class);
        $this->events   = \Mockery::mock(Dispatcher::class);
        $this->timebox  = \Mockery::mock(Timebox::class);

        // Default: Timebox::call() invokes the callback directly so
        // credential validation paths run deterministically.
        $this->timebox->shouldReceive('call')
            ->byDefault()
            ->andReturnUsing(static fn (callable $callback): mixed => $callback(new Timebox));
    }

    /**
     * A request with no Authorization header returns null from `user()`.
     *
     * @return void
     */
    public function testUserReturnsNullWhenNoCredentialsPresent(): void
    {
        $guard = $this->makeGuard($this->makeRequest(null, null));

        $this->provider->shouldNotReceive('retrieveByCredentials');
        $this->events->shouldNotReceive('dispatch');

        self::assertNull($guard->user());
    }

    /**
     * A request with a username but no password returns null.
     *
     * @return void
     */
    public function testUserReturnsNullWhenPasswordMissing(): void
    {
        $guard = $this->makeGuard($this->makeRequest(self::ALICE_EMAIL, null));

        $this->provider->shouldNotReceive('retrieveByCredentials');
        $this->events->shouldNotReceive('dispatch');

        self::assertNull($guard->user());
    }

    /**
     * When `retrieveByCredentials()` returns null, `user()` fires
     * `Attempting` and `Failed` and returns null.
     *
     * @return void
     */
    public function testUserReturnsNullWhenIdentifierDoesNotResolve(): void
    {
        $guard = $this->makeGuard($this->makeRequest('ghost@example.com', 'secret'));

        $credentials = [
            'email'    => 'ghost@example.com',
            'password' => 'secret',
        ];

        $this->provider->shouldReceive('retrieveByCredentials')
            ->once()
            ->with($credentials)
            ->andReturnNull();

        $this->provider->shouldNotReceive('validateCredentials');
        $this->resolver->shouldNotReceive('resolve');

        $dispatched = [];

        $this->events->shouldReceive('dispatch')
            ->andReturnUsing(static function (object $event) use (&$dispatched): void {
                $dispatched[] = $event::class;
            });

        self::assertNull($guard->user());
        self::assertSame([Attempting::class, Failed::class], $dispatched);
    }

    /**
     * When `validateCredentials()` returns false, `user()` fires
     * `Attempting` and `Failed` and returns null. The `Validated`
     * event is NOT emitted because the hasher check failed.
     *
     * @return void
     */
    public function testUserReturnsNullWhenCredentialsValidationFails(): void
    {
        $guard = $this->makeGuard($this->makeRequest(self::ALICE_EMAIL, 'wrong'));

        $identity = \Mockery::mock(Identity::class);

        $this->provider->shouldReceive('retrieveByCredentials')
            ->once()
            ->andReturn($identity);
        $this->provider->shouldReceive('validateCredentials')
            ->once()
            ->with($identity, ['email' => self::ALICE_EMAIL, 'password' => 'wrong'])
            ->andReturnFalse();

        $this->resolver->shouldNotReceive('resolve');

        $dispatched = [];

        $this->events->shouldReceive('dispatch')
            ->andReturnUsing(static function (object $event) use (&$dispatched): void {
                $dispatched[] = $event::class;
            });

        self::assertNull($guard->user());
        self::assertContains(Failed::class, $dispatched);
        self::assertNotContains(Validated::class, $dispatched);
    }

    /**
     * When the resolver returns null, `user()` returns null and fires
     * `Attempting`, `Validated`, and `Failed` (no `Login`).
     *
     * @return void
     */
    public function testUserReturnsNullWhenResolverProducesNoPrincipal(): void
    {
        $guard = $this->makeGuard($this->makeRequest(self::ALICE_EMAIL, 'secret'));

        $identity = \Mockery::mock(Identity::class);

        $this->provider->shouldReceive('retrieveByCredentials')
            ->once()
            ->andReturn($identity);
        $this->provider->shouldReceive('validateCredentials')
            ->once()
            ->andReturnTrue();

        $this->resolver->shouldReceive('resolve')
            ->once()
            ->with($identity)
            ->andReturnNull();

        $dispatched = [];

        $this->events->shouldReceive('dispatch')
            ->andReturnUsing(static function (object $event) use (&$dispatched): void {
                $dispatched[] = $event::class;
            });

        self::assertNull($guard->user());
        self::assertContains(Validated::class, $dispatched);
        self::assertContains(Failed::class, $dispatched);
        self::assertNotContains(Login::class, $dispatched);
    }

    /**
     * H1 regression test.
     *
     * When the principal resolver throws
     * `UnresolvableIdentityException` (the typed signal a
     * misconfigured identity model implements neither `Principal`
     * nor `HasPrincipals`) `BasicGuard::user()` MUST convert it to
     * a `Failed` event and return null - NOT let it propagate as
     * an uncaught 500. The conversion mirrors `JwtGuard::user()`
     * and `AbstractGuard::attempt()`.
     *
     * @return void
     */
    public function testUserConvertsUnresolvableIdentityExceptionToFailedEvent(): void
    {
        $guard = $this->makeGuard($this->makeRequest(self::ALICE_EMAIL, 'secret'));

        $identity = \Mockery::mock(Identity::class);

        $this->provider->shouldReceive('retrieveByCredentials')
            ->once()
            ->andReturn($identity);
        $this->provider->shouldReceive('validateCredentials')
            ->once()
            ->andReturnTrue();

        $this->resolver->shouldReceive('resolve')
            ->once()
            ->with($identity)
            ->andThrow(new \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException(
                'identity implements neither Principal nor HasPrincipals',
            ));

        $dispatched = [];

        $this->events->shouldReceive('dispatch')
            ->andReturnUsing(static function (object $event) use (&$dispatched): void {
                $dispatched[] = $event::class;
            });

        self::assertNull($guard->user());
        self::assertContains(Validated::class, $dispatched);
        self::assertContains(Failed::class, $dispatched);
        self::assertNotContains(Login::class, $dispatched);
    }

    /**
     * When the resolved principal's `isActive()` is false, `user()`
     * returns null and fires `Failed`.
     *
     * @return void
     */
    public function testUserReturnsNullWhenPrincipalIsInactive(): void
    {
        $guard = $this->makeGuard($this->makeRequest(self::ALICE_EMAIL, 'secret'));

        $identity = \Mockery::mock(Identity::class);

        $principal = \Mockery::mock(Principal::class);
        $principal->shouldReceive('isActive')
            ->once()
            ->andReturnFalse();

        $this->provider->shouldReceive('retrieveByCredentials')
            ->once()
            ->andReturn($identity);
        $this->provider->shouldReceive('validateCredentials')
            ->once()
            ->andReturnTrue();

        $this->resolver->shouldReceive('resolve')
            ->once()
            ->with($identity)
            ->andReturn($principal);

        $dispatched = [];

        $this->events->shouldReceive('dispatch')
            ->andReturnUsing(static function (object $event) use (&$dispatched): void {
                $dispatched[] = $event::class;
            });

        self::assertNull($guard->user());
        self::assertContains(Failed::class, $dispatched);
    }

    /**
     * A valid request binds the identity and principal and dispatches
     * the full success-path event sequence: `Attempting`, `Validated`,
     * `Authenticated`, `PrincipalAssigned`, and `Login`.
     *
     * @return void
     */
    public function testUserBindsIdentityAndPrincipalFromValidCredentials(): void
    {
        $guard = $this->makeGuard($this->makeRequest(self::ALICE_EMAIL, 'secret'));

        $identity = \Mockery::mock(Identity::class);

        $principal = \Mockery::mock(Principal::class);
        $principal->shouldReceive('isActive')
            ->once()
            ->andReturnTrue();

        $this->provider->shouldReceive('retrieveByCredentials')
            ->once()
            ->with(['email' => self::ALICE_EMAIL, 'password' => 'secret'])
            ->andReturn($identity);
        $this->provider->shouldReceive('validateCredentials')
            ->once()
            ->andReturnTrue();

        $this->resolver->shouldReceive('resolve')
            ->once()
            ->with($identity)
            ->andReturn($principal);

        $dispatched = [];

        $this->events->shouldReceive('dispatch')
            ->andReturnUsing(static function (object $event) use (&$dispatched): void {
                $dispatched[] = $event::class;
            });

        self::assertSame($identity, $guard->user());
        self::assertSame($principal, $guard->principal());
        self::assertContains(Attempting::class, $dispatched);
        self::assertContains(Validated::class, $dispatched);
        self::assertContains(Authenticated::class, $dispatched);
        self::assertContains(PrincipalAssigned::class, $dispatched);
        self::assertContains(Login::class, $dispatched);
    }

    /**
     * Credential validation runs inside `Timebox::call()` with the
     * default 400,000 microsecond budget.
     *
     * @return void
     */
    public function testUserRunsCredentialValidationThroughTimebox(): void
    {
        // Replace the default Timebox mock with one that asserts the
        // 400_000 microsecond budget and still invokes the callback.
        $this->timebox = \Mockery::mock(Timebox::class);
        $this->timebox->shouldReceive('call')
            ->once()
            ->with(\Mockery::type('callable'), 400000)
            ->andReturnUsing(static fn (callable $callback): mixed => $callback(new Timebox));

        $guard = $this->makeGuard($this->makeRequest(self::ALICE_EMAIL, 'secret'));

        $identity = \Mockery::mock(Identity::class);

        $principal = \Mockery::mock(Principal::class);
        $principal->shouldReceive('isActive')
            ->once()
            ->andReturnTrue();

        $this->provider->shouldReceive('retrieveByCredentials')
            ->once()
            ->andReturn($identity);
        $this->provider->shouldReceive('validateCredentials')
            ->once()
            ->andReturnTrue();

        $this->resolver->shouldReceive('resolve')
            ->once()
            ->andReturn($principal);

        $this->events->shouldReceive('dispatch')->andReturnNull();

        self::assertSame($identity, $guard->user());
    }

    /**
     * After a successful `user()` call, `check()` returns true.
     *
     * @return void
     */
    public function testCheckReflectsBoundState(): void
    {
        $guard = $this->makeGuard($this->makeRequest(self::ALICE_EMAIL, 'secret'));

        $identity = \Mockery::mock(Identity::class);

        $principal = \Mockery::mock(Principal::class);
        $principal->shouldReceive('isActive')
            ->once()
            ->andReturnTrue();

        $this->provider->shouldReceive('retrieveByCredentials')
            ->once()
            ->andReturn($identity);
        $this->provider->shouldReceive('validateCredentials')
            ->once()
            ->andReturnTrue();

        $this->resolver->shouldReceive('resolve')
            ->once()
            ->andReturn($principal);

        $this->events->shouldReceive('dispatch')->andReturnNull();

        self::assertTrue($guard->check());
    }

    /**
     * After a successful `user()` then `logout()`, `check()` returns false.
     *
     * @return void
     */
    public function testLogoutClearsBoundState(): void
    {
        $guard = $this->makeGuard($this->makeRequest(self::ALICE_EMAIL, 'secret'));

        $identity = \Mockery::mock(Identity::class);

        $principal = \Mockery::mock(Principal::class);
        $principal->shouldReceive('isActive')
            ->once()
            ->andReturnTrue();

        $this->provider->shouldReceive('retrieveByCredentials')
            ->once()
            ->andReturn($identity);
        $this->provider->shouldReceive('validateCredentials')
            ->once()
            ->andReturnTrue();

        $this->resolver->shouldReceive('resolve')
            ->once()
            ->andReturn($principal);

        $this->events->shouldReceive('dispatch')->andReturnNull();

        self::assertSame($identity, $guard->user());

        $guard->logout();

        // After logout the stateless guard will re-read the request on
        // the next `user()` call - swap in a credential-less request so
        // the re-read cannot resurrect the bound identity.
        $guard->setRequest($this->makeRequest(null, null));

        self::assertFalse($guard->check());
        self::assertNull($guard->principal());
    }

    /**
     * The inherited `attempt()` flow dispatches `Attempting`,
     * `Validated`, `Authenticated`, `PrincipalAssigned`, and `Login`
     * for valid credentials.
     *
     * @return void
     */
    public function testInheritedAttemptDispatchesAttemptingAndLoginEvents(): void
    {
        $guard = $this->makeGuard($this->makeRequest(null, null));

        $identity = \Mockery::mock(Identity::class);

        $principal = \Mockery::mock(Principal::class);
        $principal->shouldReceive('isActive')
            ->once()
            ->andReturnTrue();

        $this->provider->shouldReceive('retrieveByCredentials')
            ->once()
            ->with(['email' => self::ALICE_EMAIL, 'password' => 'secret'])
            ->andReturn($identity);
        $this->provider->shouldReceive('validateCredentials')
            ->once()
            ->andReturnTrue();

        $this->resolver->shouldReceive('resolve')
            ->once()
            ->with($identity)
            ->andReturn($principal);

        $dispatched = [];

        $this->events->shouldReceive('dispatch')
            ->andReturnUsing(static function (object $event) use (&$dispatched): void {
                $dispatched[] = $event::class;
            });

        self::assertTrue($guard->attempt([
            'email'    => self::ALICE_EMAIL,
            'password' => 'secret',
        ]));

        self::assertSame(
            [Attempting::class, Validated::class, Login::class, Authenticated::class, PrincipalAssigned::class],
            $dispatched,
        );
    }

    /**
     * When the guard is constructed with a non-default identifier
     * field, the credentials array passed to the identity provider
     * uses that field as the key.
     *
     * @return void
     */
    public function testUserUsesConfiguredIdentifierField(): void
    {
        $guard = new BasicGuard(
            self::GUARD_NAME,
            $this->provider,
            $this->resolver,
            $this->events,
            $this->makeRequest('alice', 'secret'),
            $this->timebox,
            'username',
        );

        $identity = \Mockery::mock(Identity::class);

        $principal = \Mockery::mock(Principal::class);
        $principal->shouldReceive('isActive')->andReturnTrue();

        $this->provider->shouldReceive('retrieveByCredentials')
            ->once()
            ->with(['username' => 'alice', 'password' => 'secret'])
            ->andReturn($identity);
        $this->provider->shouldReceive('validateCredentials')
            ->once()
            ->andReturnTrue();

        $this->resolver->shouldReceive('resolve')
            ->once()
            ->andReturn($principal);

        $this->events->shouldReceive('dispatch')->andReturnNull();

        self::assertSame($identity, $guard->user());
    }

    /**
     * Instantiate BasicGuard with the current set of collaborator mocks
     * and the supplied request. Uses the default `email` identifier
     * field.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \SineMacula\Laravel\Authentication\Guards\BasicGuard
     */
    private function makeGuard(Request $request): BasicGuard
    {
        return new BasicGuard(
            self::GUARD_NAME,
            $this->provider,
            $this->resolver,
            $this->events,
            $request,
            $this->timebox,
        );
    }

    /**
     * Build a real Illuminate Request with optional HTTP Basic
     * credentials populated via the standard PHP_AUTH_USER /
     * PHP_AUTH_PW server variables.
     *
     * @param  string|null  $user
     * @param  string|null  $password
     * @return \Illuminate\Http\Request
     */
    private function makeRequest(?string $user, ?string $password): Request
    {
        $server = [];

        if ($user !== null) {
            $server['PHP_AUTH_USER'] = $user;
        }

        if ($password !== null) {
            $server['PHP_AUTH_PW'] = $password;
        }

        return Request::create('/test', 'GET', [], [], [], $server);
    }
}
