<?php

declare(strict_types=1);

namespace Tests\Unit\Guards;

use Illuminate\Auth\Events\Attempting;
use Illuminate\Auth\Events\Authenticated;
use Illuminate\Auth\Events\Login;
use Illuminate\Auth\Events\Validated;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Http\Request;
use Illuminate\Support\Timebox;
use Mockery;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use Mockery\MockInterface;
use PHPUnit\Framework\Attributes\CoversNothing;
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
 * TestCase because the BasicGuard does not call into `config(...)`.
 * The Request collaborator is a real Symfony/Illuminate `Request`
 * instance built via `Request::create(...)` (per php-tst-034 fakes
 * preference for Symfony value objects).
 *
 * @author    Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright 2026 Sine Macula Limited.
 *
 * @internal
 */
#[CoversNothing]
final class BasicGuardTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    /** @var string The guard name forwarded to BasicGuard's constructor. */
    private const string GUARD_NAME = 'basic-test';

    /** @var \Mockery\MockInterface&\SineMacula\Laravel\Authentication\Contracts\IdentityProvider The mocked identity provider collaborator. */
    private MockInterface $provider;

    /** @var \Mockery\MockInterface&\SineMacula\Laravel\Authentication\Contracts\PrincipalResolver The mocked principal resolver collaborator. */
    private MockInterface $resolver;

    /** @var \Mockery\MockInterface&\Illuminate\Contracts\Events\Dispatcher The mocked event dispatcher collaborator. */
    private MockInterface $events;

    /** @var \Mockery\MockInterface&\Illuminate\Support\Timebox The mocked timebox collaborator. */
    private MockInterface $timebox;

    /**
     * Build fresh collaborator mocks before each test.
     *
     * @return void
     */
    protected function setUp(): void
    {
        parent::setUp();

        $this->provider = Mockery::mock(IdentityProvider::class);
        $this->resolver = Mockery::mock(PrincipalResolver::class);
        $this->events   = Mockery::mock(Dispatcher::class);
        $this->timebox  = Mockery::mock(Timebox::class);

        // Default: Timebox::call() invokes the callback directly so
        // credential validation paths run deterministically.
        $this->timebox->shouldReceive('call')
            ->byDefault()
            ->andReturnUsing(static fn (callable $callback): mixed => $callback(new Timebox()));
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
        $guard = $this->makeGuard($this->makeRequest('alice@example.com', null));

        $this->provider->shouldNotReceive('retrieveByCredentials');
        $this->events->shouldNotReceive('dispatch');

        self::assertNull($guard->user());
    }

    /**
     * When `retrieveByCredentials()` returns null, `user()` runs through
     * the timing-safe path and returns null.
     *
     * @return void
     */
    public function testUserReturnsNullWhenIdentifierDoesNotResolve(): void
    {
        $guard = $this->makeGuard($this->makeRequest('ghost@example.com', 'secret'));

        $this->provider->shouldReceive('retrieveByCredentials')
            ->once()
            ->with(['email' => 'ghost@example.com', 'password' => 'secret'])
            ->andReturnNull();

        $this->provider->shouldNotReceive('validateCredentials');
        $this->resolver->shouldNotReceive('resolve');
        $this->events->shouldNotReceive('dispatch');

        self::assertNull($guard->user());
    }

    /**
     * When `validateCredentials()` returns false, `user()` returns null
     * and `Failed` is NOT emitted (`user()` is a passive read, not an
     * attempt).
     *
     * @return void
     */
    public function testUserReturnsNullWhenCredentialsValidationFails(): void
    {
        $guard = $this->makeGuard($this->makeRequest('alice@example.com', 'wrong'));

        $identity = Mockery::mock(Identity::class);

        $this->provider->shouldReceive('retrieveByCredentials')
            ->once()
            ->andReturn($identity);
        $this->provider->shouldReceive('validateCredentials')
            ->once()
            ->with($identity, ['email' => 'alice@example.com', 'password' => 'wrong'])
            ->andReturnFalse();

        $this->resolver->shouldNotReceive('resolve');
        $this->events->shouldNotReceive('dispatch');

        self::assertNull($guard->user());
    }

    /**
     * When the resolver returns null, `user()` returns null.
     *
     * @return void
     */
    public function testUserReturnsNullWhenResolverProducesNoPrincipal(): void
    {
        $guard = $this->makeGuard($this->makeRequest('alice@example.com', 'secret'));

        $identity = Mockery::mock(Identity::class);

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

        // Validated is fired by hasValidCredentials; nothing else after.
        $this->events->shouldReceive('dispatch')
            ->once()
            ->with(Mockery::type(Validated::class));

        self::assertNull($guard->user());
    }

    /**
     * When the resolved principal's `isActive()` is false, `user()`
     * returns null.
     *
     * @return void
     */
    public function testUserReturnsNullWhenPrincipalIsInactive(): void
    {
        $guard = $this->makeGuard($this->makeRequest('alice@example.com', 'secret'));

        $identity = Mockery::mock(Identity::class);

        $principal = Mockery::mock(Principal::class);
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

        // Only Validated fires (from hasValidCredentials); no Authenticated.
        $this->events->shouldReceive('dispatch')
            ->once()
            ->with(Mockery::type(Validated::class));

        self::assertNull($guard->user());
    }

    /**
     * A valid request binds the identity and principal and dispatches
     * `Authenticated` and `PrincipalAssigned`.
     *
     * @return void
     */
    public function testUserBindsIdentityAndPrincipalFromValidCredentials(): void
    {
        $guard = $this->makeGuard($this->makeRequest('alice@example.com', 'secret'));

        $identity = Mockery::mock(Identity::class);

        $principal = Mockery::mock(Principal::class);
        $principal->shouldReceive('isActive')
            ->once()
            ->andReturnTrue();

        $this->provider->shouldReceive('retrieveByCredentials')
            ->once()
            ->with(['email' => 'alice@example.com', 'password' => 'secret'])
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
        self::assertContains(Validated::class, $dispatched);
        self::assertContains(Authenticated::class, $dispatched);
        self::assertContains(PrincipalAssigned::class, $dispatched);
    }

    /**
     * Credential validation runs inside `Timebox::call()` with a
     * 200,000 microsecond budget (NFR-04).
     *
     * @return void
     */
    public function testUserRunsCredentialValidationThroughTimebox(): void
    {
        // Replace the default Timebox mock with one that asserts the
        // 200_000 microsecond budget and still invokes the callback.
        $this->timebox = Mockery::mock(Timebox::class);
        $this->timebox->shouldReceive('call')
            ->once()
            ->with(Mockery::type('callable'), 200_000)
            ->andReturnUsing(static fn (callable $callback): mixed => $callback(new Timebox()));

        $guard = $this->makeGuard($this->makeRequest('alice@example.com', 'secret'));

        $identity = Mockery::mock(Identity::class);

        $principal = Mockery::mock(Principal::class);
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
        $guard = $this->makeGuard($this->makeRequest('alice@example.com', 'secret'));

        $identity = Mockery::mock(Identity::class);

        $principal = Mockery::mock(Principal::class);
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
        $guard = $this->makeGuard($this->makeRequest('alice@example.com', 'secret'));

        $identity = Mockery::mock(Identity::class);

        $principal = Mockery::mock(Principal::class);
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
        // the next `user()` call — swap in a credential-less request so
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

        $identity = Mockery::mock(Identity::class);

        $principal = Mockery::mock(Principal::class);

        $this->provider->shouldReceive('retrieveByCredentials')
            ->once()
            ->with(['email' => 'alice@example.com', 'password' => 'secret'])
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
            'email'    => 'alice@example.com',
            'password' => 'secret',
        ]));

        self::assertSame(
            [Attempting::class, Validated::class, Authenticated::class, PrincipalAssigned::class, Login::class],
            $dispatched,
        );
    }

    /**
     * Instantiate BasicGuard with the current set of collaborator mocks
     * and the supplied request.
     *
     * @param  \Illuminate\Http\Request $request The request to bind to the guard.
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
     * @param  string|null $user     The HTTP Basic username, or null for no credentials.
     * @param  string|null $password The HTTP Basic password, or null.
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
