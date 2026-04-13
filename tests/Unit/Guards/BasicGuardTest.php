<?php

declare(strict_types = 1);

namespace Tests\Unit\Guards;

use Illuminate\Auth\Events\Attempting;
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
use SineMacula\Laravel\Authentication\Contracts\CanBeActive;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\IdentityProvider;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\PrincipalResolver;
use SineMacula\Laravel\Authentication\Guards\BasicGuard;
use SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException;

/**
 * Unit tests for the BasicGuard credential extraction and validation paths.
 *
 * Exercises HTTP Basic credential extraction, timing-safe credential validation
 * via the inherited Timebox path, identity/principal resolution failures, and
 * the inactive-identity/principal guard. Success-path login, state lifecycle,
 * and event dispatch tests live in BasicGuardLoginTest.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
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

        // Default: Timebox::call() invokes the callback directly so credential
        // validation paths run deterministically.
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
     * A request with an empty-string username and a non-empty password returns
     * null. Mutation guard: pins each arm of the `||` guard in
     * `credentialsFromRequest()` independently - the empty-username branch
     * must short-circuit even when the password is present.
     *
     * @return void
     */
    public function testUserReturnsNullWhenUsernameIsEmptyString(): void
    {
        $guard = $this->makeGuard($this->makeRequest('', 'secret'));

        $this->provider->shouldNotReceive('retrieveByCredentials');
        $this->events->shouldNotReceive('dispatch');

        self::assertNull($guard->user());
    }

    /**
     * A request with a non-empty username and an empty-string password returns
     * null. Mutation guard: pins the `$password === ''` arm of the `||`
     * guard in `credentialsFromRequest()`.
     *
     * @return void
     */
    public function testUserReturnsNullWhenPasswordIsEmptyString(): void
    {
        $guard = $this->makeGuard($this->makeRequest(self::ALICE_EMAIL, ''));

        $this->provider->shouldNotReceive('retrieveByCredentials');
        $this->events->shouldNotReceive('dispatch');

        self::assertNull($guard->user());
    }

    /**
     * When `retrieveByCredentials()` returns null, `user()` fires `Attempting`
     * and `Failed` and returns null.
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
     * When `validateCredentials()` returns false, `user()` fires `Attempting`
     * and `Failed` and returns null. The `Validated` event is NOT emitted
     * because the hasher check failed.
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
     * When the principal resolver throws `UnresolvableIdentityException` (the
     * typed signal a misconfigured identity model implements neither
     * `Principal` nor `HasPrincipals`) `BasicGuard::user()` MUST convert it to
     * a `Failed` event and return null - NOT let it propagate as an uncaught
     * 500. The conversion mirrors `JwtGuard::user()` and
     * `AbstractGuard::attempt()`.
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
            ->andThrow(
                new UnresolvableIdentityException(
                    'identity implements neither Principal nor HasPrincipals',
                ),
            );

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
     * When the resolved principal's `isActive()` is false, `user()` returns
     * null and fires `Failed`.
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
     * When the resolved identity opts into activation checking and reports
     * inactive, the guard fails closed before principal resolution.
     *
     * @return void
     */
    public function testUserReturnsNullWhenIdentityIsInactive(): void
    {
        $guard = $this->makeGuard($this->makeRequest(self::ALICE_EMAIL, 'secret'));

        $identity = \Mockery::mock(Identity::class, CanBeActive::class);
        $identity->shouldReceive('isActive')
            ->once()
            ->andReturnFalse();

        $this->provider->shouldReceive('retrieveByCredentials')
            ->once()
            ->andReturn($identity);
        $this->provider->shouldReceive('validateCredentials')
            ->once()
            ->with($identity, ['email' => self::ALICE_EMAIL, 'password' => 'secret'])
            ->andReturnTrue();

        $this->resolver->shouldNotReceive('resolve');

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
     * Instantiate BasicGuard with the current set of collaborator mocks and
     * the supplied request. Uses the default `email` identifier field.
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
     * Build a real Illuminate Request with optional HTTP Basic credentials
     * populated via the standard PHP_AUTH_USER / PHP_AUTH_PW server variables.
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
