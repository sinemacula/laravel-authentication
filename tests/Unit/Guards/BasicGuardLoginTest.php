<?php

declare(strict_types = 1);

namespace Tests\Unit\Guards;

use Illuminate\Auth\Events\Attempting;
use Illuminate\Auth\Events\Authenticated;
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
 * Unit tests for the BasicGuard success path, state lifecycle, event dispatch,
 * and constructor configuration.
 *
 * Covers the happy-path login flow, logout/state clearing, timebox integration,
 * identifier-field configuration, and event assertions. Credential extraction
 * and validation failure tests live in BasicGuardTest.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(BasicGuard::class)]
final class BasicGuardLoginTest extends TestCase
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
    #[\Override]
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
     * A valid request binds the identity and principal and dispatches the full
     * success-path event sequence: `Attempting`, `Validated`, `Authenticated`,
     * `PrincipalAssigned`, and `Login`.
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
     * Credential validation runs inside `Timebox::call()` with the default
     * 400,000 microsecond budget.
     *
     * @return void
     */
    public function testUserRunsCredentialValidationThroughTimebox(): void
    {
        // Replace the default Timebox mock with one that asserts the 400_000
        // microsecond budget and still invokes the callback.
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
     * `user()` short-circuits and returns the already-bound identity (set via
     * the parent `setUser()`) without invoking the identity provider, the
     * resolver, or the dispatcher. Pins the `$this->identity !== null` guard in
     * `user()`.
     *
     * @return void
     */
    public function testUserReturnsBoundIdentityWithoutReprocessingCredentials(): void
    {
        $guard = $this->makeGuard($this->makeRequest(self::ALICE_EMAIL, 'secret'));

        $identity = \Mockery::mock(Identity::class);

        $this->events->shouldReceive('dispatch')
            ->once()
            ->with(\Mockery::type(Authenticated::class));

        // Pre-bind the identity via setUser. Subsequent user() calls must NOT
        // touch the provider/resolver - if they did, Mockery would fail because
        // no expectations are configured.
        $this->provider->shouldNotReceive('retrieveByCredentials');
        $this->provider->shouldNotReceive('validateCredentials');
        $this->resolver->shouldNotReceive('resolve');

        $guard->setUser($identity);

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

        // After logout the stateless guard will re-read the request on the next
        // `user()` call - swap in a credential-less request so the re-read
        // cannot resurrect the bound identity.
        $guard->setRequest($this->makeRequest(null, null));

        self::assertFalse($guard->check());
        self::assertNull($guard->principal());
    }

    /**
     * The inherited `attempt()` flow dispatches `Attempting`, `Validated`,
     * `Authenticated`, `PrincipalAssigned`, and `Login` for valid credentials.
     *
     * @return void
     *
     * @throws \Throwable
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
     * When the guard is constructed with a non-default identifier field, the
     * credentials array passed to the identity provider uses that field as the
     * key.
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
     * Constructing a BasicGuard with an empty-string identifier field falls
     * back to `'email'` so a misconfigured guard does not compose queries
     * against a blank column name. Mutation guard: pins the `=== '' ? 'email'`
     * ternary in `__construct()`.
     *
     * @return void
     */
    public function testConstructorFallsBackToEmailWhenIdentifierFieldIsEmpty(): void
    {
        $guard = new BasicGuard(
            self::GUARD_NAME,
            $this->provider,
            $this->resolver,
            $this->events,
            $this->makeRequest(self::ALICE_EMAIL, 'secret'),
            $this->timebox,
            '',
        );

        $identity = \Mockery::mock(Identity::class);

        $principal = \Mockery::mock(Principal::class);
        $principal->shouldReceive('isActive')->andReturnTrue();

        // The credentials must use `email` (the fallback), not an empty key.
        $this->provider->shouldReceive('retrieveByCredentials')
            ->once()
            ->with(['email' => self::ALICE_EMAIL, 'password' => 'secret'])
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
     * `resolveCredentials()` calls `Timebox::returnEarly()` when the
     * credentials validate and a principal resolves, so the timing budget is
     * consumed on the success path. Mutation guard: pins the
     * `$timebox->returnEarly()` call in `resolveCredentials()`.
     *
     * @return void
     */
    public function testUserCallsReturnEarlyOnSuccessfulResolution(): void
    {
        $returnEarlyCalled = false;

        $timeboxSpy = new class extends Timebox {
            /** @var bool Tracks whether returnEarly() was called. */
            public bool $returnEarlyCalled = false;

            /**
             * @return static
             */
            #[\Override]
            public function returnEarly(): static
            {
                $this->returnEarlyCalled = true;

                return parent::returnEarly();
            }
        };

        $this->timebox = \Mockery::mock(Timebox::class);
        $this->timebox->shouldReceive('call')
            ->once()
            ->andReturnUsing(static function (callable $callback) use ($timeboxSpy, &$returnEarlyCalled): mixed {
                $result            = $callback($timeboxSpy);
                $returnEarlyCalled = $timeboxSpy->returnEarlyCalled;

                return $result;
            });

        $guard = $this->makeGuard($this->makeRequest(self::ALICE_EMAIL, 'secret'));

        $identity = \Mockery::mock(Identity::class);

        $principal = \Mockery::mock(Principal::class);
        $principal->shouldReceive('isActive')->andReturnTrue();

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
        self::assertTrue($returnEarlyCalled);
    }

    /**
     * The `Attempting` event fires with `remember = false` so stateless guards
     * never advertise remember-me capability. Mutation guard: pins the literal
     * `false` in `fireAttemptingEvent()`.
     *
     * @return void
     */
    public function testAttemptingEventCarriesFalseRememberParameter(): void
    {
        $guard = $this->makeGuard($this->makeRequest(self::ALICE_EMAIL, 'secret'));

        $this->provider->shouldReceive('retrieveByCredentials')
            ->once()
            ->andReturnNull();

        $attemptingEvent = null;

        $this->events->shouldReceive('dispatch')
            ->andReturnUsing(static function (object $event) use (&$attemptingEvent): void {
                if (!$event instanceof Attempting) {
                    return;
                }

                $attemptingEvent = $event;
            });

        $guard->user();

        static::assertInstanceOf(Attempting::class, $attemptingEvent);
        static::assertFalse($attemptingEvent->remember);
    }

    /**
     * Instantiate BasicGuard with the current set of collaborator mocks and the
     * supplied request. Uses the default `email` identifier field.
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
