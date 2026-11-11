<?php

declare(strict_types = 1);

namespace Tests\Feature\Guards;

use Illuminate\Auth\Events\Authenticated;
use Illuminate\Contracts\Events\Dispatcher;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Contracts\PrincipalResolver;
use SineMacula\Laravel\Authentication\Events\PrincipalAssigned;
use SineMacula\Laravel\Authentication\Guards\AbstractGuard;

/**
 * Feature tests for the rebind hooks, `id()` type narrowing and the
 * `validate()` failure path on `AbstractGuard`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AbstractGuard::class)]
final class AbstractGuardWiringTest extends AbstractGuardTestCase
{
    /**
     * `setDispatcher()` swaps the bound dispatcher and returns the guard, so
     * later events reach the new one.
     *
     * @return void
     */
    public function testSetDispatcherReplacesBoundDispatcherAndReturnsGuard(): void
    {
        $guard = $this->makeGuard();

        $replacement = \Mockery::mock(Dispatcher::class);

        $identity  = $this->mockIdentity();
        $principal = $this->mockPrincipal();

        $this->resolver->shouldReceive('resolve')
            ->once()
            ->with($identity)
            ->andReturn($principal);

        $replacement->shouldReceive('dispatch')
            ->once()
            ->with(\Mockery::type(Authenticated::class));
        $replacement->shouldReceive('dispatch')
            ->once()
            ->with(\Mockery::type(PrincipalAssigned::class));

        $this->events->shouldNotReceive('dispatch');

        self::assertSame($guard, $guard->setDispatcher($replacement));

        $guard->setUser($identity);
    }

    /**
     * `setPrincipalResolver()` swaps the bound resolver and returns the guard,
     * so the next `attempt()` uses it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testSetPrincipalResolverReplacesBoundResolverAndReturnsGuard(): void
    {
        $guard = $this->makeGuard();

        $identity  = $this->mockIdentity();
        $principal = $this->mockActivePrincipal();

        $replacement = \Mockery::mock(PrincipalResolver::class);
        $replacement->shouldReceive('resolve')
            ->once()
            ->with($identity)
            ->andReturn($principal);

        $this->resolver->shouldNotReceive('resolve');

        $this->provider->shouldReceive('retrieveByCredentials')
            ->once()
            ->andReturn($identity);
        $this->provider->shouldReceive('validateCredentials')
            ->once()
            ->andReturnTrue();

        $this->events->shouldReceive('dispatch')->andReturnNull();

        self::assertSame($guard, $guard->setPrincipalResolver($replacement));

        self::assertTrue($guard->attempt(['email' => 'x', 'password' => 'y']));
    }

    /**
     * `id()` returns `null` for an identifier that is neither an int nor a
     * string.
     *
     * @return void
     */
    public function testIdReturnsNullForNonScalarIdentifier(): void
    {
        $guard = $this->makeGuard();

        $identity = $this->mockIdentity();
        $identity->shouldReceive('getAuthIdentifier')
            ->andReturn(['unexpected', 'array']);

        $this->events->shouldReceive('dispatch')->andReturnNull();

        $guard->login($identity, $this->mockPrincipal());

        self::assertNull($guard->id());
    }

    /**
     * `id()` returns a string identifier verbatim.
     *
     * @return void
     */
    public function testIdReturnsStringIdentifierVerbatim(): void
    {
        $guard = $this->makeGuard();

        $identity = $this->mockIdentity();
        $identity->shouldReceive('getAuthIdentifier')
            ->andReturn('user-42');

        $this->events->shouldReceive('dispatch')->andReturnNull();

        $guard->login($identity, $this->mockPrincipal());

        self::assertSame('user-42', $guard->id());
    }

    /**
     * `id()` returns an integer identifier of `0` as is.
     *
     * @return void
     */
    public function testIdReturnsZeroIntegerLiteral(): void
    {
        $guard = $this->makeGuard();

        $identity = $this->mockIdentity();
        $identity->shouldReceive('getAuthIdentifier')
            ->andReturn(0);

        $this->events->shouldReceive('dispatch')->andReturnNull();

        $guard->login($identity, $this->mockPrincipal());

        self::assertSame(0, $guard->id());
    }

    /**
     * `id()` returns a string identifier of `'0'` as is.
     *
     * @return void
     */
    public function testIdReturnsZeroStringLiteral(): void
    {
        $guard = $this->makeGuard();

        $identity = $this->mockIdentity();
        $identity->shouldReceive('getAuthIdentifier')
            ->andReturn('0');

        $this->events->shouldReceive('dispatch')->andReturnNull();

        $guard->login($identity, $this->mockPrincipal());

        self::assertSame('0', $guard->id());
    }

    /**
     * `id()` returns `null` for a float identifier rather than truncating it.
     *
     * @return void
     */
    public function testIdReturnsNullForFloatIdentifier(): void
    {
        $guard = $this->makeGuard();

        $identity = $this->mockIdentity();
        $identity->shouldReceive('getAuthIdentifier')
            ->andReturn(1.5);

        $this->events->shouldReceive('dispatch')->andReturnNull();

        $guard->login($identity, $this->mockPrincipal());

        self::assertNull($guard->id());
    }

    /**
     * `id()` returns `null` for a boolean identifier.
     *
     * @return void
     */
    public function testIdReturnsNullForBoolIdentifier(): void
    {
        $guard = $this->makeGuard();

        $identity = $this->mockIdentity();
        $identity->shouldReceive('getAuthIdentifier')
            ->andReturn(true);

        $this->events->shouldReceive('dispatch')->andReturnNull();

        $guard->login($identity, $this->mockPrincipal());

        self::assertNull($guard->id());
    }

    /**
     * `id()` returns `null` for an object identifier.
     *
     * @return void
     */
    public function testIdReturnsNullForObjectIdentifier(): void
    {
        $guard = $this->makeGuard();

        $identity = $this->mockIdentity();
        $identity->shouldReceive('getAuthIdentifier')
            ->andReturn(new \stdClass);

        $this->events->shouldReceive('dispatch')->andReturnNull();

        $guard->login($identity, $this->mockPrincipal());

        self::assertNull($guard->id());
    }

    /**
     * `validate()` returns `false` without `Timebox::returnEarly()` when the
     * provider returns a non-Identity user.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testValidateReturnsFalseWhenCredentialsRejected(): void
    {
        $guard = $this->makeGuard();

        $this->provider->shouldReceive('retrieveByCredentials')
            ->once()
            ->andReturnNull();
        $this->provider->shouldNotReceive('validateCredentials');

        $this->events->shouldNotReceive('dispatch');

        self::assertFalse($guard->validate(['email' => 'ghost@example.test']));
    }

    /**
     * `validate()` returns `false` for the default empty credentials.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testValidateAcceptsDefaultEmptyCredentialsArgument(): void
    {
        $guard = $this->makeGuard();

        $this->provider->shouldReceive('retrieveByCredentials')
            ->once()
            ->with([])
            ->andReturnNull();

        $this->events->shouldNotReceive('dispatch');

        self::assertFalse($guard->validate());
    }
}
