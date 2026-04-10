<?php

declare(strict_types = 1);

namespace Tests\Feature\Guards;

use Illuminate\Auth\Events\Authenticated;
use Illuminate\Contracts\Events\Dispatcher;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Contracts\PrincipalResolver;
use SineMacula\Laravel\Authentication\Guards\AbstractGuard;

/**
 * Unit tests for the runtime rebind hooks (`setDispatcher`,
 * `setPrincipalResolver`), the `id()` type-narrowing matrix, and the
 * `validate()` failure path on `AbstractGuard`.
 *
 * Split out of `AbstractGuardLifecycleTest` so each class stays focused on a
 * single behavioural slice.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 *
 * @internal
 */
#[CoversClass(AbstractGuard::class)]
final class AbstractGuardWiringTest extends AbstractGuardTestCase
{
    /**
     * `setDispatcher()` swaps the bound dispatcher and returns the guard for
     * chaining. The next event firing routes through the fresh dispatcher
     * rather than the constructor-time instance, which is what `Event::fake()`
     * and similar test fakes rely on.
     *
     * @return void
     */
    public function testSetDispatcherReplacesBoundDispatcherAndReturnsGuard(): void
    {
        $guard = $this->makeGuard();

        $replacement = \Mockery::mock(Dispatcher::class);

        $identity = $this->mockIdentity();

        $replacement->shouldReceive('dispatch')
            ->once()
            ->with(\Mockery::type(Authenticated::class));

        // The original dispatcher must NOT receive the event.
        $this->events->shouldNotReceive('dispatch');

        self::assertSame($guard, $guard->setDispatcher($replacement));

        $guard->setUser($identity);
    }

    /**
     * `setPrincipalResolver()` swaps the bound resolver and returns the guard
     * for chaining. The next `attempt()` routes through the replacement
     * resolver, proving the rebind reaches the live credential path.
     *
     * @return void
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

        // The original resolver must NOT be called.
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
     * `id()` returns `null` when the bound identity's auth identifier is
     * neither an int nor a string (e.g. a misbehaving model that returns an
     * array). Pins the type-narrowing default branch.
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

        $guard->setUser($identity);

        self::assertNull($guard->id());
    }

    /**
     * `id()` returns the literal string `'42'` when the identifier is a string,
     * proving the type guard accepts strings (not just ints).
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

        $guard->setUser($identity);

        self::assertSame('user-42', $guard->id());
    }

    /**
     * `id()` returns the literal integer `0` when the identifier is zero. Pins
     * the type check as `is_int(...)`, not a truthy check - a mutation that
     * swapped the branch would drop zero to `null`.
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

        $guard->setUser($identity);

        self::assertSame(0, $guard->id());
    }

    /**
     * `id()` returns the literal string `'0'` when the identifier is the zero
     * string. Same mutation guard as the integer variant.
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

        $guard->setUser($identity);

        self::assertSame('0', $guard->id());
    }

    /**
     * `id()` returns `null` when `getAuthIdentifier()` returns a float - the
     * type narrowing rejects floats to avoid truncating to an int.
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

        $guard->setUser($identity);

        self::assertNull($guard->id());
    }

    /**
     * `id()` returns `null` when `getAuthIdentifier()` returns a boolean. Pins
     * the matrix: bool is neither int nor string.
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

        $guard->setUser($identity);

        self::assertNull($guard->id());
    }

    /**
     * `id()` returns `null` when `getAuthIdentifier()` returns an object (e.g.
     * a value-object id). Pins the matrix: object is neither int nor string.
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

        $guard->setUser($identity);

        self::assertNull($guard->id());
    }

    /**
     * `validate()` returns `false` (and does NOT call `Timebox::returnEarly`)
     * when the identity provider returns a non-Identity user that fails
     * `hasValidCredentials`. Pins the `return false` arm of the validate()
     * match.
     *
     * @return void
     */
    public function testValidateReturnsFalseWhenCredentialsRejected(): void
    {
        $guard = $this->makeGuard();

        $this->provider->shouldReceive('retrieveByCredentials')
            ->once()
            ->andReturnNull();
        $this->provider->shouldNotReceive('validateCredentials');

        // No `Validated` event should fire on the failure path.
        $this->events->shouldNotReceive('dispatch');

        self::assertFalse($guard->validate(['email' => 'ghost@example.test']));
    }

    /**
     * `validate()` accepts the documented default `[]` argument and returns
     * false because the empty credentials never resolve a user.
     *
     * @return void
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
