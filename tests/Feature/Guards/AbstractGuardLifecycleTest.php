<?php

declare(strict_types = 1);

namespace Tests\Feature\Guards;

use Illuminate\Auth\Events\Authenticated;
use Illuminate\Auth\Events\Login;
use Illuminate\Auth\Events\Logout;
use Illuminate\Auth\Events\Validated;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Contracts\Device;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Guards\AbstractGuard;

/**
 * Feature tests for the Laravel `Guard` contract surface on `AbstractGuard`
 * (`check`, `guest`, `user`, `id`, `hasUser`, `setUser`, `logout`).
 *
 * Split out of the original AbstractGuardTest so each class stays focused on a
 * single behavioural slice.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AbstractGuard::class)]
final class AbstractGuardLifecycleTest extends AbstractGuardTestCase
{
    /**
     * A fresh guard reports unauthenticated via check().
     *
     * @return void
     */
    public function testCheckReturnsFalseWhenNoIdentityBound(): void
    {
        $guard = $this->makeGuard();

        self::assertFalse($guard->check());
    }

    /**
     * After login(), check() reports authenticated.
     *
     * @return void
     */
    public function testCheckReturnsTrueAfterLogin(): void
    {
        $guard = $this->makeGuard();

        $identity  = $this->mockIdentity();
        $principal = \Mockery::mock(Principal::class);

        $this->events->shouldReceive('dispatch')->andReturnNull();

        $guard->login($identity, $principal);

        self::assertTrue($guard->check());
    }

    /**
     * guest() is the inverse of check() in a freshly-built guard.
     *
     * @return void
     */
    public function testGuestReturnsTrueOnFreshGuard(): void
    {
        self::assertTrue($this->makeGuard()->guest());
    }

    /**
     * guest() is the inverse of check() once a login has occurred.
     *
     * @return void
     */
    public function testGuestReturnsFalseAfterLogin(): void
    {
        $guard = $this->makeGuard();

        $this->events->shouldReceive('dispatch')->andReturnNull();
        $guard->login($this->mockIdentity(), \Mockery::mock(Principal::class));

        self::assertFalse($guard->guest());
    }

    /**
     * user() returns the identity bound by login().
     *
     * @return void
     */
    public function testUserReturnsBoundIdentity(): void
    {
        $guard = $this->makeGuard();

        $identity  = $this->mockIdentity();
        $principal = \Mockery::mock(Principal::class);

        $this->events->shouldReceive('dispatch')->andReturnNull();

        $guard->login($identity, $principal);

        self::assertSame($identity, $guard->user());
    }

    /**
     * id() returns the bound identity's auth identifier.
     *
     * @return void
     */
    public function testIdReturnsAuthIdentifier(): void
    {
        $guard = $this->makeGuard();

        $identity = $this->mockIdentity();
        $identity->shouldReceive('getAuthIdentifier')
            ->andReturn(42);

        $principal = \Mockery::mock(Principal::class);

        $this->events->shouldReceive('dispatch')->andReturnNull();

        $guard->login($identity, $principal);

        self::assertSame(42, $guard->id());
    }

    /**
     * id() is null when no identity is bound.
     *
     * @return void
     */
    public function testIdReturnsNullWhenNoIdentityBound(): void
    {
        self::assertNull($this->makeGuard()->id());
    }

    /**
     * hasUser() returns false on a fresh guard.
     *
     * @return void
     */
    public function testHasUserReturnsFalseOnFreshGuard(): void
    {
        self::assertFalse($this->makeGuard()->hasUser());
    }

    /**
     * hasUser() returns true after a successful login.
     *
     * @return void
     */
    public function testHasUserReturnsTrueAfterLogin(): void
    {
        $guard = $this->makeGuard();

        $this->events->shouldReceive('dispatch')->andReturnNull();
        $guard->login($this->mockIdentity(), \Mockery::mock(Principal::class));

        self::assertTrue($guard->hasUser());
    }

    /**
     * setUser() binds the identity and fires the Authenticated event.
     *
     * @return void
     */
    public function testSetUserBindsIdentityAndFiresAuthenticatedEvent(): void
    {
        $guard = $this->makeGuard();

        $identity = $this->mockIdentity();

        $this->events->shouldReceive('dispatch')
            ->once()
            ->with(
                \Mockery::on(static fn (mixed $event): bool => $event instanceof Authenticated
                    && $event->guard === self::GUARD_NAME
                    && $event->user  === $identity),
            );

        $guard->setUser($identity);

        self::assertSame($identity, $guard->user());
    }

    /**
     * setUser() rejects Authenticatable instances that are not Identity.
     *
     * @return void
     */
    public function testSetUserThrowsInvalidArgumentExceptionForNonIdentityAuthenticatable(): void
    {
        $guard = $this->makeGuard();

        $user = \Mockery::mock(Authenticatable::class);

        $this->events->shouldNotReceive('dispatch');

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage(self::GUARD_NAME);

        $guard->setUser($user);
    }

    /**
     * logout() dispatches Logout and clears identity/principal/device state.
     *
     * @return void
     */
    public function testLogoutDispatchesLogoutEventAndClearsState(): void
    {
        $guard = $this->makeGuard();

        $identity  = $this->mockIdentity();
        $principal = \Mockery::mock(Principal::class);
        $device    = \Mockery::mock(Device::class);

        $dispatched = [];

        $this->events->shouldReceive('dispatch')
            ->andReturnUsing(static function (object $event) use (&$dispatched): void {
                $dispatched[] = $event;
            });

        $guard->login($identity, $principal, $device);
        $guard->logout();

        self::assertNull($guard->user());
        self::assertNull($guard->principal());
        self::assertNull($guard->device());

        $logoutEvents = array_values(
            array_filter(
                $dispatched,
                static fn (object $event): bool => $event instanceof Logout,
            ),
        );

        self::assertCount(1, $logoutEvents);
        self::assertInstanceOf(Logout::class, $logoutEvents[0]);
        self::assertSame(self::GUARD_NAME, $logoutEvents[0]->guard);
        self::assertSame($identity, $logoutEvents[0]->user);
    }

    /**
     * logout() is a no-op when nothing is bound.
     *
     * @return void
     */
    public function testLogoutNoOpsWhenNoIdentityBound(): void
    {
        $guard = $this->makeGuard();

        $this->events->shouldNotReceive('dispatch');

        $guard->logout();

        self::assertNull($guard->user());
    }

    /**
     * Calling `login()` directly (e.g. from a refresh exchange or an OAuth
     * callback) fires the standard `Validated` event before the bind, even
     * though no `hasValidCredentials()` call happened. This is the M14 design
     * call: `login()` is the public entry point that asserts "this identity
     * has been validated", and the standard event sequence reflects that.
     *
     * @return void
     */
    public function testLoginFiresValidatedEventBeforeBindingState(): void
    {
        $guard = $this->makeGuard();

        $identity  = $this->mockIdentity();
        $principal = \Mockery::mock(Principal::class);

        $dispatched = [];

        $this->events->shouldReceive('dispatch')
            ->andReturnUsing(static function (object $event) use (&$dispatched): void {
                $dispatched[] = $event::class;
            });

        $guard->login($identity, $principal);

        self::assertContains(Validated::class, $dispatched);
        self::assertContains(Authenticated::class, $dispatched);
        self::assertContains(Login::class, $dispatched);
        self::assertSame(
            array_search(Validated::class, $dispatched, true),
            0,
            'Validated must fire before Authenticated/PrincipalAssigned/Login on the direct login() path.',
        );
    }

    /**
     * The shared `getName()` accessor returns the registered guard name.
     *
     * @return void
     */
    public function testGetNameReturnsRegisteredGuardName(): void
    {
        self::assertSame(self::GUARD_NAME, $this->makeGuard()->getName());
    }

    /**
     * The shared `setRequest()` mutator returns the guard for chaining and
     * persists the supplied request on the protected slot used by subclasses.
     *
     * @return void
     */
    public function testSetRequestReplacesBoundRequestAndReturnsGuard(): void
    {
        $guard = $this->makeGuard();

        $request = Request::create('/swap', 'GET');

        self::assertSame($guard, $guard->setRequest($request));
    }

    /**
     * Rebinding the request must clear any previously memoized contextual state
     * so guard instances cannot leak auth context across requests.
     *
     * @return void
     */
    public function testSetRequestClearsBoundContextualState(): void
    {
        $guard = $this->makeGuard();

        $this->events->shouldReceive('dispatch')->andReturnNull();

        $guard->login(
            $this->mockIdentity(),
            \Mockery::mock(Principal::class),
            \Mockery::mock(Device::class),
        );

        $guard->setRequest(Request::create('/swap', 'GET'));

        self::assertNull($guard->user());
        self::assertNull($guard->principal());
        self::assertNull($guard->device());
    }
}
