<?php

declare(strict_types = 1);

namespace Tests\Feature\Guards;

use Illuminate\Auth\Events\Attempting;
use Illuminate\Auth\Events\Authenticated;
use Illuminate\Auth\Events\Failed;
use Illuminate\Auth\Events\Login;
use Illuminate\Auth\Events\Validated;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Builder;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Contracts\CanBeActive;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Events\DeviceAuthenticated;
use SineMacula\Laravel\Authentication\Events\PrincipalAssigned;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use Tests\Unit\Stubs\StubDevice;
use Tests\Unit\Stubs\StubIdentity;

/**
 * Unit tests for the bearer-token `user()` resolution path on
 * `JwtGuard`.
 *
 * Split out of the original JwtGuardTest so each derived class stays
 * well below the project's 20-method-per-class threshold (radarlint
 * S1448).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 *
 * @internal
 */
#[CoversClass(JwtGuard::class)]
final class JwtGuardUserResolutionTest extends JwtGuardTestCase
{
    /**
     * A request with no Authorization header returns null from `user()`
     * without firing Attempting or Failed (there is nothing to attempt).
     *
     * @return void
     */
    public function testUserReturnsNullWhenNoBearerTokenPresent(): void
    {
        $guard = $this->makeGuard($this->makeRequest(null));

        $this->events->shouldNotReceive('dispatch');
        $this->provider->shouldNotReceive('retrieveById');

        self::assertNull($guard->user());
    }

    /**
     * A request whose `Authorization: Bearer` header carries an
     * empty string token returns null without firing any events.
     * Mutation guard: pins the `$token === ''` arm at
     * `JwtGuard.php:100` separately from the `null` arm above.
     *
     * @return void
     */
    public function testUserReturnsNullWhenBearerTokenIsEmptyString(): void
    {
        $guard = $this->makeGuard($this->makeRequest(''));

        $this->events->shouldNotReceive('dispatch');
        $this->provider->shouldNotReceive('retrieveById');

        self::assertNull($guard->user());
    }

    /**
     * When the token service cannot parse a token (malformed / bad
     * signature / expired), `user()` fires `Attempting` and `Failed`
     * then returns null.
     *
     * @return void
     */
    public function testUserReturnsNullWhenTokenServiceCannotParseToken(): void
    {
        $guard = $this->makeGuard($this->makeRequest('not-a-jwt'));

        $dispatched = [];

        $this->events->shouldReceive('dispatch')
            ->andReturnUsing(static function (object $event) use (&$dispatched): void {
                $dispatched[] = $event::class;
            });

        $this->provider->shouldNotReceive('retrieveById');

        self::assertNull($guard->user());
        self::assertSame([Attempting::class, Failed::class], $dispatched);
    }

    /**
     * A token whose claims array lacks `sub` fires Attempting+Failed
     * and returns null.
     *
     * @return void
     */
    public function testUserReturnsNullWhenSubClaimMissing(): void
    {
        $token = $this->encodeAccessToken(['pid' => 'p-1', 'did' => 'd-1']);

        $guard = $this->makeGuard($this->makeRequest($token));

        $dispatched = [];

        $this->events->shouldReceive('dispatch')
            ->andReturnUsing(static function (object $event) use (&$dispatched): void {
                $dispatched[] = $event::class;
            });

        $this->provider->shouldNotReceive('retrieveById');

        self::assertNull($guard->user());
        self::assertSame([Attempting::class, Failed::class], $dispatched);
    }

    /**
     * When `retrieveById()` returns null, `user()` returns null.
     *
     * @return void
     */
    public function testUserReturnsNullWhenIdentityNotFound(): void
    {
        $token = $this->encodeAccessToken(['sub' => 'i-1']);

        $guard = $this->makeGuard($this->makeRequest($token));

        $this->provider->shouldReceive('retrieveById')
            ->once()
            ->with('i-1')
            ->andReturnNull();

        $this->resolver->shouldNotReceive('resolve');

        $this->events->shouldReceive('dispatch')
            ->with(\Mockery::type(Attempting::class));
        $this->events->shouldReceive('dispatch')
            ->with(\Mockery::type(Failed::class));

        self::assertNull($guard->user());
    }

    /**
     * When `retrieveById()` returns an Authenticatable that is not an
     * Identity, `user()` returns null.
     *
     * @return void
     */
    public function testUserReturnsNullWhenResolvedUserIsNotIdentity(): void
    {
        $token = $this->encodeAccessToken(['sub' => 'i-1']);

        $guard = $this->makeGuard($this->makeRequest($token));

        $nonIdentity = \Mockery::mock(Authenticatable::class);

        $this->provider->shouldReceive('retrieveById')
            ->once()
            ->with('i-1')
            ->andReturn($nonIdentity);

        $this->resolver->shouldNotReceive('resolve');

        $this->events->shouldReceive('dispatch')
            ->with(\Mockery::type(Attempting::class));
        $this->events->shouldReceive('dispatch')
            ->with(\Mockery::type(Failed::class));

        self::assertNull($guard->user());
    }

    /**
     * When `resolver->resolve()` returns null, `user()` returns null.
     *
     * @return void
     */
    public function testUserReturnsNullWhenResolverProducesNoPrincipal(): void
    {
        $token = $this->encodeAccessToken(['sub' => 'i-1']);

        $guard = $this->makeGuard($this->makeRequest($token));

        $identity = \Mockery::mock(Identity::class);

        $this->provider->shouldReceive('retrieveById')
            ->once()
            ->with('i-1')
            ->andReturn($identity);

        $this->resolver->shouldReceive('resolve')
            ->once()
            ->with($identity)
            ->andReturnNull();

        $this->events->shouldReceive('dispatch')
            ->with(\Mockery::type(Attempting::class));
        $this->events->shouldReceive('dispatch')
            ->with(\Mockery::type(Failed::class));

        self::assertNull($guard->user());
    }

    /**
     * When the resolved principal's `isActive()` returns false, `user()`
     * returns null.
     *
     * @return void
     */
    public function testUserReturnsNullWhenResolvedPrincipalIsInactive(): void
    {
        $token = $this->encodeAccessToken(['sub' => 'i-1', 'pid' => 'p-1']);

        $guard = $this->makeGuard($this->makeRequest($token));

        $identity = \Mockery::mock(Identity::class);

        $principal = \Mockery::mock(Principal::class);
        $principal->shouldReceive('getPrincipalIdentifier')
            ->andReturn('p-1');
        $principal->shouldReceive('isActive')
            ->once()
            ->andReturnFalse();

        $this->provider->shouldReceive('retrieveById')
            ->once()
            ->with('i-1')
            ->andReturn($identity);

        $this->resolver->shouldReceive('resolve')
            ->once()
            ->with($identity, 'p-1')
            ->andReturn($principal);

        $this->events->shouldReceive('dispatch')
            ->with(\Mockery::type(Attempting::class));
        $this->events->shouldReceive('dispatch')
            ->with(\Mockery::type(Failed::class));

        self::assertNull($guard->user());
    }

    /**
     * A `CanBeActive` identity reporting `false` is rejected by
     * `user()` after `retrieveById()` returns it.
     *
     * @return void
     */
    public function testUserReturnsNullWhenIdentityIsInactive(): void
    {
        $token = $this->encodeAccessToken(['sub' => 'i-1']);

        $guard = $this->makeGuard($this->makeRequest($token));

        $identity = \Mockery::mock(Identity::class, CanBeActive::class);
        $identity->shouldReceive('isActive')->once()->andReturnFalse();

        $this->provider->shouldReceive('retrieveById')
            ->once()
            ->with('i-1')
            ->andReturn($identity);

        $this->resolver->shouldNotReceive('resolve');

        $this->events->shouldReceive('dispatch')
            ->with(\Mockery::type(Attempting::class));
        $this->events->shouldReceive('dispatch')
            ->with(\Mockery::type(Failed::class));

        self::assertNull($guard->user());
    }

    /**
     * Fail-closed: when the token carries a `pid` hint but the
     * resolver returns `null` (the hinted principal cannot be
     * resolved), `user()` rejects the token rather than falling back
     * to the default principal.
     *
     * @return void
     */
    public function testUserRejectsTokenWhenPidHintResolvesToNullPrincipal(): void
    {
        $token = $this->encodeAccessToken(['sub' => 'i-1', 'pid' => 'p-hinted']);

        $guard = $this->makeGuard($this->makeRequest($token));

        $identity = \Mockery::mock(Identity::class);

        $this->provider->shouldReceive('retrieveById')
            ->once()
            ->with('i-1')
            ->andReturn($identity);

        $this->resolver->shouldReceive('resolve')
            ->once()
            ->with($identity, 'p-hinted')
            ->andReturnNull();

        $this->events->shouldReceive('dispatch')
            ->with(\Mockery::type(Attempting::class));
        $this->events->shouldReceive('dispatch')
            ->with(\Mockery::type(Failed::class));

        self::assertNull($guard->user());
    }

    /**
     * Fail-closed: when the token carries a `pid` hint but the
     * resolver returns a *different* principal (because it fell
     * through to the default), `user()` returns null rather than
     * silently downgrading the active principal.
     *
     * @return void
     */
    public function testUserRejectsTokenWhenPidHintDoesNotMatchResolvedPrincipal(): void
    {
        $token = $this->encodeAccessToken(['sub' => 'i-1', 'pid' => 'p-hinted']);

        $guard = $this->makeGuard($this->makeRequest($token));

        $identity = \Mockery::mock(Identity::class);

        $principal = \Mockery::mock(Principal::class);
        $principal->shouldReceive('getPrincipalIdentifier')
            ->andReturn('p-default');

        $this->provider->shouldReceive('retrieveById')
            ->once()
            ->with('i-1')
            ->andReturn($identity);

        $this->resolver->shouldReceive('resolve')
            ->once()
            ->with($identity, 'p-hinted')
            ->andReturn($principal);

        $this->events->shouldReceive('dispatch')
            ->with(\Mockery::type(Attempting::class));
        $this->events->shouldReceive('dispatch')
            ->with(\Mockery::type(Failed::class));

        self::assertNull($guard->user());
    }

    /**
     * Fail-closed: when the resolver returns a principal whose
     * identifier stringifies to `null` (e.g. an unsaved Eloquent
     * model returned from a misbehaving custom resolver), the guard
     * MUST reject the token rather than bind a transient actor.
     * Pins the `$resolvedId !== null` arm of `matchesPidHint()`.
     *
     * @return void
     */
    public function testUserRejectsTokenWhenResolvedPrincipalIdentifierIsNull(): void
    {
        $token = $this->encodeAccessToken(['sub' => 'i-1', 'pid' => 'p-hinted']);

        $guard = $this->makeGuard($this->makeRequest($token));

        $identity = \Mockery::mock(Identity::class);

        $principal = \Mockery::mock(Principal::class);
        $principal->shouldReceive('getPrincipalIdentifier')
            ->andReturn(null);

        $this->provider->shouldReceive('retrieveById')
            ->once()
            ->with('i-1')
            ->andReturn($identity);

        $this->resolver->shouldReceive('resolve')
            ->once()
            ->with($identity, 'p-hinted')
            ->andReturn($principal);

        $this->events->shouldReceive('dispatch')
            ->with(\Mockery::type(Attempting::class));
        $this->events->shouldReceive('dispatch')
            ->with(\Mockery::type(Failed::class));

        self::assertNull($guard->user());
    }

    /**
     * Fail-closed: when the token carries a `did` hint but the
     * device lookup fails, `user()` returns null rather than
     * silently binding the identity with no device.
     *
     * @return void
     */
    public function testUserRejectsTokenWhenDidHintCannotBeResolved(): void
    {
        $token = $this->encodeAccessToken(['sub' => 'i-1', 'pid' => 'p-1', 'did' => 'd-missing']);

        $guard = $this->makeGuard($this->makeRequest($token));

        $builder = \Mockery::mock(Builder::class);
        $builder->shouldReceive('find')
            ->once()
            ->with('d-missing')
            ->andReturnNull();

        /** @var \Mockery\MockInterface&\Tests\Unit\Stubs\StubIdentity $identity */
        $identity = \Mockery::mock(StubIdentity::class)->makePartial();
        $identity->shouldReceive('devices')
            ->once()
            ->andReturn($builder);

        $principal = \Mockery::mock(Principal::class);
        $principal->shouldReceive('getPrincipalIdentifier')
            ->andReturn('p-1');
        $principal->shouldReceive('isActive')
            ->once()
            ->andReturnTrue();

        $this->provider->shouldReceive('retrieveById')
            ->once()
            ->with('i-1')
            ->andReturn($identity);

        $this->resolver->shouldReceive('resolve')
            ->once()
            ->with($identity, 'p-1')
            ->andReturn($principal);

        $this->events->shouldReceive('dispatch')
            ->with(\Mockery::type(Attempting::class));
        $this->events->shouldReceive('dispatch')
            ->with(\Mockery::type(Failed::class));

        self::assertNull($guard->user());
    }

    /**
     * A valid token whose claims include `sub`, `pid`, and `did` results
     * in the guard binding the identity, principal, and device and
     * dispatching `Attempting`, `Authenticated`, `Validated`,
     * `PrincipalAssigned`, `DeviceAuthenticated`, and `Login`.
     *
     * @return void
     */
    public function testUserBindsIdentityPrincipalAndDeviceFromValidToken(): void
    {
        $token = $this->encodeAccessToken(['sub' => 'i-1', 'pid' => 'p-1', 'did' => 'd-1']);

        $guard = $this->makeGuard($this->makeRequest($token));

        $device = new StubDevice(['id' => 'd-1']);

        $builder = \Mockery::mock(Builder::class);
        $builder->shouldReceive('find')
            ->once()
            ->with('d-1')
            ->andReturn($device);

        /** @var \Mockery\MockInterface&\Tests\Unit\Stubs\StubIdentity $identity */
        $identity = \Mockery::mock(StubIdentity::class)->makePartial();
        $identity->shouldReceive('devices')
            ->once()
            ->andReturn($builder);

        $principal = \Mockery::mock(Principal::class);
        $principal->shouldReceive('getPrincipalIdentifier')
            ->andReturn('p-1');
        $principal->shouldReceive('isActive')
            ->once()
            ->andReturnTrue();

        $this->provider->shouldReceive('retrieveById')
            ->once()
            ->with('i-1')
            ->andReturn($identity);

        $this->resolver->shouldReceive('resolve')
            ->once()
            ->with($identity, 'p-1')
            ->andReturn($principal);

        $dispatched = [];

        $this->events->shouldReceive('dispatch')
            ->andReturnUsing(static function (object $event) use (&$dispatched): void {
                $dispatched[] = $event::class;
            });

        self::assertNotNull($guard->user());
        self::assertSame($identity, $guard->identity());
        self::assertSame($principal, $guard->principal());
        self::assertSame($device, $guard->device());

        // Assert the full, ordered event sequence. The bearer-resolution
        // path routes through `login()` which fires `Validated`, then
        // `bindAuthenticationLifecycle()` which fires `Login` before
        // `Authenticated` (Laravel's ordering), followed by the
        // contextual `PrincipalAssigned` and `DeviceAuthenticated`
        // events as the state is bound. See C3 in `ISSUES.md`.
        self::assertSame(
            [
                Attempting::class,
                Validated::class,
                Login::class,
                Authenticated::class,
                PrincipalAssigned::class,
                DeviceAuthenticated::class,
            ],
            $dispatched,
        );
    }

    /**
     * A valid token without a `did` claim binds identity + principal
     * and does NOT fire `DeviceAuthenticated`.
     *
     * @return void
     */
    public function testUserSkipsDeviceWhenNoDidClaimPresent(): void
    {
        $token = $this->encodeAccessToken(['sub' => 'i-1', 'pid' => 'p-1']);

        $guard = $this->makeGuard($this->makeRequest($token));

        $identity = \Mockery::mock(Identity::class);

        $principal = \Mockery::mock(Principal::class);
        $principal->shouldReceive('getPrincipalIdentifier')
            ->andReturn('p-1');
        $principal->shouldReceive('isActive')
            ->once()
            ->andReturnTrue();

        $this->provider->shouldReceive('retrieveById')
            ->once()
            ->with('i-1')
            ->andReturn($identity);

        $this->resolver->shouldReceive('resolve')
            ->once()
            ->with($identity, 'p-1')
            ->andReturn($principal);

        $dispatched = [];

        $this->events->shouldReceive('dispatch')
            ->andReturnUsing(static function (object $event) use (&$dispatched): void {
                $dispatched[] = $event::class;
            });

        self::assertSame($identity, $guard->user());
        self::assertSame($principal, $guard->principal());
        self::assertNull($guard->device());
        self::assertNotContains(DeviceAuthenticated::class, $dispatched);
    }
}
