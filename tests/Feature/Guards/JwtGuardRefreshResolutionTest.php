<?php

declare(strict_types = 1);

namespace Tests\Feature\Guards;

use Illuminate\Auth\Events\Attempting;
use Illuminate\Auth\Events\Authenticated;
use Illuminate\Auth\Events\Failed;
use Illuminate\Auth\Events\Login;
use Illuminate\Auth\Events\Validated;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Contracts\CanBeActive;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\PrincipalResolver;
use SineMacula\Laravel\Authentication\Contracts\ResolutionCache;
use SineMacula\Laravel\Authentication\Events\DeviceAuthenticated;
use SineMacula\Laravel\Authentication\Events\Enums\RefreshFailureReason;
use SineMacula\Laravel\Authentication\Events\PrincipalAssigned;
use SineMacula\Laravel\Authentication\Events\Refreshed;
use SineMacula\Laravel\Authentication\Events\RefreshFailed;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Jwt\Enums\Claims;
use SineMacula\Laravel\Authentication\Jwt\Enums\TokenType;
use SineMacula\Laravel\Authentication\Jwt\IdentifierCoercion;
use SineMacula\Laravel\Authentication\Jwt\RefreshResult;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenExchange;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenHasher;
use Tests\Unit\Stubs\StubDevice;
use Tests\Unit\Stubs\StubIdentity;

/**
 * Feature tests for the identity and principal resolution paths within
 * JwtGuard's refresh-token exchange, plus the successful refresh lifecycle.
 *
 * Split from JwtGuardRefreshTest so each class stays focused on a single
 * behavioural slice: this class covers identity/principal resolution failures
 * and the success-path event sequence.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(JwtGuard::class)]
#[CoversClass(RefreshTokenExchange::class)]
#[CoversClass(IdentifierCoercion::class)]
final class JwtGuardRefreshResolutionTest extends JwtGuardTestCase
{
    /**
     * When the bound identity reports `isActive() === false`, refresh fails
     * with `identity_inactive` and dispatches `RefreshFailed`.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testRefreshReturnsNullWhenIdentityIsInactive(): void
    {
        $plainRotationId = 'stored-rotation-id';

        $identity = \Mockery::mock(Identity::class, CanBeActive::class);
        $identity->shouldReceive('isActive')->once()->andReturnFalse();

        $device = new StubDevice;
        $device->forceFill(['refresh_key' => RefreshTokenHasher::hash($plainRotationId)])->save();
        $device->setRelation('authenticatable', $identity);

        $this->swapDeviceModelToInMemoryInstance($device);

        $guard = $this->makeGuard($this->makeRequest(null));

        $token = $this->encodeRefreshToken([
            'did' => $device->id,
            'jti' => $plainRotationId,
        ]);

        $this->resolver->shouldNotReceive('resolve');

        $this->expectRefreshFailureEvents();
        $this->events->shouldReceive('dispatch')
            ->once()
            ->with(
                \Mockery::on(static fn (mixed $event): bool => $event instanceof RefreshFailed
                    && $event->reason === RefreshFailureReason::IDENTITY_INACTIVE),
            );

        self::assertNull($guard->refresh($token));
    }

    /**
     * When a refresh token carries a `pid` hint but the resolver returns
     * `null`, refresh fails with `principal_unresolved` instead of downgrading
     * to the default principal.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testRefreshReturnsNullWhenPrincipalIsUnresolved(): void
    {
        $plainRotationId = 'stored-rotation-id';

        $identity = new StubIdentity;
        $identity->forceFill(['id' => 9]);

        $device = new StubDevice;
        $device->forceFill([
            'authenticatable_type' => StubIdentity::class,
            'authenticatable_id'   => '9',
            'refresh_key'          => RefreshTokenHasher::hash($plainRotationId),
        ])->save();
        $device->setRelation('authenticatable', $identity);

        $this->swapDeviceModelToInMemoryInstance($device);

        $guard = $this->makeGuard($this->makeRequest(null));

        $this->resolver->shouldReceive('resolve')
            ->once()
            ->with($identity, 'p-hinted')
            ->andReturnNull();

        $token = $this->encodeRefreshToken([
            'pid' => 'p-hinted',
            'did' => $device->id,
            'jti' => $plainRotationId,
        ]);

        $this->expectRefreshFailureEvents();
        $this->events->shouldReceive('dispatch')
            ->once()
            ->with(
                \Mockery::on(static fn (mixed $event): bool => $event instanceof RefreshFailed
                    && $event->reason   === RefreshFailureReason::PRINCIPAL_MISMATCH
                    && $event->deviceId === $device->id),
            );

        self::assertNull($guard->refresh($token));
    }

    /**
     * When a refresh token carries a `pid` hint but the resolver returns a
     * different principal, refresh fails with `principal_mismatch`.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testRefreshReturnsNullWhenPidHintDoesNotMatchResolvedPrincipal(): void
    {
        $plainRotationId = 'stored-rotation-id';

        $identity = new StubIdentity;
        $identity->forceFill(['id' => 10]);

        $device = new StubDevice;
        $device->forceFill([
            'authenticatable_type' => StubIdentity::class,
            'authenticatable_id'   => '10',
            'refresh_key'          => RefreshTokenHasher::hash($plainRotationId),
        ])->save();
        $device->setRelation('authenticatable', $identity);

        $this->swapDeviceModelToInMemoryInstance($device);

        $guard = $this->makeGuard($this->makeRequest(null));

        $principal = \Mockery::mock(Principal::class);
        $principal->shouldReceive('getPrincipalIdentifier')
            ->once()
            ->andReturn('p-default');

        $this->resolver->shouldReceive('resolve')
            ->once()
            ->with($identity, 'p-hinted')
            ->andReturn($principal);

        $token = $this->encodeRefreshToken([
            'pid' => 'p-hinted',
            'did' => $device->id,
            'jti' => $plainRotationId,
        ]);

        $this->expectRefreshFailureEvents();
        $this->events->shouldReceive('dispatch')
            ->once()
            ->with(
                \Mockery::on(static fn (mixed $event): bool => $event instanceof RefreshFailed
                    && $event->reason   === RefreshFailureReason::PRINCIPAL_MISMATCH
                    && $event->deviceId === $device->id),
            );

        self::assertNull($guard->refresh($token));
    }

    /**
     * Fail-closed: a hinted principal whose identifier stringifies to `null`
     * must be rejected rather than rebound into a transient principal.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testRefreshReturnsNullWhenResolvedPrincipalIdentifierIsNull(): void
    {
        $plainRotationId = 'stored-rotation-id';

        $identity = new StubIdentity;
        $identity->forceFill(['id' => 15]);

        $device = new StubDevice;
        $device->forceFill([
            'authenticatable_type' => StubIdentity::class,
            'authenticatable_id'   => '15',
            'refresh_key'          => RefreshTokenHasher::hash($plainRotationId),
        ])->save();
        $device->setRelation('authenticatable', $identity);

        $this->swapDeviceModelToInMemoryInstance($device);

        $guard = $this->makeGuard($this->makeRequest(null));

        $principal = \Mockery::mock(Principal::class);
        $principal->shouldReceive('getPrincipalIdentifier')
            ->once()
            ->andReturn(null);

        $this->resolver->shouldReceive('resolve')
            ->once()
            ->with($identity, 'p-hinted')
            ->andReturn($principal);

        $token = $this->encodeRefreshToken([
            'pid' => 'p-hinted',
            'did' => $device->id,
            'jti' => $plainRotationId,
        ]);

        $this->expectRefreshFailureEvents();
        $this->events->shouldReceive('dispatch')
            ->once()
            ->with(
                \Mockery::on(static fn (mixed $event): bool => $event instanceof RefreshFailed
                    && $event->reason   === RefreshFailureReason::PRINCIPAL_MISMATCH
                    && $event->deviceId === $device->id),
            );

        self::assertNull($guard->refresh($token));
    }

    /**
     * When the hinted principal reports `isActive() === false`, refresh fails
     * with `principal_inactive` and dispatches `RefreshFailed`.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testRefreshReturnsNullWhenPrincipalIsInactive(): void
    {
        $plainRotationId = 'stored-rotation-id';

        $identity = new StubIdentity;
        $identity->forceFill(['id' => 11]);

        $device = new StubDevice;
        $device->forceFill([
            'authenticatable_type' => StubIdentity::class,
            'authenticatable_id'   => '11',
            'refresh_key'          => RefreshTokenHasher::hash($plainRotationId),
        ])->save();
        $device->setRelation('authenticatable', $identity);

        $this->swapDeviceModelToInMemoryInstance($device);

        $guard = $this->makeGuard($this->makeRequest(null));

        $principal = \Mockery::mock(Principal::class);
        $principal->shouldReceive('getPrincipalIdentifier')->once()->andReturn('p-11');
        $principal->shouldReceive('isActive')->once()->andReturnFalse();

        $this->resolver->shouldReceive('resolve')
            ->once()
            ->with($identity, 'p-11')
            ->andReturn($principal);

        $token = $this->encodeRefreshToken([
            'pid' => 'p-11',
            'did' => $device->id,
            'jti' => $plainRotationId,
        ]);

        $this->expectRefreshFailureEvents();
        $this->events->shouldReceive('dispatch')
            ->once()
            ->with(
                \Mockery::on(static fn (mixed $event): bool => $event instanceof RefreshFailed
                    && $event->reason === RefreshFailureReason::PRINCIPAL_INACTIVE),
            );

        self::assertNull($guard->refresh($token));
    }

    /**
     * Fail-closed: when the resolver returns `null` for a hinted `pid` during
     * refresh, `matchesPidHint` must return `false` so the exchange rejects the
     * token. Mutation guard: pins the `$resolved === null` early-return `false`
     * in `RefreshTokenExchange::matchesPidHint()`.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testRefreshRejectsTokenWhenNullPrincipalResolvesForPidHint(): void
    {
        $plainRotationId = 'stored-rotation-id';

        $identity = new StubIdentity;
        $identity->forceFill(['id' => 25]);

        $device = new StubDevice;
        $device->forceFill([
            'authenticatable_type' => StubIdentity::class,
            'authenticatable_id'   => '25',
            'refresh_key'          => RefreshTokenHasher::hash($plainRotationId),
        ])->save();
        $device->setRelation('authenticatable', $identity);

        $this->swapDeviceModelToInMemoryInstance($device);

        $guard = $this->makeGuard($this->makeRequest(null));

        $this->resolver->shouldReceive('resolve')
            ->once()
            ->with($identity, 'p-hinted')
            ->andReturnNull();

        $token = $this->encodeRefreshToken([
            'pid' => 'p-hinted',
            'did' => $device->id,
            'jti' => $plainRotationId,
        ]);

        $this->expectRefreshFailureEvents();
        $this->events->shouldReceive('dispatch')
            ->once()
            ->with(
                \Mockery::on(static fn (mixed $event): bool => $event instanceof RefreshFailed
                    && $event->reason === RefreshFailureReason::PRINCIPAL_MISMATCH),
            );

        self::assertNull($guard->refresh($token));
    }

    /**
     * A successful refresh preserves the original active principal by carrying
     * the same `pid` through the rotated refresh token and newly issued access
     * token.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testRefreshRotatesAndIssuesNewTokenPairOnSuccess(): void
    {
        $plainRotationId = 'stored-rotation-id';
        $oldDigest       = RefreshTokenHasher::hash($plainRotationId);

        $identity = new StubIdentity;
        $identity->forceFill(['id' => 7]);

        $device = new StubDevice;
        $device->forceFill([
            'authenticatable_type' => StubIdentity::class,
            'authenticatable_id'   => '7',
            'refresh_key'          => $oldDigest,
        ])->save();

        $device->setRelation('authenticatable', $identity);

        $this->swapDeviceModelToInMemoryInstance($device);

        $guard = $this->makeGuard($this->makeRequest(null));

        $principal = \Mockery::mock(Principal::class);
        $principal->shouldReceive('getPrincipalIdentifier')
            ->andReturn('p-1');
        $principal->shouldReceive('isActive')
            ->once()
            ->andReturnTrue();

        $this->resolver->shouldReceive('resolve')
            ->once()
            ->with($identity, 'p-1')
            ->andReturn($principal);

        $token = $this->encodeRefreshToken([
            'pid' => 'p-1',
            'did' => $device->id,
            'jti' => $plainRotationId,
        ]);

        $dispatched = [];

        $this->events->shouldReceive('dispatch')
            ->andReturnUsing(static function (object $event) use (&$dispatched): void {
                $dispatched[] = $event;
            });

        $result = $guard->refresh($token);

        self::assertInstanceOf(RefreshResult::class, $result);

        $accessClaims = $this->tokens->parse($result->accessToken, TokenType::ACCESS);
        self::assertIsArray($accessClaims);
        self::assertSame('7', $accessClaims[Claims::SUBJECT->value]);
        self::assertSame('p-1', $accessClaims[Claims::PRINCIPAL_ID->value]);
        self::assertSame($device->id, $accessClaims[Claims::DEVICE_ID->value]);

        $refreshClaims = $this->tokens->parse($result->refreshToken, TokenType::REFRESH);
        self::assertIsArray($refreshClaims);
        self::assertSame($device->id, $refreshClaims[Claims::DEVICE_ID->value]);
        self::assertSame('p-1', $refreshClaims[Claims::PRINCIPAL_ID->value]);
        self::assertIsString($refreshClaims[Claims::JWT_ID->value]);
        self::assertNotSame($plainRotationId, $refreshClaims[Claims::JWT_ID->value]);

        // The device's stored digest has been rotated and the old digest is no
        // longer valid.
        $fresh = StubDevice::query()->findOrFail($device->id);
        self::assertNotSame($oldDigest, $fresh->refresh_key);
        self::assertTrue(RefreshTokenHasher::verify($refreshClaims[Claims::JWT_ID->value], $fresh->refresh_key));

        $refreshed = array_values(
            array_filter(
                $dispatched,
                static fn (object $event): bool => $event instanceof Refreshed,
            ),
        );

        self::assertCount(1, $refreshed);
        self::assertInstanceOf(Refreshed::class, $refreshed[0]);
        self::assertSame(self::GUARD_NAME, $refreshed[0]->guard);
        self::assertSame($identity, $refreshed[0]->identity);
        self::assertSame($principal, $refreshed[0]->principal);
        self::assertSame($device, $refreshed[0]->device);
    }

    /**
     * A successful refresh routes through `login()` and then dispatches the
     * package `Refreshed` event, yielding the full ordered success sequence.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testRefreshDispatchesSuccessfulLifecycleEventsBeforeRefreshed(): void
    {
        $plainRotationId = 'stored-rotation-id';

        $identity = new StubIdentity;
        $identity->forceFill(['id' => 19]);

        $device = new StubDevice;
        $device->forceFill([
            'authenticatable_type' => StubIdentity::class,
            'authenticatable_id'   => '19',
            'refresh_key'          => RefreshTokenHasher::hash($plainRotationId),
        ])->save();

        $device->setRelation('authenticatable', $identity);

        $this->swapDeviceModelToInMemoryInstance($device);

        $guard = $this->makeGuard($this->makeRequest(null));

        $principal = \Mockery::mock(Principal::class);
        $principal->shouldReceive('getPrincipalIdentifier')
            ->andReturn('p-19');
        $principal->shouldReceive('isActive')
            ->once()
            ->andReturnTrue();

        $this->resolver->shouldReceive('resolve')
            ->once()
            ->with($identity, 'p-19')
            ->andReturn($principal);

        $token = $this->encodeRefreshToken([
            'pid' => 'p-19',
            'did' => $device->id,
            'jti' => $plainRotationId,
        ]);

        $dispatched = [];

        $this->events->shouldReceive('dispatch')
            ->times(7)
            ->andReturnUsing(static function (object $event) use (&$dispatched): void {
                $dispatched[] = $event::class;
            });

        self::assertInstanceOf(RefreshResult::class, $guard->refresh($token));
        self::assertSame([
            Attempting::class,
            Validated::class,
            Login::class,
            Authenticated::class,
            PrincipalAssigned::class,
            DeviceAuthenticated::class,
            Refreshed::class,
        ], $dispatched);
    }

    /**
     * After a successful refresh the guard has the identity, principal, and
     * device bound for the rest of the request.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testRefreshBindsIdentityPrincipalAndDeviceOnSuccess(): void
    {
        $plainRotationId = 'stored-rotation-id';

        $identity = new StubIdentity;
        $identity->forceFill(['id' => 7]);

        $device = new StubDevice;
        $device->forceFill([
            'authenticatable_type' => StubIdentity::class,
            'authenticatable_id'   => '7',
            'refresh_key'          => RefreshTokenHasher::hash($plainRotationId),
        ])->save();

        $device->setRelation('authenticatable', $identity);

        $this->swapDeviceModelToInMemoryInstance($device);

        $guard = $this->makeGuard($this->makeRequest(null));

        $principal = \Mockery::mock(Principal::class);
        $principal->shouldReceive('getPrincipalIdentifier')
            ->andReturn('p-1');
        $principal->shouldReceive('isActive')
            ->once()
            ->andReturnTrue();

        $this->resolver->shouldReceive('resolve')
            ->once()
            ->with($identity)
            ->andReturn($principal);

        $token = $this->encodeRefreshToken([
            'did' => $device->id,
            'jti' => $plainRotationId,
        ]);

        $this->events->shouldReceive('dispatch')->andReturnNull();

        self::assertInstanceOf(RefreshResult::class, $guard->refresh($token));
        self::assertSame($identity, $guard->identity());
        self::assertSame($principal, $guard->principal());
        self::assertSame($device, $guard->device());
    }

    /**
     * Rebinding the guard's principal resolver must also update the refresh
     * exchange so `refresh()` uses the replacement resolver rather than the
     * constructor-time one.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testRefreshUsesReplacementResolverAfterGuardResolverRebind(): void
    {
        $plainRotationId = 'stored-rotation-id';

        $identity = new StubIdentity;
        $identity->forceFill(['id' => 17]);

        $device = new StubDevice;
        $device->forceFill([
            'authenticatable_type' => StubIdentity::class,
            'authenticatable_id'   => '17',
            'refresh_key'          => RefreshTokenHasher::hash($plainRotationId),
        ])->save();

        $device->setRelation('authenticatable', $identity);

        $this->swapDeviceModelToInMemoryInstance($device);

        $guard = $this->makeGuard($this->makeRequest(null));

        $replacement = \Mockery::mock(PrincipalResolver::class);
        $principal   = \Mockery::mock(Principal::class);

        $principal->shouldReceive('getPrincipalIdentifier')
            ->andReturn('p-17');
        $principal->shouldReceive('isActive')
            ->once()
            ->andReturnTrue();

        $replacement->shouldReceive('resolve')
            ->once()
            ->with($identity)
            ->andReturn($principal);

        $this->resolver->shouldNotReceive('resolve');

        $guard->setPrincipalResolver($replacement);

        $token = $this->encodeRefreshToken([
            'did' => $device->id,
            'jti' => $plainRotationId,
        ]);

        $this->events->shouldReceive('dispatch')->andReturnNull();

        self::assertInstanceOf(RefreshResult::class, $guard->refresh($token));
        self::assertSame($principal, $guard->principal());
    }

    /**
     * Refresh must stay live-only even when a shared resolution cache is
     * injected into the guard.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testRefreshPathNeverUsesResolutionCache(): void
    {
        $plainRotationId = 'stored-rotation-id';

        $identity = new StubIdentity;
        $identity->forceFill(['id' => 21]);

        $device = new StubDevice;
        $device->forceFill([
            'authenticatable_type' => StubIdentity::class,
            'authenticatable_id'   => '21',
            'refresh_key'          => RefreshTokenHasher::hash($plainRotationId),
        ])->save();

        $device->setRelation('authenticatable', $identity);

        $this->swapDeviceModelToInMemoryInstance($device);

        $cache = \Mockery::mock(ResolutionCache::class);
        $cache->shouldNotReceive('rememberJwtIdentity');
        $cache->shouldNotReceive('forgetJwtIdentity');

        $guard = $this->makeGuard($this->makeRequest(null), $cache);

        $principal = \Mockery::mock(Principal::class);
        $principal->shouldReceive('getPrincipalIdentifier')->andReturn('p-21');
        $principal->shouldReceive('isActive')->once()->andReturnTrue();

        $this->resolver->shouldReceive('resolve')
            ->once()
            ->with($identity)
            ->andReturn($principal);

        $token = $this->encodeRefreshToken([
            'did' => $device->id,
            'jti' => $plainRotationId,
        ]);

        $this->events->shouldReceive('dispatch')->andReturnNull();

        self::assertInstanceOf(RefreshResult::class, $guard->refresh($token));
    }

    /**
     * `setPrincipalResolver()` must update both the parent guard and the
     * exchange resolver. This test asserts the parent (bearer) resolver is also
     * updated by resolving a bearer token after rebinding. Mutation guard: pins
     * the `parent::setPrincipalResolver()` call in
     * `JwtGuard::setPrincipalResolver()`.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testSetPrincipalResolverUpdatesBearerResolutionPath(): void
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

        $replacement = \Mockery::mock(PrincipalResolver::class);
        $replacement->shouldReceive('resolve')
            ->once()
            ->with($identity, 'p-1')
            ->andReturn($principal);

        // The original resolver must NOT be called.
        $this->resolver->shouldNotReceive('resolve');

        $this->provider->shouldReceive('retrieveById')
            ->once()
            ->with('i-1')
            ->andReturn($identity);

        $this->events->shouldReceive('dispatch')->andReturnNull();

        $guard->setPrincipalResolver($replacement);

        self::assertSame($identity, $guard->user());
        self::assertSame($principal, $guard->principal());
    }

    /**
     * Allow the standard `Attempting` + `Failed` events that every failed
     * `JwtGuard::refresh()` call now dispatches (alongside the package-specific
     * `RefreshFailed` event). Tests that assert a specific `RefreshFailed`
     * reason call this helper first to permit the standard events without
     * constraining them.
     *
     * @return void
     */
    private function expectRefreshFailureEvents(): void
    {
        $this->events->shouldReceive('dispatch')
            ->with(\Mockery::type(Attempting::class));
        $this->events->shouldReceive('dispatch')
            ->with(\Mockery::type(Failed::class));
    }
}
