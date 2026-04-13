<?php

declare(strict_types = 1);

namespace Tests\Feature\Guards;

use Carbon\Carbon;
use Illuminate\Auth\Events\Attempting;
use Illuminate\Auth\Events\Authenticated;
use Illuminate\Auth\Events\Failed;
use Illuminate\Auth\Events\Login;
use Illuminate\Auth\Events\Validated;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Cache\ResolutionCache;
use SineMacula\Laravel\Authentication\Contracts\CanBeActive;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\PrincipalResolver;
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
use Tests\Unit\Stubs\StubModel;

/**
 * Feature tests for the refresh-token exchange path on
 * JwtGuard, including all RefreshFailed early-return
 * branches.
 *
 * Split out of the original JwtGuardTest so each class stays focused on a
 * single behavioural slice.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(JwtGuard::class)]
#[CoversClass(RefreshTokenExchange::class)]
#[CoversClass(IdentifierCoercion::class)]
final class JwtGuardRefreshTest extends JwtGuardTestCase
{
    /**
     * When the refresh token cannot be parsed, `refresh()` returns null and
     * fires `RefreshFailed` with reason `token_invalid`.
     *
     * @return void
     */
    public function testRefreshReturnsNullWhenTokenCannotBeParsed(): void
    {
        $guard = $this->makeGuard($this->makeRequest(null));

        $this->expectRefreshFailureEvents();
        $this->events->shouldReceive('dispatch')
            ->once()
            ->with(
                \Mockery::on(static fn (mixed $event): bool => $event instanceof RefreshFailed
                    && $event->reason === RefreshFailureReason::TOKEN_INVALID),
            );

        self::assertNull($guard->refresh('not-a-jwt'));
    }

    /**
     * A refresh token without a `did` claim returns null and fires
     * `RefreshFailed` with reason `token_invalid`.
     *
     * @return void
     */
    public function testRefreshReturnsNullWhenDeviceIdMissingFromClaims(): void
    {
        $guard = $this->makeGuard($this->makeRequest(null));

        $token = $this->encodeRefreshToken(['jti' => 'some-rotation-id']);

        $this->expectRefreshFailureEvents();
        $this->events->shouldReceive('dispatch')
            ->once()
            ->with(
                \Mockery::on(static fn (mixed $event): bool => $event instanceof RefreshFailed
                    && $event->reason === RefreshFailureReason::TOKEN_INVALID),
            );

        self::assertNull($guard->refresh($token));
    }

    /**
     * When the device lookup returns null, `refresh()` returns null and fires
     * `RefreshFailed` with reason `device_unknown`.
     *
     * @return void
     */
    public function testRefreshReturnsNullWhenDeviceLookupFails(): void
    {
        $guard = $this->makeGuard($this->makeRequest(null));

        $token = $this->encodeRefreshToken([
            'did' => '01HZZZZZZZZZZZZZZZZZZZZZZZ',
            'jti' => 'rotation-id',
        ]);

        $this->expectRefreshFailureEvents();
        $this->events->shouldReceive('dispatch')
            ->once()
            ->with(
                \Mockery::on(static fn (mixed $event): bool => $event instanceof RefreshFailed
                    && $event->reason   === RefreshFailureReason::DEVICE_UNKNOWN
                    && $event->deviceId === '01HZZZZZZZZZZZZZZZZZZZZZZZ'),
            );

        self::assertNull($guard->refresh($token));
    }

    /**
     * When the device's stored refresh-key digest does not match the hash of
     * the token's `jti` claim, `refresh()` returns null and fires
     * `RefreshFailed` with reason `rotation_mismatch`.
     *
     * @return void
     */
    public function testRefreshReturnsNullWhenRefreshKeyDoesNotMatch(): void
    {
        $device = new StubDevice;
        $device->forceFill(['refresh_key' => RefreshTokenHasher::hash('stored-rotation-id')])->save();

        $guard = $this->makeGuard($this->makeRequest(null));

        $token = $this->encodeRefreshToken([
            'did' => $device->id,
            'jti' => 'tampered-rotation-id',
        ]);

        $this->expectRefreshFailureEvents();
        $this->events->shouldReceive('dispatch')
            ->once()
            ->with(
                \Mockery::on(static fn (mixed $event): bool => $event instanceof RefreshFailed
                    && $event->reason   === RefreshFailureReason::ROTATION_MISMATCH
                    && $event->deviceId === $device->id),
            );

        self::assertNull($guard->refresh($token));
    }

    /**
     * When `device->authenticatable` is not an Identity, `refresh()` returns
     * null and fires `RefreshFailed` with reason `authenticatable_missing`.
     *
     * @return void
     */
    public function testRefreshReturnsNullWhenAuthenticatableRelationIsNotIdentity(): void
    {
        $plainRotationId = 'stored-rotation-id';

        $device = new StubDevice;
        $device->forceFill(['refresh_key' => RefreshTokenHasher::hash($plainRotationId)])->save();

        $nonIdentity = new StubModel;
        $device->setRelation('authenticatable', $nonIdentity);

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
                    && $event->reason === RefreshFailureReason::AUTHENTICATABLE_MISSING),
            );

        self::assertNull($guard->refresh($token));
    }

    /**
     * When the bound identity reports `isActive() === false`, refresh fails
     * with `identity_inactive` and dispatches `RefreshFailed`.
     *
     * @return void
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
     * `null`, refresh fails with `principal_unresolved` instead of
     * downgrading to the default principal.
     *
     * @return void
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
                    && $event->reason   === RefreshFailureReason::PRINCIPAL_UNRESOLVED
                    && $event->deviceId === $device->id),
            );

        self::assertNull($guard->refresh($token));
    }

    /**
     * When a refresh token carries a `pid` hint but the resolver returns a
     * different principal, refresh fails with `principal_unresolved`.
     *
     * @return void
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
                    && $event->reason   === RefreshFailureReason::PRINCIPAL_UNRESOLVED
                    && $event->deviceId === $device->id),
            );

        self::assertNull($guard->refresh($token));
    }

    /**
     * A refresh token whose `jti` is present but empty is malformed and
     * yields `token_invalid` while preserving the parseable device id for
     * attribution.
     *
     * @return void
     */
    public function testRefreshReturnsNullWhenRotationIdClaimIsEmptyString(): void
    {
        $guard = $this->makeGuard($this->makeRequest(null));

        $token = $this->encodeRefreshToken([
            'did' => 'device-empty-jti',
            'jti' => '',
        ]);

        $this->expectRefreshFailureEvents();
        $this->events->shouldReceive('dispatch')
            ->once()
            ->with(
                \Mockery::on(static fn (mixed $event): bool => $event instanceof RefreshFailed
                    && $event->reason   === RefreshFailureReason::TOKEN_INVALID
                    && $event->deviceId === 'device-empty-jti'),
            );

        self::assertNull($guard->refresh($token));
    }

    /**
     * A refresh token whose `jti` is not a string is malformed and yields
     * `token_invalid` while preserving the parseable device id for
     * attribution.
     *
     * @return void
     */
    public function testRefreshReturnsNullWhenRotationIdClaimIsNotString(): void
    {
        $guard = $this->makeGuard($this->makeRequest(null));

        $token = $this->encodeRefreshToken([
            'did' => 'device-non-string-jti',
            'jti' => 12345,
        ]);

        $this->expectRefreshFailureEvents();
        $this->events->shouldReceive('dispatch')
            ->once()
            ->with(
                \Mockery::on(static fn (mixed $event): bool => $event instanceof RefreshFailed
                    && $event->reason   === RefreshFailureReason::TOKEN_INVALID
                    && $event->deviceId === 'device-non-string-jti'),
            );

        self::assertNull($guard->refresh($token));
    }

    /**
     * Fail-closed: a hinted principal whose identifier stringifies to `null`
     * must be rejected rather than rebound into a transient principal.
     *
     * @return void
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
                    && $event->reason   === RefreshFailureReason::PRINCIPAL_UNRESOLVED
                    && $event->deviceId === $device->id),
            );

        self::assertNull($guard->refresh($token));
    }

    /**
     * When the hinted principal reports `isActive() === false`, refresh fails
     * with `principal_inactive` and dispatches `RefreshFailed`.
     *
     * @return void
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
     * A refresh attempt against a device whose `revoked_at` column is set
     * returns null and fires `RefreshFailed` with reason `device_revoked`,
     * regardless of whether the rotation id verifies against the stored
     * digest.
     *
     * @return void
     */
    public function testRefreshReturnsNullWhenDeviceHasBeenRevoked(): void
    {
        $plainRotationId = 'stored-rotation-id';

        $device = new StubDevice;
        $device->forceFill([
            'refresh_key' => RefreshTokenHasher::hash($plainRotationId),
            'revoked_at'  => Carbon::now(),
        ])->save();

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
                    && $event->reason === RefreshFailureReason::DEVICE_REVOKED),
            );

        self::assertNull($guard->refresh($token));
    }

    /**
     * Reuse-detection regression test.
     *
     * When the refresh token verifies against the device's in-memory digest
     * but the atomic CAS affects zero rows - meaning the database row's digest
     * has been changed since the read, typically by a concurrent refresh or a
     * stolen-token replay - the exchange service revokes the entire device and
     * dispatches `RefreshFailed` with reason `rotation_reuse`. We simulate the
     * race by mutating the sqlite row directly between the setRelation() setup
     * and the refresh() call.
     *
     * @return void
     */
    public function testRefreshRevokesDeviceOnRotationReuseWhenCasAffectsZeroRows(): void
    {
        $plainRotationId = 'stored-rotation-id';
        $staleDigest     = RefreshTokenHasher::hash($plainRotationId);

        $identity = new StubIdentity;
        $identity->forceFill(['id' => 13]);

        $device = new StubDevice;
        $device->forceFill([
            'authenticatable_type' => StubIdentity::class,
            'authenticatable_id'   => '13',
            'refresh_key'          => $staleDigest,
        ])->save();

        $device->setRelation('authenticatable', $identity);

        $this->swapDeviceModelToInMemoryInstance($device);

        // Simulate a concurrent rotation: mutate the sqlite row's refresh_key
        // directly so the in-memory digest (which `loadDeviceForRefresh` still
        // verifies against) is stale from the CAS's point of view. The CAS will
        // then affect zero rows and the exchange must detect the reuse.
        StubDevice::query()
            ->whereKey($device->id)
            ->update(['refresh_key' => RefreshTokenHasher::hash('concurrent-rotation')]);

        $guard = $this->makeGuard($this->makeRequest(null));

        $principal = \Mockery::mock(Principal::class);
        $principal->shouldReceive('getPrincipalIdentifier')->andReturn('p-13');
        $principal->shouldReceive('isActive')->andReturnTrue();

        $this->resolver->shouldReceive('resolve')
            ->once()
            ->with($identity)
            ->andReturn($principal);

        $token = $this->encodeRefreshToken([
            'did' => $device->id,
            'jti' => $plainRotationId,
        ]);

        $this->expectRefreshFailureEvents();
        $this->events->shouldReceive('dispatch')
            ->once()
            ->with(
                \Mockery::on(static fn (mixed $event): bool => $event instanceof RefreshFailed
                    && $event->reason   === RefreshFailureReason::ROTATION_REUSE
                    && $event->deviceId === $device->id),
            );

        self::assertNull($guard->refresh($token));

        // The device row has been revoked: revoked_at is set and the
        // refresh-key column is cleared, so subsequent refresh attempts produce
        // REASON_DEVICE_REVOKED.
        $fresh = StubDevice::query()->findOrFail($device->id);
        self::assertNotNull($fresh->revoked_at);
        self::assertNull($fresh->refresh_key);
    }

    /**
     * A successful refresh preserves the original active principal by carrying
     * the same `pid` through the rotated refresh token and newly issued access
     * token.
     *
     * @return void
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
     * Once a refresh succeeds and rotates the device digest, replaying the
     * exact old token should fail as `rotation_mismatch` without revoking the
     * current device family. `rotation_reuse` is reserved for the CAS-lost
     * branch where the token verified before losing a concurrent race.
     *
     * @return void
     */
    public function testRefreshRejectsOldRefreshTokenAfterSuccessfulRotationWithoutRevokingDevice(): void
    {
        $plainRotationId = 'stored-rotation-id';

        $identity = new StubIdentity;
        $identity->forceFill(['id' => 18]);

        $device = new StubDevice;
        $device->forceFill([
            'authenticatable_type' => StubIdentity::class,
            'authenticatable_id'   => '18',
            'refresh_key'          => RefreshTokenHasher::hash($plainRotationId),
        ])->save();

        $device->setRelation('authenticatable', $identity);

        $this->swapDeviceModelToInMemoryInstance($device);

        $firstGuard = $this->makeGuard($this->makeRequest(null));

        $principal = \Mockery::mock(Principal::class);
        $principal->shouldReceive('getPrincipalIdentifier')
            ->times(3)
            ->andReturn('p-18');
        $principal->shouldReceive('isActive')
            ->once()
            ->andReturnTrue();

        $this->resolver->shouldReceive('resolve')
            ->once()
            ->with($identity, 'p-18')
            ->andReturn($principal);

        $oldToken = $this->encodeRefreshToken([
            'pid' => 'p-18',
            'did' => $device->id,
            'jti' => $plainRotationId,
        ]);

        $this->events->shouldReceive('dispatch')
            ->times(7)
            ->andReturnNull();

        self::assertInstanceOf(RefreshResult::class, $firstGuard->refresh($oldToken));

        $secondGuard = $this->makeGuard($this->makeRequest(null));

        $this->expectRefreshFailureEvents();
        $this->events->shouldReceive('dispatch')
            ->once()
            ->with(
                \Mockery::on(static fn (mixed $event): bool => $event instanceof RefreshFailed
                    && $event->reason   === RefreshFailureReason::ROTATION_MISMATCH
                    && $event->deviceId === $device->id),
            );

        self::assertNull($secondGuard->refresh($oldToken));

        $fresh = StubDevice::query()->findOrFail($device->id);

        self::assertNull($fresh->revoked_at);
        self::assertNotNull(
            $fresh->refresh_key,
            'The rotated digest should remain in place for the current device family.',
        );
    }

    /**
     * After a successful refresh the guard has the identity, principal, and
     * device bound for the rest of the request.
     *
     * @return void
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
     * Allow the standard `Attempting` + `Failed` events that every failed
     * `JwtGuard::refresh()` call now dispatches (alongside the
     * package-specific `RefreshFailed` event). Tests that assert a specific
     * `RefreshFailed` reason call this helper first to permit the standard
     * events without constraining them.
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
