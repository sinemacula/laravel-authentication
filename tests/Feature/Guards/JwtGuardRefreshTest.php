<?php

declare(strict_types = 1);

namespace Tests\Feature\Guards;

use Carbon\Carbon;
use Illuminate\Auth\Events\Attempting;
use Illuminate\Auth\Events\Failed;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Contracts\CanBeActive;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Events\Enums\RefreshFailureReason;
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
 * Unit tests for the refresh-token exchange path on `JwtGuard`, including all
 * `RefreshFailed` early-return branches.
 *
 * Split out of the original JwtGuardTest so each class stays focused on a
 * single behavioural slice.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
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
                    && $event->reason === RefreshFailureReason::DEVICE_UNKNOWN),
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
                    && $event->reason === RefreshFailureReason::ROTATION_MISMATCH),
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
     * When the principal resolver returns `null`, refresh fails with
     * `principal_unresolved` and dispatches `RefreshFailed`.
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
            ->with($identity)
            ->andReturnNull();

        $token = $this->encodeRefreshToken([
            'did' => $device->id,
            'jti' => $plainRotationId,
        ]);

        $this->expectRefreshFailureEvents();
        $this->events->shouldReceive('dispatch')
            ->once()
            ->with(
                \Mockery::on(static fn (mixed $event): bool => $event instanceof RefreshFailed
                    && $event->reason === RefreshFailureReason::PRINCIPAL_UNRESOLVED),
            );

        self::assertNull($guard->refresh($token));
    }

    /**
     * When the resolved principal reports `isActive() === false`, refresh fails
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
        $principal->shouldReceive('isActive')->once()->andReturnFalse();

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
                    && $event->reason === RefreshFailureReason::ROTATION_REUSE),
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
     * A successful refresh returns a `RefreshResult` carrying a new access
     * token and a new rotated refresh token, rotates the device's stored
     * digest, and dispatches the `Refreshed` event carrying identity +
     * principal + device.
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
            ->with($identity)
            ->andReturn($principal);

        $token = $this->encodeRefreshToken([
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
