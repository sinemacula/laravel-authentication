<?php

declare(strict_types = 1);

namespace Tests\Feature\Guards;

use Carbon\Carbon;
use Illuminate\Auth\Events\Attempting;
use Illuminate\Auth\Events\Failed;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Events\Enums\RefreshFailureReason;
use SineMacula\Laravel\Authentication\Events\RefreshFailed;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Jwt\IdentifierCoercion;
use SineMacula\Laravel\Authentication\Jwt\RefreshResult;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenExchange;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenHasher;
use Tests\Unit\Stubs\StubDevice;
use Tests\Unit\Stubs\StubIdentity;
use Tests\Unit\Stubs\StubModel;

/**
 * Feature tests for the token-level and device-level validation paths within
 * JwtGuard's refresh-token exchange, including rotation integrity checks.
 *
 * Covers token parsing failures, device lookup, rotation-key verification,
 * device revocation, and rotation-reuse detection. Identity and principal
 * resolution tests live in JwtGuardRefreshResolutionTest.
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
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
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
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
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
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
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
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
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
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
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
     * A refresh token whose `jti` is present but empty is malformed and yields
     * `token_invalid` while preserving the parseable device id for attribution.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
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
     * `token_invalid` while preserving the parseable device id for attribution.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
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
     * A refresh attempt against a device whose `revoked_at` column is set
     * returns null and fires `RefreshFailed` with reason `device_revoked`,
     * regardless of whether the rotation id verifies against the stored digest.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
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
     * When the refresh token verifies against the device's in-memory digest but
     * the atomic CAS affects zero rows - meaning the database row's digest has
     * been changed since the read, typically by a concurrent refresh or a
     * stolen-token replay - the exchange service revokes the entire device and
     * dispatches `RefreshFailed` with reason `rotation_reuse`. We simulate the
     * race by mutating the sqlite row directly between the setRelation() setup
     * and the refresh() call.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
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
     * Once a refresh succeeds and rotates the device digest, replaying the
     * exact old token should fail as `rotation_mismatch` without revoking the
     * current device family. `rotation_reuse` is reserved for the CAS-lost
     * branch where the token verified before losing a concurrent race.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
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
     * A failed refresh dispatches the standard Laravel `Failed` event in
     * addition to the package-specific `RefreshFailed`. Mutation guard: pins
     * the `$this->fireFailedEvent(null, [])` call in `refresh()`.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testRefreshDispatchesFailedEventOnFailure(): void
    {
        $guard = $this->makeGuard($this->makeRequest(null));

        $failedEvent = null;

        $this->events->shouldReceive('dispatch')
            ->andReturnUsing(static function (object $event) use (&$failedEvent): void {
                if (!$event instanceof Failed) {
                    return;
                }

                $failedEvent = $event;
            });

        $guard->refresh('not-a-jwt');

        self::assertInstanceOf(Failed::class, $failedEvent);
        self::assertSame(self::GUARD_NAME, $failedEvent->guard);
        self::assertNull($failedEvent->user);
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
