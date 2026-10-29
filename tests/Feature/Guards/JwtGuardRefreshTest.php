<?php

declare(strict_types = 1);

namespace Tests\Feature\Guards;

use Carbon\Carbon;
use Illuminate\Auth\Events\Attempting;
use Illuminate\Auth\Events\Failed;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Contracts\CanBeActive;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\DeviceRevoked;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\Refreshed;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Jwt\Enums\Claims;
use SineMacula\Laravel\Authentication\Jwt\Enums\TokenType;
use SineMacula\Laravel\Authentication\Jwt\IdentifierCoercion;
use SineMacula\Laravel\Authentication\Jwt\RefreshResult;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenExchange;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenHasher;
use Tests\Concerns\InteractsWithDevices;
use Tests\Unit\Stubs\StubDevice;
use Tests\Unit\Stubs\StubIdentity;

/**
 * Feature tests for the token-level and device-level validation paths within
 * JwtGuard's refresh-token exchange, including rotation integrity checks.
 *
 * Covers token parsing failures, device lookup, replay detection and the grace
 * window, and device revocation. Identity and principal resolution tests live
 * in JwtGuardRefreshResolutionTest.
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
    use InteractsWithDevices;

    /**
     * When the refresh token cannot be parsed, `refresh()` returns null and
     * fires `AuthenticationFailed` with reason `token_invalid`.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Random\RandomException
     */
    public function testRefreshReturnsNullWhenTokenCannotBeParsed(): void
    {
        $guard = $this->makeGuard($this->makeRequest(null));

        $this->expectRefreshFailureEvents();
        $this->events->shouldReceive('dispatch')
            ->once()
            ->with(
                \Mockery::on(static fn (mixed $event): bool => $event instanceof AuthenticationFailed
                    && $event->reason === FailureReason::TOKEN_INVALID),
            );

        self::assertNull($guard->refresh('not-a-jwt'));
    }

    /**
     * A refresh token without a `did` claim returns null and fires
     * `AuthenticationFailed` with reason `token_invalid`.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Random\RandomException
     */
    public function testRefreshReturnsNullWhenDeviceIdMissingFromClaims(): void
    {
        $guard = $this->makeGuard($this->makeRequest(null));

        $token = $this->encodeRefreshToken(['jti' => 'some-rotation-id']);

        $this->expectRefreshFailureEvents();
        $this->events->shouldReceive('dispatch')
            ->once()
            ->with(
                \Mockery::on(static fn (mixed $event): bool => $event instanceof AuthenticationFailed
                    && $event->reason === FailureReason::TOKEN_INVALID),
            );

        self::assertNull($guard->refresh($token));
    }

    /**
     * When the device lookup returns null, `refresh()` returns null and fires
     * `AuthenticationFailed` with reason `device_unknown`.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Random\RandomException
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
                \Mockery::on(static fn (mixed $event): bool => $event instanceof AuthenticationFailed
                    && $event->reason            === FailureReason::DEVICE_UNKNOWN
                    && $event->context->deviceId === '01HZZZZZZZZZZZZZZZZZZZZZZZ'),
            );

        self::assertNull($guard->refresh($token));
    }

    /**
     * A refresh token for a live device whose rotation id the device never held
     * as current or previous is a replay: `refresh()` returns null, revokes the
     * device, and dispatches `DeviceRevoked`, `AuthenticationFailed` with
     * reason `rotation_reuse`, and Laravel's `Failed`.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Random\RandomException
     */
    public function testRefreshRevokesTheDeviceForARotationIdItDoesNotHold(): void
    {
        $device = new StubDevice;
        $device->forceFill([...self::liveSession(self::GUARD_NAME), 'refresh_key' => RefreshTokenHasher::hash('stored-rotation-id')])->save();

        $guard = $this->makeGuard($this->makeRequest(null));

        $token = $this->encodeRefreshToken([
            'did' => $device->id,
            'jti' => 'tampered-rotation-id',
        ]);

        $dispatched = $this->recordDispatchedEvents();

        self::assertNull($guard->refresh($token));

        $events = $dispatched->getArrayCopy();

        $classes = array_map(static fn (object $event): string => $event::class, $events);

        self::assertSame([Attempting::class, DeviceRevoked::class, Failed::class, AuthenticationFailed::class], $classes);
        self::assertInstanceOf(AuthenticationFailed::class, $events[3]);
        self::assertSame(FailureReason::ROTATION_REUSE, $events[3]->reason);

        $fresh = StubDevice::query()->findOrFail($device->id);

        self::assertNotNull($fresh->revoked_at);
        self::assertSame('rotation_reuse', $fresh->revoked_reason);
        self::assertNull($fresh->refresh_key);
    }

    /**
     * A refresh token whose `jti` is present but empty lacks a required claim,
     * so it fails to parse and yields `token_invalid`; a token that does not
     * parse carries no device id for attribution.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Random\RandomException
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
                \Mockery::on(static fn (mixed $event): bool => $event instanceof AuthenticationFailed
                    && $event->reason            === FailureReason::TOKEN_INVALID
                    && $event->context->deviceId === null),
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
     * @throws \Random\RandomException
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
                \Mockery::on(static fn (mixed $event): bool => $event instanceof AuthenticationFailed
                    && $event->reason            === FailureReason::TOKEN_INVALID
                    && $event->context->deviceId === 'device-non-string-jti'),
            );

        self::assertNull($guard->refresh($token));
    }

    /**
     * A refresh attempt against a device whose `revoked_at` column is set
     * returns null and fires `AuthenticationFailed` with reason
     * `device_revoked`, regardless of whether the rotation id verifies against
     * the stored digest.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Random\RandomException
     */
    public function testRefreshReturnsNullWhenDeviceHasBeenRevoked(): void
    {
        $plainRotationId = 'stored-rotation-id';

        $device = new StubDevice;
        $device->forceFill([
            ...self::liveSession(self::GUARD_NAME),
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
                \Mockery::on(static fn (mixed $event): bool => $event instanceof AuthenticationFailed
                    && $event->reason === FailureReason::DEVICE_REVOKED),
            );

        self::assertNull($guard->refresh($token));
    }

    /**
     * A digest replaced between the exchange's read and its swap by something
     * other than a rotation (no previous digest records the presented id) is
     * judged again from the row as it now is: the presented id is neither
     * current nor previous, so it is a replay and the device is revoked.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Random\RandomException
     */
    public function testRefreshRevokesTheDeviceWhenItsDigestIsReplacedBeforeTheSwap(): void
    {
        $plainRotationId = 'stored-rotation-id';

        $identity = new StubIdentity;
        $identity->forceFill(['id' => 13]);

        $device = new StubDevice;
        $device->forceFill([
            ...self::liveSession(self::GUARD_NAME),
            'authenticatable_type' => StubIdentity::class,
            'authenticatable_id'   => '13',
            'refresh_key'          => RefreshTokenHasher::hash($plainRotationId),
        ])->save();

        $this->expectOwnerReload($device, $identity);

        $ran = false;

        DB::connection()->beforeExecuting(static function (string $query) use (&$ran, $device): void {
            if ($ran || !str_contains($query, 'refresh_rotated_at')) {
                return;
            }

            $ran = true;

            DB::table('stub_devices')->where('id', $device->id)->update(['refresh_key' => RefreshTokenHasher::hash('replaced-elsewhere')]);
        });

        $guard = $this->makeGuard($this->makeRequest(null));

        $principal = \Mockery::mock(Principal::class, CanBeActive::class);
        $principal->shouldReceive('getTenant')->andReturnNull();
        $principal->shouldReceive('getPrincipalIdentifier')->andReturn('p-13');
        $principal->shouldReceive('isActive')->andReturnTrue();

        $this->resolver->shouldReceive('resolve')
            ->once()
            ->with($identity)
            ->andReturn($principal);

        $device->forceFill(self::recordedPrincipal($principal))->save();

        $token = $this->encodeRefreshToken([
            'did' => $device->id,
            'jti' => $plainRotationId,
        ]);

        $dispatched = $this->recordDispatchedEvents();

        self::assertNull($guard->refresh($token));
        self::assertContains(DeviceRevoked::class, array_map(static fn (object $event): string => $event::class, $dispatched->getArrayCopy()));

        $fresh = StubDevice::query()->findOrFail($device->id);

        self::assertSame('rotation_reuse', $fresh->revoked_reason);
        self::assertNull($fresh->refresh_key);
    }

    /**
     * The refresh token a successful refresh replaced still gets the session's
     * current credential inside the grace window, through the guard, with the
     * same events as any refresh; once the window has passed it is a replay and
     * revokes the device.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Random\RandomException
     */
    public function testReplacedRefreshTokenIsHonouredInsideTheGraceWindowOnly(): void
    {
        $plainRotationId = 'stored-rotation-id';

        $identity = new StubIdentity;
        $identity->forceFill(['id' => 18]);

        $device = new StubDevice;
        $device->forceFill([
            ...self::liveSession(self::GUARD_NAME),
            'authenticatable_type' => StubIdentity::class,
            'authenticatable_id'   => '18',
            'refresh_key'          => RefreshTokenHasher::hash($plainRotationId),
        ])->save();

        $this->provider->shouldReceive('retrieveById')
            ->twice()
            ->with('18')
            ->andReturn($identity);

        $principal = \Mockery::mock(Principal::class, CanBeActive::class);
        $principal->shouldReceive('getTenant')->andReturnNull();
        $principal->shouldReceive('getPrincipalIdentifier')->andReturn('p-18');
        $principal->shouldReceive('isActive')->andReturnTrue();

        $this->resolver->shouldReceive('resolve')
            ->twice()
            ->with($identity, 'p-18')
            ->andReturn($principal);

        $device->forceFill(self::recordedPrincipal($principal))->save();

        $oldToken = $this->encodeRefreshToken([
            'pid' => 'p-18',
            'did' => $device->id,
            'jti' => $plainRotationId,
        ]);

        $dispatched = $this->recordDispatchedEvents();

        $rotated = $this->makeGuard($this->makeRequest(null))->refresh($oldToken);

        self::assertInstanceOf(RefreshResult::class, $rotated);

        Carbon::setTestNow($this->now->copy()->addSeconds(29));

        $retried = $this->makeGuard($this->makeRequest(null))->refresh($oldToken);

        self::assertInstanceOf(RefreshResult::class, $retried);
        self::assertSame(
            $this->tokens->parse($rotated->refreshToken, TokenType::REFRESH)[Claims::JWT_ID->value] ?? null,
            $this->tokens->parse($retried->refreshToken, TokenType::REFRESH)[Claims::JWT_ID->value] ?? null,
        );
        self::assertCount(2, array_filter($dispatched->getArrayCopy(), static fn (object $event): bool => $event instanceof Refreshed));

        Carbon::setTestNow($this->now->copy()->addSeconds(30));

        self::assertNull($this->makeGuard($this->makeRequest(null))->refresh($oldToken));
        self::assertSame('rotation_reuse', StubDevice::query()->findOrFail($device->id)->revoked_reason);
    }

    /**
     * A failed refresh dispatches the standard Laravel `Failed` event in
     * addition to the package-specific `AuthenticationFailed`. Mutation guard:
     * pins the `$this->fireFailedEvent(null, [])` call in `refresh()`.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Random\RandomException
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
     * `AuthenticationFailed` event). Tests that assert a specific
     * `AuthenticationFailed` reason call this helper first to permit the
     * standard events without constraining them.
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

    /**
     * Record every event the guard and its exchange dispatch.
     *
     * @return \ArrayObject<int, object>
     */
    private function recordDispatchedEvents(): \ArrayObject
    {
        /** @var \ArrayObject<int, object> $dispatched */
        $dispatched = new \ArrayObject;

        $this->events->shouldReceive('dispatch')
            ->andReturnUsing(static function (object $event) use ($dispatched): void {
                $dispatched->append($event);
            });

        return $dispatched;
    }
}
