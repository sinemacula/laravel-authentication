<?php

declare(strict_types = 1);

namespace Tests\Feature\Guards;

use Illuminate\Auth\Events\Attempting;
use Illuminate\Auth\Events\Authenticated;
use Illuminate\Auth\Events\Failed;
use Illuminate\Auth\Events\Login;
use Illuminate\Auth\Events\Validated;
use Illuminate\Contracts\Events\Dispatcher;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\CanBeActive;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\PrincipalResolver;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\DeviceAuthenticated;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\PrincipalAssigned;
use SineMacula\Laravel\Authentication\Events\Refreshed;
use SineMacula\Laravel\Authentication\Events\SignedIn;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Jwt\Enums\Claims;
use SineMacula\Laravel\Authentication\Jwt\Enums\TokenType;
use SineMacula\Laravel\Authentication\Jwt\RefreshResult;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenExchange;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenHasher;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use Tests\Concerns\InteractsWithDevices;
use Tests\Unit\Stubs\StubAuthenticatableModel;
use Tests\Unit\Stubs\StubDevice;
use Tests\Unit\Stubs\StubIdentity;
use Tests\Unit\Stubs\StubPrincipal;

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
    use InteractsWithDevices;

    /**
     * When the bound identity reports `isActive() === false`, refresh fails
     * with `identity_inactive` and dispatches `AuthenticationFailed`.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Random\RandomException
     */
    public function testRefreshReturnsNullWhenIdentityIsInactive(): void
    {
        $plainRotationId = 'stored-rotation-id';

        $identity = new class extends StubIdentity implements CanBeActive {
            /**
             * Report the identity as deactivated.
             *
             * @return bool
             */
            #[\Override]
            public function isActive(): bool
            {
                return false;
            }
        };
        $identity->forceFill(['id' => 21]);

        $device = new StubDevice;
        $device->forceFill([
            ...self::liveSession(self::GUARD_NAME),
            'authenticatable_type' => $identity->getMorphClass(),
            'authenticatable_id'   => '21',
            'refresh_key'          => RefreshTokenHasher::hash($plainRotationId),
        ])->save();
        $this->expectOwnerReload($device, $identity);

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
                    && $event->reason === FailureReason::IDENTITY_INACTIVE),
            );

        self::assertNull($guard->refresh($token));
    }

    /**
     * Provider answers for the owner key `9` of a `StubIdentity` device that
     * are not that owner.
     *
     * @return iterable<string, array{0: \Closure(): mixed}>
     */
    public static function provideAnswersThatAreNotTheDeviceOwner(): iterable
    {
        yield from [
            'no identity through the provider'           => [static fn (): null => null],
            'an authenticatable that is not an identity' => [static fn (): StubAuthenticatableModel => (new StubAuthenticatableModel)->forceFill(['id' => 9])],
            'another identity model with the owner key'  => [static fn (): StubPrincipal => (new StubPrincipal)->forceFill(['id' => 9])],
            'the owner model with another key'           => [static fn (): StubIdentity => (new StubIdentity)->forceFill(['id' => 10])],
            'an identity that is not an eloquent model'  => [static fn (): Identity => \Mockery::mock(Identity::class)],
        ];
    }

    /**
     * Refresh reloads the device owner through the guard's provider by the
     * owner key on the device row and accepts only that exact owner; any other
     * answer fails with `identity_unknown` before a principal is resolved.
     *
     * @param  \Closure(): mixed  $answer
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Random\RandomException
     */
    #[DataProvider('provideAnswersThatAreNotTheDeviceOwner')]
    public function testRefreshRejectsAProviderAnswerThatIsNotTheDeviceOwner(\Closure $answer): void
    {
        $plainRotationId = 'stored-rotation-id';

        $device = new StubDevice;
        $device->forceFill([
            ...self::liveSession(self::GUARD_NAME),
            'authenticatable_type' => StubIdentity::class,
            'authenticatable_id'   => '9',
            'refresh_key'          => RefreshTokenHasher::hash($plainRotationId),
        ])->save();
        $this->expectOwnerReload($device, $answer());

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
                    && $event->reason            === FailureReason::IDENTITY_UNKNOWN
                    && $event->context->deviceId === $device->id),
            );

        self::assertNull($guard->refresh($token));
    }

    /**
     * A device row with no owner key has no owner to reload: refresh fails with
     * `identity_unknown` without asking the provider.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Random\RandomException
     */
    public function testRefreshRejectsADeviceWithoutAnOwnerKeyWithoutAskingTheProvider(): void
    {
        $plainRotationId = 'stored-rotation-id';

        $device = new StubDevice;
        $device->forceFill([
            ...self::liveSession(self::GUARD_NAME),
            'authenticatable_type' => StubIdentity::class,
            'refresh_key'          => RefreshTokenHasher::hash($plainRotationId),
        ])->save();

        $this->swapDeviceModelToInMemoryInstance($device);

        $guard = $this->makeGuard($this->makeRequest(null));

        $token = $this->encodeRefreshToken([
            'did' => $device->id,
            'jti' => $plainRotationId,
        ]);

        $this->provider->shouldNotReceive('retrieveById');
        $this->resolver->shouldNotReceive('resolve');

        $this->expectRefreshFailureEvents();
        $this->events->shouldReceive('dispatch')
            ->once()
            ->with(
                \Mockery::on(static fn (mixed $event): bool => $event instanceof AuthenticationFailed
                    && $event->reason === FailureReason::IDENTITY_UNKNOWN),
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
     * @throws \Random\RandomException
     */
    public function testRefreshReturnsNullWhenPrincipalIsUnresolved(): void
    {
        $plainRotationId = 'stored-rotation-id';

        $identity = new StubIdentity;
        $identity->forceFill(['id' => 9]);

        $device = new StubDevice;
        $device->forceFill([
            ...self::liveSession(self::GUARD_NAME),
            'authenticatable_type' => StubIdentity::class,
            'authenticatable_id'   => '9',
            'refresh_key'          => RefreshTokenHasher::hash($plainRotationId),
        ])->save();
        $this->expectOwnerReload($device, $identity);

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
                \Mockery::on(static fn (mixed $event): bool => $event instanceof AuthenticationFailed
                    && $event->reason            === FailureReason::PRINCIPAL_MISMATCH
                    && $event->context->deviceId === $device->id),
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
     * @throws \Random\RandomException
     */
    public function testRefreshReturnsNullWhenPidHintDoesNotMatchResolvedPrincipal(): void
    {
        $plainRotationId = 'stored-rotation-id';

        $identity = new StubIdentity;
        $identity->forceFill(['id' => 10]);

        $device = new StubDevice;
        $device->forceFill([
            ...self::liveSession(self::GUARD_NAME),
            'authenticatable_type' => StubIdentity::class,
            'authenticatable_id'   => '10',
            'refresh_key'          => RefreshTokenHasher::hash($plainRotationId),
        ])->save();
        $this->expectOwnerReload($device, $identity);

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
                \Mockery::on(static fn (mixed $event): bool => $event instanceof AuthenticationFailed
                    && $event->reason            === FailureReason::PRINCIPAL_MISMATCH
                    && $event->context->deviceId === $device->id),
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
     * @throws \Random\RandomException
     */
    public function testRefreshReturnsNullWhenResolvedPrincipalIdentifierIsNull(): void
    {
        $plainRotationId = 'stored-rotation-id';

        $identity = new StubIdentity;
        $identity->forceFill(['id' => 15]);

        $device = new StubDevice;
        $device->forceFill([
            ...self::liveSession(self::GUARD_NAME),
            'authenticatable_type' => StubIdentity::class,
            'authenticatable_id'   => '15',
            'refresh_key'          => RefreshTokenHasher::hash($plainRotationId),
        ])->save();
        $this->expectOwnerReload($device, $identity);

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
                \Mockery::on(static fn (mixed $event): bool => $event instanceof AuthenticationFailed
                    && $event->reason            === FailureReason::PRINCIPAL_MISMATCH
                    && $event->context->deviceId === $device->id),
            );

        self::assertNull($guard->refresh($token));
    }

    /**
     * When the hinted principal reports `isActive() === false`, refresh fails
     * with `principal_inactive` and dispatches `AuthenticationFailed`.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Random\RandomException
     */
    public function testRefreshReturnsNullWhenPrincipalIsInactive(): void
    {
        $plainRotationId = 'stored-rotation-id';

        $identity = new StubIdentity;
        $identity->forceFill(['id' => 11]);

        $device = new StubDevice;
        $device->forceFill([
            ...self::liveSession(self::GUARD_NAME),
            'authenticatable_type' => StubIdentity::class,
            'authenticatable_id'   => '11',
            'refresh_key'          => RefreshTokenHasher::hash($plainRotationId),
        ])->save();
        $this->expectOwnerReload($device, $identity);

        $this->swapDeviceModelToInMemoryInstance($device);

        $guard = $this->makeGuard($this->makeRequest(null));

        $principal = \Mockery::mock(Principal::class, CanBeActive::class);
        $principal->shouldReceive('getPrincipalIdentifier')->andReturn('p-11');
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
                \Mockery::on(static fn (mixed $event): bool => $event instanceof AuthenticationFailed
                    && $event->reason === FailureReason::PRINCIPAL_INACTIVE),
            );

        self::assertNull($guard->refresh($token));
    }

    /**
     * Fail-closed: when the resolver returns `null` for a hinted `pid` during
     * refresh, the hint check must fail so the exchange rejects the token.
     * Mutation guard: pins the null-safe principal read in
     * `RefreshTokenExchange::resolveRefreshPrincipal()`.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Random\RandomException
     */
    public function testRefreshRejectsTokenWhenNullPrincipalResolvesForPidHint(): void
    {
        $plainRotationId = 'stored-rotation-id';

        $identity = new StubIdentity;
        $identity->forceFill(['id' => 25]);

        $device = new StubDevice;
        $device->forceFill([
            ...self::liveSession(self::GUARD_NAME),
            'authenticatable_type' => StubIdentity::class,
            'authenticatable_id'   => '25',
            'refresh_key'          => RefreshTokenHasher::hash($plainRotationId),
        ])->save();
        $this->expectOwnerReload($device, $identity);

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
                \Mockery::on(static fn (mixed $event): bool => $event instanceof AuthenticationFailed
                    && $event->reason === FailureReason::PRINCIPAL_MISMATCH),
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
     * @throws \Random\RandomException
     */
    public function testRefreshRotatesAndIssuesNewTokenPairOnSuccess(): void
    {
        $plainRotationId = 'stored-rotation-id';
        $oldDigest       = RefreshTokenHasher::hash($plainRotationId);

        $identity = new StubIdentity;
        $identity->forceFill(['id' => 7]);

        $device = new StubDevice;
        $device->forceFill([
            ...self::liveSession(self::GUARD_NAME),
            'authenticatable_type' => StubIdentity::class,
            'authenticatable_id'   => '7',
            'refresh_key'          => $oldDigest,
        ])->save();

        $this->expectOwnerReload($device, $identity);

        $this->swapDeviceModelToInMemoryInstance($device);

        $guard = $this->makeGuard($this->makeRequest(null));

        $principal = \Mockery::mock(Principal::class, CanBeActive::class);
        $principal->shouldReceive('getTenant')->andReturnNull();
        $principal->shouldReceive('getPrincipalIdentifier')
            ->andReturn('p-1');
        $principal->shouldReceive('isActive')
            ->once()
            ->andReturnTrue();

        $this->resolver->shouldReceive('resolve')
            ->once()
            ->with($identity, 'p-1')
            ->andReturn($principal);

        $device->forceFill(self::recordedPrincipal($principal))->save();

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
        self::assertSame(self::GUARD_NAME, $refreshed[0]->context->guard);
        self::assertSame($identity, $refreshed[0]->context->identity);
        self::assertSame($principal, $refreshed[0]->context->principal);
        self::assertSame($device, $refreshed[0]->context->device);
    }

    /**
     * A successful refresh is a sign-in: `Attempting`, the package `Refreshed`
     * and `SignedIn` (a refresh, on the device it continued), reported before
     * the bind, then `Validated`, `Login` and the bind events.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Random\RandomException
     */
    public function testRefreshDispatchesRefreshedAndSignedInBeforeTheBind(): void
    {
        $plainRotationId = 'stored-rotation-id';

        $identity = new StubIdentity;
        $identity->forceFill(['id' => 19]);

        $device = new StubDevice;
        $device->forceFill([
            ...self::liveSession(self::GUARD_NAME),
            'authenticatable_type' => StubIdentity::class,
            'authenticatable_id'   => '19',
            'refresh_key'          => RefreshTokenHasher::hash($plainRotationId),
        ])->save();

        $this->expectOwnerReload($device, $identity);

        $this->swapDeviceModelToInMemoryInstance($device);

        $guard = $this->makeGuard($this->makeRequest(null));

        $principal = \Mockery::mock(Principal::class, CanBeActive::class);
        $principal->shouldReceive('getTenant')->andReturnNull();
        $principal->shouldReceive('getPrincipalIdentifier')
            ->andReturn('p-19');
        $principal->shouldReceive('isActive')
            ->once()
            ->andReturnTrue();

        $this->resolver->shouldReceive('resolve')
            ->once()
            ->with($identity, 'p-19')
            ->andReturn($principal);

        $device->forceFill(self::recordedPrincipal($principal))->save();

        $token = $this->encodeRefreshToken([
            'pid' => 'p-19',
            'did' => $device->id,
            'jti' => $plainRotationId,
        ]);

        $dispatched = [];

        $this->events->shouldReceive('dispatch')
            ->times(8)
            ->andReturnUsing(static function (object $event) use (&$dispatched): void {
                $dispatched[] = $event;
            });

        self::assertInstanceOf(RefreshResult::class, $guard->refresh($token));
        self::assertSame([
            Attempting::class,
            Refreshed::class,
            SignedIn::class,
            Validated::class,
            Login::class,
            Authenticated::class,
            PrincipalAssigned::class,
            DeviceAuthenticated::class,
        ], array_map(static fn (object $event): string => $event::class, $dispatched));

        $refreshed = $dispatched[1];
        $signedIn  = $dispatched[2];

        self::assertInstanceOf(Refreshed::class, $refreshed);
        self::assertInstanceOf(SignedIn::class, $signedIn);
        self::assertSame($refreshed->context, $signedIn->context);
        self::assertFalse($signedIn->deviceCreated);
        self::assertTrue($signedIn->refresh);
        self::assertSame('password', $signedIn->context->method);
        self::assertSame($device, $signedIn->context->device);
    }

    /**
     * After a successful refresh the guard has the identity, principal, and
     * device bound for the rest of the request.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Random\RandomException
     */
    public function testRefreshBindsIdentityPrincipalAndDeviceOnSuccess(): void
    {
        $plainRotationId = 'stored-rotation-id';

        $identity = new StubIdentity;
        $identity->forceFill(['id' => 7]);

        $device = new StubDevice;
        $device->forceFill([
            ...self::liveSession(self::GUARD_NAME),
            'authenticatable_type' => StubIdentity::class,
            'authenticatable_id'   => '7',
            'refresh_key'          => RefreshTokenHasher::hash($plainRotationId),
        ])->save();

        $this->expectOwnerReload($device, $identity);

        $this->swapDeviceModelToInMemoryInstance($device);

        $guard = $this->makeGuard($this->makeRequest(null));

        $principal = \Mockery::mock(Principal::class, CanBeActive::class);
        $principal->shouldReceive('getTenant')->andReturnNull();
        $principal->shouldReceive('getPrincipalIdentifier')
            ->andReturn('p-1');
        $principal->shouldReceive('isActive')
            ->once()
            ->andReturnTrue();

        $this->resolver->shouldReceive('resolve')
            ->once()
            ->with($identity)
            ->andReturn($principal);

        $device->forceFill(self::recordedPrincipal($principal))->save();

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
     * Rebinding the guard's principal resolver reaches the refresh exchange,
     * which reads the guard's context, so `refresh()` uses the replacement
     * resolver rather than the constructor-time one.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Random\RandomException
     */
    public function testRefreshUsesReplacementResolverAfterGuardResolverRebind(): void
    {
        $plainRotationId = 'stored-rotation-id';

        $identity = new StubIdentity;
        $identity->forceFill(['id' => 17]);

        $device = new StubDevice;
        $device->forceFill([
            ...self::liveSession(self::GUARD_NAME),
            'authenticatable_type' => StubIdentity::class,
            'authenticatable_id'   => '17',
            'refresh_key'          => RefreshTokenHasher::hash($plainRotationId),
        ])->save();

        $this->expectOwnerReload($device, $identity);

        $this->swapDeviceModelToInMemoryInstance($device);

        $guard = $this->makeGuard($this->makeRequest(null));

        $replacement = \Mockery::mock(PrincipalResolver::class);
        $principal   = \Mockery::mock(Principal::class, CanBeActive::class);
        $principal->shouldReceive('getTenant')->andReturnNull();

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

        $device->forceFill(self::recordedPrincipal($principal))->save();

        $token = $this->encodeRefreshToken([
            'did' => $device->id,
            'jti' => $plainRotationId,
        ]);

        $this->events->shouldReceive('dispatch')->andReturnNull();

        self::assertInstanceOf(RefreshResult::class, $guard->refresh($token));
        self::assertSame($principal, $guard->principal());
    }

    /**
     * `setPrincipalResolver()` rebinds the resolver bearer resolution reads as
     * well as the one refresh reads: a bearer token resolved after the rebind
     * goes through the replacement.
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
        $identity->shouldReceive('getAuthIdentifier')->andReturn('i-1');

        $principal = \Mockery::mock(Principal::class, CanBeActive::class);
        $principal->shouldReceive('getTenant')->andReturnNull();
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
     * `setDispatcher()` returns the guard and rebinds the dispatcher the
     * refresh path reads: a later failed refresh reports `Attempting`,
     * `AuthenticationFailed` and `Failed` to the new dispatcher only.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Random\RandomException
     */
    public function testSetDispatcherRoutesLaterRefreshFailuresToTheNewDispatcher(): void
    {
        $guard = $this->makeGuard($this->makeRequest(null));

        $replacement = \Mockery::mock(Dispatcher::class);
        $replacement->shouldReceive('dispatch')
            ->once()
            ->with(\Mockery::type(Attempting::class));
        $replacement->shouldReceive('dispatch')
            ->once()
            ->with(\Mockery::on(static fn (mixed $event): bool => $event instanceof AuthenticationFailed
                && $event->reason === FailureReason::TOKEN_INVALID));
        $replacement->shouldReceive('dispatch')
            ->once()
            ->with(\Mockery::type(Failed::class));

        $this->events->shouldNotReceive('dispatch');

        self::assertSame($guard, $guard->setDispatcher($replacement));
        self::assertNull($guard->refresh('not-a-jwt'));
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
}
