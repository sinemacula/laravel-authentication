<?php

declare(strict_types = 1);

namespace Tests\Feature\Guards;

use Carbon\CarbonImmutable;
use Illuminate\Auth\Events\Failed;
use Illuminate\Auth\Events\Login;
use Illuminate\Database\Eloquent\Builder;
use Mockery\MockInterface;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Authentication\Contracts\CanBeActive;
use SineMacula\Laravel\Authentication\Contracts\Device;
use SineMacula\Laravel\Authentication\Contracts\HasDevices;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Guards\AbstractGuard;
use SineMacula\Laravel\Authentication\Guards\Concerns\VerifiesPinnedContext;
use Tests\Unit\Stubs\StubPinnedContextGuard;

/**
 * Feature tests for the principal and device a caller pins on `attempt()`: each
 * is bound only once proven to belong to the authenticated identity, and a pin
 * that fails the check fails the attempt.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversTrait(VerifiesPinnedContext::class)]
final class VerifiesPinnedContextTest extends AbstractGuardTestCase
{
    /** @var array<int, class-string> Classes of the dispatched events. */
    private array $dispatched = [];

    /** @var ?\SineMacula\Laravel\Authentication\Guards\AbstractGuard Guard of the last `guardAttempt()`. */
    private ?AbstractGuard $lastGuard = null;

    /**
     * Accept the credentials of a fresh identity and record dispatched events.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->provider->shouldReceive('validateCredentials')->andReturnTrue();

        $this->events->shouldReceive('dispatch')
            ->andReturnUsing(function (object $event): void {
                $this->dispatched[] = $event::class;
            });
    }

    /**
     * A pinned principal whose identifier resolves to a different principal
     * (the resolver falling back to the identity's default) fails the attempt.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testPinnedPrincipalResolvingToAnotherPrincipalFailsTheAttempt(): void
    {
        $identity = $this->acceptIdentity($this->mockIdentity());

        $pinned   = $this->principal('p-other');
        $fallback = $this->principal('p-default');

        $this->resolver->shouldReceive('resolve')->once()->with($identity, 'p-other')->andReturn($fallback);

        $this->assertAttemptFails($this->guardAttempt($pinned));
    }

    /**
     * A pinned principal of another class that shares the identifier of one the
     * identity owns fails the attempt.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testPinnedPrincipalOfAnotherClassWithACollidingIdentifierFailsTheAttempt(): void
    {
        $identity = $this->acceptIdentity($this->mockIdentity());

        $pinned = \Mockery::mock(Principal::class, CanBeActive::class);
        $pinned->shouldReceive('getPrincipalIdentifier')->andReturn('p-1');

        $owned = $this->principal('p-1');

        $this->resolver->shouldReceive('resolve')->once()->with($identity, 'p-1')->andReturn($owned);

        $this->assertAttemptFails($this->guardAttempt($pinned));
    }

    /**
     * A pinned principal with no identifier (unsaved) cannot be proven and
     * fails the attempt.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testPinnedPrincipalWithoutIdentifierFailsTheAttempt(): void
    {
        $identity = $this->acceptIdentity($this->mockIdentity());

        $pinned = $this->principal(null);

        $this->resolver->shouldReceive('resolve')->once()->with($identity)->andReturn($pinned);

        $this->assertAttemptFails($this->guardAttempt($pinned));
    }

    /**
     * When the resolver resolves nothing for a pinned principal the attempt
     * fails.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testPinnedPrincipalTheResolverCannotResolveFailsTheAttempt(): void
    {
        $identity = $this->acceptIdentity($this->mockIdentity());

        $this->resolver->shouldReceive('resolve')->once()->with($identity, 'p-1')->andReturnNull();

        $this->assertAttemptFails($this->guardAttempt($this->principal('p-1')));
    }

    /**
     * An owned but inactive pinned principal fails the attempt.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testInactivePinnedPrincipalFailsTheAttempt(): void
    {
        $identity = $this->acceptIdentity($this->mockIdentity());

        $pinned = \Mockery::mock(Principal::class, CanBeActive::class);
        $pinned->shouldReceive('getPrincipalIdentifier')->andReturn('p-1');
        $pinned->shouldReceive('isActive')->andReturnFalse();

        $this->resolver->shouldReceive('resolve')->once()->with($identity, 'p-1')->andReturn($pinned);

        $this->assertAttemptFails($this->guardAttempt($pinned));
    }

    /**
     * An owned, live pinned device binds the identity's own row rather than the
     * caller's instance.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testOwnedLivePinnedDeviceBindsTheIdentitysOwnRow(): void
    {
        $pinned = $this->device('d-1', null);
        $owned  = $this->device('d-1', null);

        $guard = $this->guardWithDevices($owned);

        self::assertTrue($guard->attempt(['email' => 'x'], null, $pinned));
        self::assertSame($owned, $guard->device());
    }

    /**
     * A pinned device the identity does not own fails the attempt.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testPinnedDeviceTheIdentityDoesNotOwnFailsTheAttempt(): void
    {
        $guard = $this->guardWithDevices(null);

        $this->assertAttemptFails($guard->attempt(['email' => 'x'], null, $this->device('d-1', null)), $guard);
    }

    /**
     * A revoked pinned device fails the attempt.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRevokedPinnedDeviceFailsTheAttempt(): void
    {
        $revoked = $this->device('d-1', CarbonImmutable::now());

        $guard = $this->guardWithDevices($revoked);

        $this->assertAttemptFails($guard->attempt(['email' => 'x'], null, $revoked), $guard);
    }

    /**
     * A pinned device of another class that shares the identifier of a device
     * the identity owns fails the attempt.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testPinnedDeviceOfAnotherClassWithACollidingIdentifierFailsTheAttempt(): void
    {
        $pinned = \Mockery::mock(Device::class, CanBeActive::class);
        $pinned->shouldReceive('getDeviceIdentifier')->andReturn('d-1');

        $guard = $this->guardWithDevices($this->device('d-1', null));

        $this->assertAttemptFails($guard->attempt(['email' => 'x'], null, $pinned), $guard);
    }

    /**
     * A pinned device with no identifier cannot be looked up and fails the
     * attempt without querying.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testPinnedDeviceWithoutIdentifierFailsTheAttempt(): void
    {
        $devices = \Mockery::mock(Builder::class);
        $devices->shouldNotReceive('find');

        $identity = \Mockery::mock(Identity::class, HasDevices::class);
        $identity->shouldReceive('devices')->andReturn($devices);

        $this->acceptIdentity($identity);
        $this->resolver->shouldReceive('resolve')->andReturn($this->principal('p-1'));

        $guard = $this->makeGuard();

        $this->assertAttemptFails($guard->attempt(['email' => 'x'], null, $this->device(null, null)), $guard);
    }

    /**
     * A pinned device on an identity that cannot own devices cannot be proven
     * and fails the attempt.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testPinnedDeviceOnIdentityWithoutDevicesFailsTheAttempt(): void
    {
        $this->acceptIdentity($this->mockIdentity());
        $this->resolver->shouldReceive('resolve')->andReturn($this->principal('p-1'));

        $guard = $this->makeGuard();

        $this->assertAttemptFails($guard->attempt(['email' => 'x'], null, $this->device('d-1', null)), $guard);
    }

    /**
     * The hint check matches a resolved principal only on an equal, non-null
     * identifier, comparing integer and string forms alike.
     *
     * @return void
     */
    public function testPrincipalHintMatchesOnlyAnEqualIdentifier(): void
    {
        $guard = $this->makeStubGuard();

        self::assertTrue($guard->matches($this->principal('5'), 5));
        self::assertTrue($guard->matches($this->principal('p-1'), 'p-1'));
        self::assertFalse($guard->matches($this->principal('p-1'), 'p-2'));
        self::assertFalse($guard->matches($this->principal(null), 'p-1'));
        self::assertFalse($guard->matches($this->principal('p-1'), null));
        self::assertFalse($guard->matches(null, 'p-1'));
    }

    /**
     * The pinned-principal and pinned-device checks are callable from a guard
     * subclass, and return the identity's own instances.
     *
     * @return void
     */
    public function testPinnedChecksAreAvailableToGuardSubclasses(): void
    {
        $guard = $this->makeStubGuard();

        $principal = $this->principal('p-1');
        $identity  = \Mockery::mock(Identity::class, HasDevices::class);
        $device    = $this->device('d-1', null);

        $devices = \Mockery::mock(Builder::class);
        $devices->shouldReceive('find')->once()->with('d-1')->andReturn($device);

        $identity->shouldReceive('devices')->andReturn($devices);

        $this->resolver->shouldReceive('resolve')->once()->with($identity, 'p-1')->andReturn($principal);

        self::assertSame($principal, $guard->pinnedPrincipal($identity, $principal));
        self::assertSame($device, $guard->pinnedDevice($identity, $device));
    }

    /**
     * Build the subclass test double over the shared collaborators.
     *
     * @return \Tests\Unit\Stubs\StubPinnedContextGuard
     */
    private function makeStubGuard(): StubPinnedContextGuard
    {
        return new StubPinnedContextGuard(self::GUARD_NAME, $this->provider, $this->resolver, $this->events, $this->request, $this->timebox);
    }

    /**
     * Make the provider return the identity for any credentials.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @return \SineMacula\Laravel\Authentication\Contracts\Identity
     */
    private function acceptIdentity(Identity $identity): Identity
    {
        $this->provider->shouldReceive('retrieveByCredentials')->andReturn($identity);

        return $identity;
    }

    /**
     * Attempt with the pinned principal on a fresh guard, keeping the guard for
     * assertions.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $pinned
     * @return bool
     *
     * @throws \Throwable
     */
    private function guardAttempt(Principal $pinned): bool
    {
        $this->lastGuard = $this->makeGuard();

        return $this->lastGuard->attempt(['email' => 'x'], $pinned);
    }

    /**
     * Assert the attempt failed: `false`, `Failed` dispatched, no `Login`, and
     * nothing bound.
     *
     * @param  bool  $result
     * @param  ?\SineMacula\Laravel\Authentication\Guards\AbstractGuard  $guard
     * @return void
     */
    private function assertAttemptFails(bool $result, ?AbstractGuard $guard = null): void
    {
        $guard ??= $this->lastGuard;

        self::assertFalse($result);
        self::assertContains(Failed::class, $this->dispatched);
        self::assertNotContains(Login::class, $this->dispatched);
        self::assertNotNull($guard);
        self::assertFalse($guard->hasUser());
    }

    /**
     * Build a guard whose authenticated identity owns the supplied device (or
     * none) and resolves an active principal.
     *
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Device  $owned
     * @return \SineMacula\Laravel\Authentication\Guards\AbstractGuard
     */
    private function guardWithDevices(?Device $owned): AbstractGuard
    {
        $devices = \Mockery::mock(Builder::class);
        $devices->shouldReceive('find')->once()->with('d-1')->andReturn($owned);

        $identity = \Mockery::mock(Identity::class, HasDevices::class);
        $identity->shouldReceive('devices')->andReturn($devices);

        $this->acceptIdentity($identity);
        $this->resolver->shouldReceive('resolve')->once()->with($identity)->andReturn($this->principal('p-1'));

        return $this->makeGuard();
    }

    /**
     * Build a principal without the activation capability that acts within no
     * tenant.
     *
     * @param  ?string  $identifier
     * @return \Mockery\MockInterface&\SineMacula\Laravel\Authentication\Contracts\Principal
     */
    private function principal(?string $identifier): MockInterface
    {
        $principal = \Mockery::mock(Principal::class);
        $principal->shouldReceive('getPrincipalIdentifier')->andReturn($identifier);
        $principal->shouldReceive('getTenant')->andReturnNull();

        return $principal;
    }

    /**
     * Build a device with the supplied identifier and revocation time.
     *
     * @param  ?string  $identifier
     * @param  ?\Carbon\CarbonImmutable  $revokedAt
     * @return \Mockery\MockInterface&\SineMacula\Laravel\Authentication\Contracts\Device
     */
    private function device(?string $identifier, ?CarbonImmutable $revokedAt): MockInterface
    {
        $device = \Mockery::mock(Device::class);
        $device->shouldReceive('getDeviceIdentifier')->andReturn($identifier);
        $device->shouldReceive('getRevokedAt')->andReturn($revokedAt);

        return $device;
    }
}
