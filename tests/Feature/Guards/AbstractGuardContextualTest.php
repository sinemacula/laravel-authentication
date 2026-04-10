<?php

declare(strict_types = 1);

namespace Tests\Feature\Guards;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Authentication\Contracts\Device;
use SineMacula\Laravel\Authentication\Contracts\HasType;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Events\DeviceAuthenticated;
use SineMacula\Laravel\Authentication\Events\PrincipalAssigned;
use SineMacula\Laravel\Authentication\Guards\AbstractGuard;
use SineMacula\Laravel\Authentication\Guards\Concerns\BindsContextualState;

/**
 * Feature tests for the contextual state surface on `AbstractGuard`
 * (`setPrincipal`, `setDevice`, `tenant`, `type`).
 *
 * Split out of the original AbstractGuardTest so each class stays focused on a
 * single behavioural slice.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 *
 * @internal
 */
#[CoversClass(AbstractGuard::class)]
#[CoversTrait(BindsContextualState::class)]
final class AbstractGuardContextualTest extends AbstractGuardTestCase
{
    /**
     * setPrincipal() fires the PrincipalAssigned custom event.
     *
     * @return void
     */
    public function testSetPrincipalFiresPrincipalAssignedEvent(): void
    {
        $guard = $this->makeGuard();

        $principal = \Mockery::mock(Principal::class);

        $this->events->shouldReceive('dispatch')
            ->once()
            ->with(
                \Mockery::on(static fn (mixed $event): bool => $event instanceof PrincipalAssigned
                    && $event->guard     === self::GUARD_NAME
                    && $event->principal === $principal),
            );

        $guard->setPrincipal($principal);

        self::assertSame($principal, $guard->principal());
    }

    /**
     * setDevice() fires the DeviceAuthenticated custom event.
     *
     * @return void
     */
    public function testSetDeviceFiresDeviceAuthenticatedEvent(): void
    {
        $guard = $this->makeGuard();

        $device = \Mockery::mock(Device::class);

        $this->events->shouldReceive('dispatch')
            ->once()
            ->with(
                \Mockery::on(static fn (mixed $event): bool => $event instanceof DeviceAuthenticated
                    && $event->guard  === self::GUARD_NAME
                    && $event->device === $device),
            );

        $guard->setDevice($device);

        self::assertSame($device, $guard->device());
    }

    /**
     * tenant() reads the principal's getTenant().
     *
     * @return void
     */
    public function testTenantReturnsPrincipalsTenant(): void
    {
        $guard = $this->makeGuard();

        $tenant = \Mockery::mock(Tenant::class);

        $principal = \Mockery::mock(Principal::class);
        $principal->shouldReceive('getTenant')
            ->andReturn($tenant);

        $this->events->shouldReceive('dispatch')->andReturnNull();

        $guard->setPrincipal($principal);

        self::assertSame($tenant, $guard->tenant());
    }

    /**
     * type() returns the tenant's type when the tenant declares the `HasType`
     * capability.
     *
     * @return void
     */
    public function testTypeReturnsTenantTypeWhenCapabilityDeclared(): void
    {
        $guard = $this->makeGuard();

        $tenant = \Mockery::mock(Tenant::class, HasType::class);
        $tenant->shouldReceive('getType')
            ->andReturn('staff');

        $principal = \Mockery::mock(Principal::class);
        $principal->shouldReceive('getTenant')
            ->andReturn($tenant);

        $this->events->shouldReceive('dispatch')->andReturnNull();

        $guard->setPrincipal($principal);

        self::assertSame('staff', $guard->type());
    }

    /**
     * type() returns null when the tenant does not declare the `HasType`
     * capability.
     *
     * @return void
     */
    public function testTypeReturnsNullWhenTenantHasNoTypeCapability(): void
    {
        $guard = $this->makeGuard();

        $tenant = \Mockery::mock(Tenant::class);

        $principal = \Mockery::mock(Principal::class);
        $principal->shouldReceive('getTenant')
            ->andReturn($tenant);

        $this->events->shouldReceive('dispatch')->andReturnNull();

        $guard->setPrincipal($principal);

        self::assertNull($guard->type());
    }
}
