<?php

declare(strict_types = 1);

namespace Tests\Unit\Guards;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Authentication\Contracts\Device;
use SineMacula\Laravel\Authentication\Contracts\Organization;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Events\DeviceAuthenticated;
use SineMacula\Laravel\Authentication\Events\PrincipalAssigned;
use SineMacula\Laravel\Authentication\Guards\AbstractGuard;
use SineMacula\Laravel\Authentication\Guards\Concerns\BindsContextualState;

/**
 * Unit tests for the contextual state surface on `AbstractGuard`
 * (`setPrincipal`, `setDevice`, `organization`, `scope`).
 *
 * Split out of the original AbstractGuardTest so each derived class
 * stays well below the project's 20-method-per-class threshold
 * (radarlint S1448).
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
            ->with(\Mockery::on(static fn (mixed $event): bool => $event instanceof PrincipalAssigned
                    && $event->guard     === self::GUARD_NAME
                    && $event->principal === $principal));

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
            ->with(\Mockery::on(static fn (mixed $event): bool => $event instanceof DeviceAuthenticated
                    && $event->guard  === self::GUARD_NAME
                    && $event->device === $device));

        $guard->setDevice($device);

        self::assertSame($device, $guard->device());
    }

    /**
     * organization() reads the principal's getOrganization().
     *
     * @return void
     */
    public function testOrganizationReturnsPrincipalsOrganization(): void
    {
        $guard = $this->makeGuard();

        $organization = \Mockery::mock(Organization::class);

        $principal = \Mockery::mock(Principal::class);
        $principal->shouldReceive('getOrganization')
            ->andReturn($organization);

        $this->events->shouldReceive('dispatch')->andReturnNull();

        $guard->setPrincipal($principal);

        self::assertSame($organization, $guard->organization());
    }

    /**
     * scope() reads the organization's scope string.
     *
     * @return void
     */
    public function testScopeReturnsOrganizationScope(): void
    {
        $guard = $this->makeGuard();

        $organization = \Mockery::mock(Organization::class);
        $organization->shouldReceive('getOrganizationScope')
            ->andReturn('internal');

        $principal = \Mockery::mock(Principal::class);
        $principal->shouldReceive('getOrganization')
            ->andReturn($organization);

        $this->events->shouldReceive('dispatch')->andReturnNull();

        $guard->setPrincipal($principal);

        self::assertSame('internal', $guard->scope());
    }
}
