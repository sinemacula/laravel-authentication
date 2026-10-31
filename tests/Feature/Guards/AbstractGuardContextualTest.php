<?php

declare(strict_types = 1);

namespace Tests\Feature\Guards;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Events\DeviceAuthenticated;
use SineMacula\Laravel\Authentication\Events\PrincipalAssigned;
use SineMacula\Laravel\Authentication\Guards\AbstractGuard;

/**
 * Feature tests for the contextual state surface on `AbstractGuard`
 * (`setPrincipal`, `setDevice`, `tenant`).
 *
 * Split out of the original AbstractGuardTest so each class stays focused on a
 * single behavioral slice.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AbstractGuard::class)]
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

        $principal = $this->mockPrincipal();

        $this->events->shouldReceive('dispatch')
            ->once()
            ->with(
                \Mockery::on(static fn (mixed $event): bool => $event instanceof PrincipalAssigned
                    && $event->context->guard     === self::GUARD_NAME
                    && $event->context->principal === $principal),
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

        $device = $this->mockDevice();

        $this->events->shouldReceive('dispatch')
            ->once()
            ->with(
                \Mockery::on(static fn (mixed $event): bool => $event instanceof DeviceAuthenticated
                    && $event->context->guard  === self::GUARD_NAME
                    && $event->context->device === $device),
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
        $tenant->shouldReceive('getTenantIdentifier')->byDefault()->andReturn('tenant-1');

        $principal = $this->mockPrincipal();
        $principal->shouldReceive('getTenant')
            ->andReturn($tenant);

        $this->events->shouldReceive('dispatch')->andReturnNull();

        $guard->setPrincipal($principal);

        self::assertSame($tenant, $guard->tenant());
    }
}
