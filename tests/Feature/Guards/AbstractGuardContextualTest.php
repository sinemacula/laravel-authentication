<?php

declare(strict_types = 1);

namespace Tests\Feature\Guards;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Contracts\HasType;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Events\DeviceAuthenticated;
use SineMacula\Laravel\Authentication\Events\PrincipalAssigned;
use SineMacula\Laravel\Authentication\Guards\AbstractGuard;

/**
 * Feature tests for the contextual state surface on `AbstractGuard`
 * (`setPrincipal`, `setDevice`, `tenant`, `type`).
 *
 * Split out of the original AbstractGuardTest so each class stays focused on a
 * single behavioural slice.
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

    /**
     * type() returns the principal's own type when it declares the `HasType`
     * capability, over the type of the tenant it acts within.
     *
     * @return void
     */
    public function testTypeReturnsThePrincipalsOwnTypeOverItsTenants(): void
    {
        $guard = $this->makeGuard();

        $tenant = \Mockery::mock(Tenant::class, HasType::class);
        $tenant->shouldReceive('getTenantIdentifier')->andReturn('tenant-1');
        $tenant->shouldNotReceive('getType');

        $principal = $this->mockPrincipal(HasType::class);
        $principal->shouldReceive('getType')
            ->andReturn('client_admin');
        $principal->shouldReceive('getTenant')->andReturn($tenant);

        $this->events->shouldReceive('dispatch')->andReturnNull();

        $guard->setPrincipal($principal);

        self::assertSame('client_admin', $guard->type());
    }

    /**
     * type() falls back to the tenant's type when the principal declares none
     * and the tenant declares the `HasType` capability.
     *
     * @return void
     */
    public function testTypeReturnsTenantTypeWhenCapabilityDeclared(): void
    {
        $guard = $this->makeGuard();

        $tenant = \Mockery::mock(Tenant::class, HasType::class);
        $tenant->shouldReceive('getTenantIdentifier')->byDefault()->andReturn('tenant-1');
        $tenant->shouldReceive('getType')
            ->andReturn('staff');

        $principal = $this->mockPrincipal();
        $principal->shouldReceive('getTenant')
            ->andReturn($tenant);

        $this->events->shouldReceive('dispatch')->andReturnNull();

        $guard->setPrincipal($principal);

        self::assertSame('staff', $guard->type());
    }

    /**
     * type() returns null when neither the principal nor its tenant declares
     * the `HasType` capability.
     *
     * @return void
     */
    public function testTypeReturnsNullWhenTenantHasNoTypeCapability(): void
    {
        $guard = $this->makeGuard();

        $tenant = \Mockery::mock(Tenant::class);
        $tenant->shouldReceive('getTenantIdentifier')->byDefault()->andReturn('tenant-1');

        $principal = $this->mockPrincipal();
        $principal->shouldReceive('getTenant')
            ->andReturn($tenant);

        $this->events->shouldReceive('dispatch')->andReturnNull();

        $guard->setPrincipal($principal);

        self::assertNull($guard->type());
    }
}
