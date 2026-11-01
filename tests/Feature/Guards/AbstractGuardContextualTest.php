<?php

declare(strict_types = 1);

namespace Tests\Feature\Guards;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Events\PrincipalAssigned;
use SineMacula\Laravel\Authentication\Events\SessionAuthenticated;
use SineMacula\Laravel\Authentication\Guards\AbstractGuard;

/**
 * Feature tests for the contextual state surface on `AbstractGuard`
 * (`setPrincipal`, `setSession`, `tenant`).
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
     * setSession() fires the SessionAuthenticated custom event.
     *
     * @return void
     */
    public function testSetSessionFiresSessionAuthenticatedEvent(): void
    {
        $guard = $this->makeGuard();

        $session = $this->mockSession();

        $this->events->shouldReceive('dispatch')
            ->once()
            ->with(
                \Mockery::on(static fn (mixed $event): bool => $event instanceof SessionAuthenticated
                    && $event->context->guard   === self::GUARD_NAME
                    && $event->context->session === $session),
            );

        $guard->setSession($session);

        self::assertSame($session, $guard->session());
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
