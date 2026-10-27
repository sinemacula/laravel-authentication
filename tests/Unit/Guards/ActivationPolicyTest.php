<?php

declare(strict_types = 1);

namespace Tests\Unit\Guards;

use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Contracts\CanBeActive;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Guards\ActivationPolicy;

/**
 * Unit tests for the opt-in `ActivationPolicy`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ActivationPolicy::class)]
final class ActivationPolicyTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    /**
     * A subject without the `CanBeActive` capability is active: activation is
     * opt-in, so an ordinary model with no activation column authenticates.
     *
     * @return void
     */
    public function testSubjectWithoutActivationCapabilityIsActive(): void
    {
        self::assertTrue(ActivationPolicy::isActive(\Mockery::mock(Principal::class)));
    }

    /**
     * A `CanBeActive` subject that reports active passes.
     *
     * @return void
     */
    public function testCanBeActiveSubjectReportingActiveIsActive(): void
    {
        $subject = \Mockery::mock(CanBeActive::class);
        $subject->shouldReceive('isActive')->once()->andReturnTrue();

        self::assertTrue(ActivationPolicy::isActive($subject));
    }

    /**
     * A `CanBeActive` subject that reports inactive fails.
     *
     * @return void
     */
    public function testCanBeActiveSubjectReportingInactiveIsNotActive(): void
    {
        $subject = \Mockery::mock(CanBeActive::class);
        $subject->shouldReceive('isActive')->once()->andReturnFalse();

        self::assertFalse(ActivationPolicy::isActive($subject));
    }

    /**
     * A principal that acts within no tenant passes the tenant check.
     *
     * @return void
     */
    public function testPrincipalWithoutTenantPassesTenantCheck(): void
    {
        self::assertTrue(ActivationPolicy::isTenantActive($this->principalWithTenant(null)));
    }

    /**
     * A tenant without the `CanBeActive` capability is active.
     *
     * @return void
     */
    public function testTenantWithoutActivationCapabilityIsActive(): void
    {
        self::assertTrue(ActivationPolicy::isTenantActive($this->principalWithTenant(\Mockery::mock(Tenant::class))));
    }

    /**
     * A `CanBeActive` tenant reporting active passes, and one reporting
     * inactive fails.
     *
     * @return void
     */
    public function testCanBeActiveTenantIsCheckedThroughThePrincipal(): void
    {
        self::assertTrue(ActivationPolicy::isTenantActive($this->principalWithTenant($this->tenant(true))));
        self::assertFalse(ActivationPolicy::isTenantActive($this->principalWithTenant($this->tenant(false))));
    }

    /**
     * A principal passes only when it and its tenant are both active.
     *
     * @return void
     */
    public function testPrincipalIsActiveOnlyWhenItAndItsTenantAreActive(): void
    {
        self::assertTrue(ActivationPolicy::isPrincipalActive($this->principalWithTenant($this->tenant(true))));
        self::assertFalse(ActivationPolicy::isPrincipalActive($this->principalWithTenant($this->tenant(false))));

        $inactive = \Mockery::mock(Principal::class, CanBeActive::class);
        $inactive->shouldReceive('isActive')->once()->andReturnFalse();
        $inactive->shouldNotReceive('getTenant');

        self::assertFalse(ActivationPolicy::isPrincipalActive($inactive));
    }

    /**
     * Build a principal without the activation capability that acts within the
     * supplied tenant.
     *
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Tenant  $tenant
     * @return \SineMacula\Laravel\Authentication\Contracts\Principal
     */
    private function principalWithTenant(?Tenant $tenant): Principal
    {
        $principal = \Mockery::mock(Principal::class);
        $principal->shouldReceive('getTenant')->once()->andReturn($tenant);

        return $principal;
    }

    /**
     * Build a `CanBeActive` tenant reporting the supplied state.
     *
     * @param  bool  $active
     * @return \SineMacula\Laravel\Authentication\Contracts\Tenant
     */
    private function tenant(bool $active): Tenant
    {
        $tenant = \Mockery::mock(Tenant::class, CanBeActive::class);
        $tenant->shouldReceive('isActive')->once()->andReturn($active);

        return $tenant;
    }
}
