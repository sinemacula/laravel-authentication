<?php

declare(strict_types = 1);

namespace Tests\Unit\Guards;

use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Contracts\CanBeActive;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Exceptions\TenantUnavailableException;
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
     * A principal that names a tenant which cannot be loaded fails the tenant
     * check, and so fails as a principal, rather than passing as one with no
     * tenant.
     *
     * @return void
     */
    public function testPrincipalNamingAnUnavailableTenantFailsTheTenantCheck(): void
    {
        $principal = \Mockery::mock(Principal::class);
        $principal->shouldReceive('getTenant')->twice()->andThrow(new TenantUnavailableException('gone'));

        self::assertFalse(ActivationPolicy::isTenantActive($principal));
        self::assertFalse(ActivationPolicy::isPrincipalActive($principal));
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
     * `activeTenant()` returns the very tenant it loaded and checked when that
     * tenant is active, whether or not it opts into activation, so a caller
     * reporting the tenant reports the one that passed.
     *
     * @return void
     */
    public function testActiveTenantReturnsTheTenantItChecked(): void
    {
        $plain  = \Mockery::mock(Tenant::class);
        $active = $this->tenant(true);

        self::assertSame($plain, ActivationPolicy::activeTenant($this->principalWithTenant($plain)));
        self::assertSame($active, ActivationPolicy::activeTenant($this->principalWithTenant($active)));
    }

    /**
     * `activeTenant()` returns `null` for a principal that acts within no
     * tenant, and `false`, never the tenant, for one whose tenant is inactive
     * or cannot be loaded.
     *
     * @return void
     */
    public function testActiveTenantTellsNoTenantFromATenantThatMayNotAuthenticate(): void
    {
        self::assertNull(ActivationPolicy::activeTenant($this->principalWithTenant(null)));
        self::assertFalse(ActivationPolicy::activeTenant($this->principalWithTenant($this->tenant(false))));

        $unavailable = \Mockery::mock(Principal::class);
        $unavailable->shouldReceive('getTenant')->once()->andThrow(new TenantUnavailableException('gone'));

        self::assertFalse(ActivationPolicy::activeTenant($unavailable));
    }

    /**
     * `ActivationPolicy` is a static utility; instantiation is disallowed via
     * the private constructor so consumers cannot create a stateful activation
     * policy. Reflection invokes the private constructor so the line is covered
     * while still documenting the access modifier.
     *
     * @return void
     *
     * @SuppressWarnings("php:S3011")
     */
    public function testConstructorIsPrivate(): void
    {
        $reflection  = new \ReflectionClass(ActivationPolicy::class);
        $constructor = $reflection->getConstructor();

        self::assertNotNull($constructor);
        self::assertTrue($constructor->isPrivate());

        $instance = $reflection->newInstanceWithoutConstructor();
        $constructor->invoke($instance);

        self::assertInstanceOf(ActivationPolicy::class, $instance);
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
