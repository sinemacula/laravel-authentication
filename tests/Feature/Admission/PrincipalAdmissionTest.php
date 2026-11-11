<?php

declare(strict_types = 1);

namespace Tests\Feature\Admission;

use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use Mockery\MockInterface;
use Orchestra\Testbench\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Admission\PrincipalAdmission;
use SineMacula\Laravel\Authentication\AuthenticationServiceProvider;
use SineMacula\Laravel\Authentication\Contracts\ApplicationAccess;
use SineMacula\Laravel\Authentication\Contracts\CanBeActive;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Exceptions\TenantUnavailableException;
use Tests\Unit\Stubs\PlainPrincipalFixture;
use Tests\Unit\Stubs\PlainTenantFixture;

/**
 * Feature tests for whether a principal may hold a session of an application.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PrincipalAdmission::class)]
final class PrincipalAdmissionTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    /** @var \Mockery\MockInterface&\SineMacula\Laravel\Authentication\Contracts\ApplicationAccess The access the admission asks. */
    private MockInterface $access;

    /**
     * Bind an application access mock.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->access = \Mockery::mock(ApplicationAccess::class);

        $this->app?->instance(ApplicationAccess::class, $this->access);
    }

    /**
     * An active principal in an active tenant, or in none, that the access lets
     * use the application is admitted.
     *
     * @return void
     */
    public function testAnActivePrincipalTheAccessAdmitsMayHoldASession(): void
    {
        $inTenant = new PlainPrincipalFixture(1, tenant: new PlainTenantFixture(7));
        $platform = new PlainPrincipalFixture(2);

        $this->access->shouldReceive('mayUse')->once()->with('console', $inTenant)->andReturnTrue();
        $this->access->shouldReceive('mayUse')->once()->with('console', $platform)->andReturnTrue();

        self::assertNull(PrincipalAdmission::refusal('console', $inTenant));
        self::assertNull(PrincipalAdmission::refusal('console', $platform));
    }

    /**
     * An inactive principal or own tenant is refused before the access is
     * asked.
     *
     * @return void
     */
    public function testInactivityIsRefusedBeforeTheAccessIsAsked(): void
    {
        $tenant = \Mockery::mock(Tenant::class, CanBeActive::class);
        $tenant->shouldReceive('isActive')->andReturnFalse();

        $missing = \Mockery::mock(Principal::class);
        $missing->shouldReceive('getTenant')->andThrow(new TenantUnavailableException('The tenant is gone.'));

        $this->access->shouldNotReceive('mayUse');

        self::assertSame(FailureReason::PRINCIPAL_INACTIVE, PrincipalAdmission::refusal('console', new PlainPrincipalFixture(1, active: false)));
        self::assertSame(FailureReason::TENANT_INACTIVE, PrincipalAdmission::refusal('console', new PlainPrincipalFixture(2, tenant: $tenant)));
        self::assertSame(FailureReason::TENANT_INACTIVE, PrincipalAdmission::refusal('console', $missing));
    }

    /**
     * A principal the access keeps out of the application is refused as
     * `principal_ineligible`, and `mayUse()` answers as the access does.
     *
     * @return void
     */
    public function testAPrincipalTheAccessRefusesIsIneligible(): void
    {
        $principal = new PlainPrincipalFixture(1);

        $this->access->shouldReceive('mayUse')->twice()->with('admin', $principal)->andReturnFalse();

        self::assertSame(FailureReason::PRINCIPAL_INELIGIBLE, PrincipalAdmission::refusal('admin', $principal));
        self::assertFalse(PrincipalAdmission::mayUse('admin', $principal));
    }

    /**
     * A principal whose own activity the caller has checked is not asked it
     * again.
     *
     * @return void
     */
    public function testAPrincipalWhoseActivityWasCheckedIsJudgedByItsTenantThenTheAccess(): void
    {
        $tenant = \Mockery::mock(Tenant::class, CanBeActive::class);
        $tenant->shouldReceive('isActive')->andReturnFalse();

        $unasked    = new PlainPrincipalFixture(1, active: false);
        $inInactive = new PlainPrincipalFixture(2, tenant: $tenant);
        $kept       = new PlainPrincipalFixture(3);

        $this->access->shouldReceive('mayUse')->once()->with('console', $unasked)->andReturnTrue();
        $this->access->shouldReceive('mayUse')->once()->with('console', $kept)->andReturnFalse();

        self::assertNull(PrincipalAdmission::refusalOfActive('console', $unasked));
        self::assertSame(FailureReason::TENANT_INACTIVE, PrincipalAdmission::refusalOfActive('console', $inInactive));
        self::assertSame(FailureReason::PRINCIPAL_INELIGIBLE, PrincipalAdmission::refusalOfActive('console', $kept));
    }

    /**
     * The access is resolved each time it is asked.
     *
     * @return void
     */
    public function testTheAccessBoundWhenAskedIsHeard(): void
    {
        $principal = new PlainPrincipalFixture(1);

        $this->access->shouldReceive('mayUse')->once()->andReturnTrue();

        self::assertTrue(PrincipalAdmission::mayUse('admin', $principal));

        $later = \Mockery::mock(ApplicationAccess::class);
        $later->shouldReceive('mayUse')->once()->with('admin', $principal)->andReturnFalse();

        $this->app?->instance(ApplicationAccess::class, $later);

        self::assertFalse(PrincipalAdmission::mayUse('admin', $principal));
    }

    /**
     * The class is a static utility that cannot be instantiated from outside.
     *
     * @return void
     */
    public function testConstructorIsPrivate(): void
    {
        $reflection  = new \ReflectionClass(PrincipalAdmission::class);
        $constructor = $reflection->getConstructor();

        self::assertNotNull($constructor);
        self::assertTrue($constructor->isPrivate());

        $instance = $reflection->newInstanceWithoutConstructor();
        $constructor->invoke($instance);

        self::assertInstanceOf(PrincipalAdmission::class, $instance);
    }

    /**
     * Register the package service provider.
     *
     * @param  mixed  $app
     * @return array<int, class-string<\Illuminate\Support\ServiceProvider>>
     */
    #[\Override]
    protected function getPackageProviders(mixed $app): array
    {
        return [AuthenticationServiceProvider::class];
    }
}
