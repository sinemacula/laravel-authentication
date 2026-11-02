<?php

declare(strict_types = 1);

namespace Tests\Feature\Admission;

use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use Mockery\MockInterface;
use Orchestra\Testbench\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Admission\TenantAdmission;
use SineMacula\Laravel\Authentication\AuthenticationServiceProvider;
use SineMacula\Laravel\Authentication\Contracts\CanBeActive;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Contracts\TenantAccess;
use SineMacula\Laravel\Authentication\Contracts\TenantResolver;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Exceptions\TenantUnavailableException;
use SineMacula\Laravel\Authentication\Tenancy\TenantSelection;
use Tests\Unit\Stubs\PlainPrincipalFixture;
use Tests\Unit\Stubs\PlainTenantFixture;

/**
 * Feature tests for the tenant a principal is to act in: the one a selection
 * asks for and the one a session records, resolved (the principal's own from
 * the principal, any other through the bound resolver), held to the bound
 * `TenantAccess`, and checked active, each refusal with its own reason.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(TenantAdmission::class)]
final class TenantAdmissionTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    /** @var \Mockery\MockInterface&\SineMacula\Laravel\Authentication\Contracts\TenantAccess The access the admission asks. */
    private MockInterface $access;

    /** @var \Mockery\MockInterface&\SineMacula\Laravel\Authentication\Contracts\TenantResolver The resolver the admission asks. */
    private MockInterface $resolver;

    /**
     * Bind a tenant access and a tenant resolver mock.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->access   = \Mockery::mock(TenantAccess::class);
        $this->resolver = \Mockery::mock(TenantResolver::class);

        $this->app?->instance(TenantAccess::class, $this->access);
        $this->app?->instance(TenantResolver::class, $this->resolver);
    }

    /**
     * The principal's default is its own tenant, never asked of the resolver,
     * once the access lets it act there; a platform principal's default is
     * none, asked of the access as none.
     *
     * @return void
     */
    public function testTheDefaultIsThePrincipalsOwnTenantOrNone(): void
    {
        $own       = new PlainTenantFixture(7);
        $principal = new PlainPrincipalFixture(1, tenant: $own);
        $platform  = new PlainPrincipalFixture(2);

        $this->resolver->shouldNotReceive('resolve');
        $this->access->shouldReceive('mayActIn')->once()->with($principal, $own)->andReturnTrue();
        $this->access->shouldReceive('mayActIn')->once()->with($platform, null)->andReturnTrue();

        self::assertSame($own, TenantAdmission::select($principal, TenantSelection::principalDefault()));
        self::assertNull(TenantAdmission::select($platform, TenantSelection::principalDefault()));
    }

    /**
     * A selection that names the principal's own tenant by its identifier is
     * that tenant, without the resolver; one that names none is none.
     *
     * @return void
     */
    public function testNamingTheOwnTenantOrNoneNeedsNoResolver(): void
    {
        $own       = new PlainTenantFixture(7);
        $principal = new PlainPrincipalFixture(1, tenant: $own);

        $this->resolver->shouldNotReceive('resolve');
        $this->access->shouldReceive('mayActIn')->once()->with($principal, $own)->andReturnTrue();
        $this->access->shouldReceive('mayActIn')->once()->with($principal, null)->andReturnTrue();

        self::assertSame($own, TenantAdmission::select($principal, TenantSelection::of('7')));
        self::assertNull(TenantAdmission::select($principal, TenantSelection::none()));
    }

    /**
     * Another tenant is resolved by its identifier and admitted once the access
     * lets the principal act in it and it is active.
     *
     * @return void
     */
    public function testAnotherTenantIsResolvedHeldToTheAccessAndCheckedActive(): void
    {
        $principal  = new PlainPrincipalFixture(1, tenant: new PlainTenantFixture(7));
        $descendant = self::activatable('9', true);

        $this->resolver->shouldReceive('resolve')->once()->with('9')->andReturn($descendant);
        $this->access->shouldReceive('mayActIn')->once()->with($principal, $descendant)->andReturnTrue();

        self::assertSame($descendant, TenantAdmission::select($principal, TenantSelection::of(9)));
    }

    /**
     * A named tenant the resolver does not find, or finds under another
     * identifier, is `tenant_ineligible`, the access never asked.
     *
     * @return void
     */
    public function testAnUnresolvedTenantIsIneligible(): void
    {
        $principal = new PlainPrincipalFixture(1);

        $this->resolver->shouldReceive('resolve')->once()->with('missing')->andReturnNull();
        $this->resolver->shouldReceive('resolve')->once()->with('other')->andReturn(new PlainTenantFixture('another'));
        $this->access->shouldNotReceive('mayActIn');

        self::assertSame(FailureReason::TENANT_INELIGIBLE, TenantAdmission::select($principal, TenantSelection::of('missing')));
        self::assertSame(FailureReason::TENANT_INELIGIBLE, TenantAdmission::select($principal, TenantSelection::of('other')));
    }

    /**
     * A tenant the access refuses is `tenant_ineligible` before its activity is
     * read, so the answer says nothing of the state of a tenant the principal
     * may not act in; an allowed tenant that is inactive is `tenant_inactive`.
     *
     * @return void
     */
    public function testTheAccessIsAskedBeforeTheActivity(): void
    {
        $principal = new PlainPrincipalFixture(1);
        $refused   = \Mockery::mock(Tenant::class, CanBeActive::class);
        $refused->shouldReceive('getTenantIdentifier')->andReturn('refused');
        $refused->shouldNotReceive('isActive');
        $inactive = self::activatable('inactive', false);

        $this->resolver->shouldReceive('resolve')->with('refused')->andReturn($refused);
        $this->resolver->shouldReceive('resolve')->with('inactive')->andReturn($inactive);
        $this->access->shouldReceive('mayActIn')->with($principal, $refused)->andReturnFalse();
        $this->access->shouldReceive('mayActIn')->with($principal, $inactive)->andReturnTrue();

        self::assertSame(FailureReason::TENANT_INELIGIBLE, TenantAdmission::select($principal, TenantSelection::of('refused')));
        self::assertSame(FailureReason::TENANT_INACTIVE, TenantAdmission::select($principal, TenantSelection::of('inactive')));
    }

    /**
     * The access refusing the principal's default, or no tenant, is
     * `tenant_ineligible` too.
     *
     * @return void
     */
    public function testARefusedDefaultOrNoneIsIneligible(): void
    {
        $principal = new PlainPrincipalFixture(1, tenant: new PlainTenantFixture(7));

        $this->access->shouldReceive('mayActIn')->twice()->andReturnFalse();

        self::assertSame(FailureReason::TENANT_INELIGIBLE, TenantAdmission::select($principal, TenantSelection::principalDefault()));
        self::assertSame(FailureReason::TENANT_INELIGIBLE, TenantAdmission::select($principal, TenantSelection::none()));
    }

    /**
     * A principal whose own tenant cannot be loaded may act in no tenant: any
     * selection is `tenant_inactive`, as its own tenant's activity check
     * answers, without asking the resolver or the access.
     *
     * @return void
     */
    public function testAPrincipalWhoseOwnTenantCannotBeLoadedIsRefusedAnySelection(): void
    {
        $principal = \Mockery::mock(Principal::class);
        $principal->shouldReceive('getTenant')->andThrow(new TenantUnavailableException('The tenant is gone.'));

        $this->resolver->shouldNotReceive('resolve');
        $this->access->shouldNotReceive('mayActIn');

        foreach ([TenantSelection::principalDefault(), TenantSelection::none(), TenantSelection::of('9')] as $selection) {
            self::assertSame(FailureReason::TENANT_INACTIVE, TenantAdmission::select($principal, $selection));
        }

        self::assertSame(FailureReason::TENANT_INACTIVE, TenantAdmission::recorded($principal, '9', true));
    }

    /**
     * A session that records no tenant acts in none: the access is asked about
     * none only when asked to check it.
     *
     * @return void
     */
    public function testARecordedNoneIsNone(): void
    {
        $principal = new PlainPrincipalFixture(1, tenant: new PlainTenantFixture(7));

        $this->access->shouldReceive('mayActIn')->once()->with($principal, null)->andReturnFalse();

        self::assertNull(TenantAdmission::recorded($principal, null, false));
        self::assertSame(FailureReason::TENANT_INELIGIBLE, TenantAdmission::recorded($principal, null, true));
    }

    /**
     * A recorded tenant that is the principal's own is that tenant, without the
     * resolver; another is resolved; and the access is asked only when asked to
     * check it.
     *
     * @return void
     */
    public function testARecordedTenantIsTheOwnOrTheResolved(): void
    {
        $own        = new PlainTenantFixture(7);
        $principal  = new PlainPrincipalFixture(1, tenant: $own);
        $descendant = self::activatable('9', true);

        $this->resolver->shouldReceive('resolve')->twice()->with('9')->andReturn($descendant);
        $this->access->shouldReceive('mayActIn')->once()->with($principal, $descendant)->andReturnTrue();

        self::assertSame($own, TenantAdmission::recorded($principal, '7', false));
        self::assertSame($descendant, TenantAdmission::recorded($principal, '9', false));
        self::assertSame($descendant, TenantAdmission::recorded($principal, '9', true));
    }

    /**
     * A recorded tenant that no longer resolves, or resolves inactive, is
     * `tenant_inactive`; one the access no longer allows is
     * `tenant_ineligible`.
     *
     * @return void
     */
    public function testARecordedTenantGoneInactiveOrRefusedIsRefused(): void
    {
        $principal = new PlainPrincipalFixture(1);
        $inactive  = self::activatable('inactive', false);
        $refused   = self::activatable('refused', true);

        $this->resolver->shouldReceive('resolve')->with('gone')->andReturnNull();
        $this->resolver->shouldReceive('resolve')->with('inactive')->andReturn($inactive);
        $this->resolver->shouldReceive('resolve')->with('refused')->andReturn($refused);
        $this->access->shouldReceive('mayActIn')->with($principal, $refused)->andReturnFalse();

        self::assertSame(FailureReason::TENANT_INACTIVE, TenantAdmission::recorded($principal, 'gone', false));
        self::assertSame(FailureReason::TENANT_INACTIVE, TenantAdmission::recorded($principal, 'inactive', false));
        self::assertSame($refused, TenantAdmission::recorded($principal, 'refused', false));
        self::assertSame(FailureReason::TENANT_INELIGIBLE, TenantAdmission::recorded($principal, 'refused', true));
    }

    /**
     * A trusted bind names a tenant with no access or activity check: the own
     * tenant when its identifier matches, else the resolver's answer when it
     * has the identifier asked for, and nothing for one it does not find or
     * finds under another identifier.
     *
     * @return void
     */
    public function testANamedTenantIsTheOwnOrTheResolvedWithNoCheck(): void
    {
        $own       = new PlainTenantFixture(7);
        $principal = new PlainPrincipalFixture(1, tenant: $own);
        $inactive  = \Mockery::mock(Tenant::class, CanBeActive::class);
        $inactive->shouldReceive('getTenantIdentifier')->andReturn('9');
        $inactive->shouldNotReceive('isActive');

        $this->resolver->shouldReceive('resolve')->once()->with('9')->andReturn($inactive);
        $this->resolver->shouldReceive('resolve')->once()->with('gone')->andReturnNull();
        $this->resolver->shouldReceive('resolve')->once()->with('other')->andReturn(new PlainTenantFixture('another'));
        $this->access->shouldNotReceive('mayActIn');

        self::assertSame($own, TenantAdmission::named($principal, $own, '7'));
        self::assertSame($inactive, TenantAdmission::named($principal, $own, '9'));
        self::assertNull(TenantAdmission::named($principal, $own, 'gone'));
        self::assertNull(TenantAdmission::named($principal, null, 'other'));
    }

    /**
     * The class is a static utility that cannot be instantiated from outside.
     *
     * @return void
     */
    public function testConstructorIsPrivate(): void
    {
        $reflection  = new \ReflectionClass(TenantAdmission::class);
        $constructor = $reflection->getConstructor();

        self::assertNotNull($constructor);
        self::assertTrue($constructor->isPrivate());

        $instance = $reflection->newInstanceWithoutConstructor();
        $constructor->invoke($instance);

        self::assertInstanceOf(TenantAdmission::class, $instance);
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

    /**
     * A tenant that opts into activation, with the identifier and the state.
     *
     * @param  string  $id
     * @param  bool  $active
     * @return \Mockery\MockInterface&\SineMacula\Laravel\Authentication\Contracts\Tenant
     */
    private static function activatable(string $id, bool $active): MockInterface
    {
        $tenant = \Mockery::mock(Tenant::class, CanBeActive::class);
        $tenant->shouldReceive('getTenantIdentifier')->andReturn($id);
        $tenant->shouldReceive('isActive')->andReturn($active);

        return $tenant;
    }
}
