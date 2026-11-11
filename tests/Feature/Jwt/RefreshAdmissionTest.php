<?php

declare(strict_types = 1);

namespace Tests\Feature\Jwt;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\Schema;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use Mockery\MockInterface;
use Orchestra\Testbench\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Admission\Admitted;
use SineMacula\Laravel\Authentication\Admission\Refused;
use SineMacula\Laravel\Authentication\Contracts\ApplicationAccess;
use SineMacula\Laravel\Authentication\Contracts\ApplicationPolicy;
use SineMacula\Laravel\Authentication\Contracts\CanBeActive;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\IdentityProvider;
use SineMacula\Laravel\Authentication\Contracts\MachineIdentity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\PrincipalResolver;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Contracts\TenantAccess;
use SineMacula\Laravel\Authentication\Contracts\TenantResolver;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Jwt\RefreshAdmission;
use SineMacula\Laravel\Authentication\Tenancy\OwnTenantOnly;
use SineMacula\Laravel\Authentication\Tenancy\ResolveNoTenant;
use Tests\Concerns\InteractsWithSessionRecords;
use Tests\Unit\Stubs\PlainPrincipalFixture;
use Tests\Unit\Stubs\StubIdentity;
use Tests\Unit\Stubs\StubSession;

/**
 * Feature tests for whom a session's refresh token signs in again.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RefreshAdmission::class)]
final class RefreshAdmissionTest extends TestCase
{
    use InteractsWithSessionRecords, MockeryPHPUnitIntegration;

    /** @var string Guard the admission is for. */
    private const string GUARD = 'api';

    /** @var \Mockery\MockInterface&\SineMacula\Laravel\Authentication\Contracts\IdentityProvider The guard's provider. */
    private MockInterface $provider;

    /** @var \Mockery\MockInterface&\SineMacula\Laravel\Authentication\Contracts\PrincipalResolver The guard's resolver. */
    private MockInterface $resolver;

    /** @var \Mockery\MockInterface&\SineMacula\Laravel\Authentication\Contracts\ApplicationPolicy The application policy. */
    private MockInterface $policy;

    /** @var \Mockery\MockInterface&\SineMacula\Laravel\Authentication\Contracts\ApplicationAccess Whether a principal may use the application. */
    private MockInterface $access;

    /**
     * Build the collaborators and the session table.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->provider = \Mockery::mock(IdentityProvider::class);
        $this->resolver = \Mockery::mock(PrincipalResolver::class);
        $this->policy   = \Mockery::mock(ApplicationPolicy::class);
        $this->access   = \Mockery::mock(ApplicationAccess::class);

        $this->policy->shouldReceive('allowsMethod')->with(self::GUARD, 'password')->andReturnTrue()->byDefault();
        $this->access->shouldReceive('mayUse')->andReturnTrue()->byDefault();

        $this->app?->instance(ApplicationPolicy::class, $this->policy);
        $this->app?->instance(ApplicationAccess::class, $this->access);
        $this->app?->singleton(TenantAccess::class, OwnTenantOnly::class);
        $this->app?->singleton(TenantResolver::class, ResolveNoTenant::class);

        self::createSessionRecordTable('stub_sessions');
    }

    /**
     * Drop the session table.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Schema::dropIfExists('stub_sessions');

        parent::tearDown();
    }

    /**
     * The active owner, as the principal the hint names, is admitted with its
     * tenant and the session.
     *
     * @return void
     */
    public function testTheActiveOwnerIsAdmittedAsTheNamedPrincipal(): void
    {
        $session   = $this->seedSession();
        $identity  = $this->expectOwner();
        $tenant    = self::tenant(true);
        $principal = $this->expectPrincipal($identity, 'p-1', 'p-1', $tenant);

        $admitted = $this->admission()->admit($session, 'p-1');

        self::assertInstanceOf(Admitted::class, $admitted);
        self::assertSame($identity, $admitted->identity);
        self::assertSame($principal, $admitted->principal);
        self::assertSame($tenant, $admitted->tenant);
        self::assertSame($session, $admitted->session);
    }

    /**
     * A token without a hint is admitted as the resolver's default principal.
     *
     * @return void
     */
    public function testATokenWithoutAHintIsAdmittedAsTheDefaultPrincipal(): void
    {
        $session   = $this->seedSession();
        $identity  = $this->expectOwner();
        $principal = \Mockery::mock(Principal::class);
        $principal->shouldReceive('getTenant')->andReturnNull();

        $this->resolver->shouldReceive('resolve')->once()->withArgs(static fn (mixed ...$arguments): bool => $arguments === [$identity])->andReturn($principal);

        $admitted = $this->admission()->admit($session, null);

        self::assertInstanceOf(Admitted::class, $admitted);
        self::assertSame($principal, $admitted->principal);
        self::assertNull($admitted->tenant);
    }

    /**
     * An owner the provider does not return, or returns as another model, is
     * refused as `identity_unknown`.
     *
     * @return void
     */
    public function testAnOwnerTheProviderDoesNotReturnIsUnknown(): void
    {
        $session = $this->seedSession();

        $this->provider->shouldReceive('retrieveById')->once()->with('7')->andReturnNull();
        $this->resolver->shouldNotReceive('resolve');

        $refused = $this->admission()->admit($session, 'p-1');

        self::assertInstanceOf(Refused::class, $refused);
        self::assertSame(FailureReason::IDENTITY_UNKNOWN, $refused->reason);
        self::assertNull($refused->identity);
    }

    /**
     * A machine owner is refused as `machine_identity` with the owner, even
     * when it is also inactive.
     *
     * @return void
     */
    public function testAMachineOwnerIsRefusedWithTheOwner(): void
    {
        $session = $this->seedSession();
        $machine = new class extends StubIdentity implements CanBeActive, MachineIdentity {
            /**
             * Inactive as well, so the machine reason must come before the
             * activity check.
             *
             * @return bool
             */
            #[\Override]
            public function isActive(): bool
            {
                return false;
            }

            /**
             * Record the identity under the stub's own class, as the session
             * does.
             *
             * @return string
             */
            #[\Override]
            public function getMorphClass(): string
            {
                return StubIdentity::class;
            }
        };

        $machine->forceFill(['id' => 7]);

        $this->provider->shouldReceive('retrieveById')->once()->with('7')->andReturn($machine);
        $this->resolver->shouldNotReceive('resolve');

        $refused = $this->admission()->admit($session, 'p-1');

        self::assertInstanceOf(Refused::class, $refused);
        self::assertSame(FailureReason::MACHINE_IDENTITY, $refused->reason);
        self::assertSame($machine, $refused->identity);
    }

    /**
     * An inactive owner is refused as `identity_inactive`, carrying the owner.
     *
     * @return void
     */
    public function testAnInactiveOwnerIsRefusedWithTheOwner(): void
    {
        $session  = $this->seedSession();
        $identity = $this->expectOwner(false);

        $this->resolver->shouldNotReceive('resolve');

        $refused = $this->admission()->admit($session, 'p-1');

        self::assertInstanceOf(Refused::class, $refused);
        self::assertSame(FailureReason::IDENTITY_INACTIVE, $refused->reason);
        self::assertSame($identity, $refused->identity);
        self::assertNull($refused->principal);
    }

    /**
     * A hint resolving to another principal or none is refused as
     * `principal_mismatch`, and no default principal as `principal_unresolved`.
     *
     * @return void
     */
    public function testAPrincipalThatIsNotTheNamedOneIsRefused(): void
    {
        $session  = $this->seedSession();
        $identity = $this->expectOwner(true, 3);

        $this->expectPrincipal($identity, 'p-1', 'p-2', null);

        $mismatch = $this->admission()->admit($session, 'p-1');

        $this->resolver->shouldReceive('resolve')->once()->with($identity, 'p-9')->andReturnNull();

        $missing = $this->admission()->admit($session, 'p-9');

        self::assertInstanceOf(Refused::class, $missing);
        self::assertSame(FailureReason::PRINCIPAL_MISMATCH, $missing->reason);

        $this->resolver->shouldReceive('resolve')->once()->withArgs(static fn (mixed ...$arguments): bool => $arguments === [$identity])->andReturnNull();

        $unresolved = $this->admission()->admit($session, null);

        self::assertInstanceOf(Refused::class, $mismatch);
        self::assertSame(FailureReason::PRINCIPAL_MISMATCH, $mismatch->reason);
        self::assertSame($identity, $mismatch->identity);
        self::assertNull($mismatch->principal);
        self::assertInstanceOf(Refused::class, $unresolved);
        self::assertSame(FailureReason::PRINCIPAL_UNRESOLVED, $unresolved->reason);
    }

    /**
     * An inactive principal is refused as `principal_inactive`, and one in an
     * inactive tenant as `tenant_inactive`.
     *
     * @return void
     */
    public function testAnInactivePrincipalOrTenantIsRefusedWithThePrincipal(): void
    {
        $session  = $this->seedSession();
        $identity = $this->expectOwner(true, 2);

        $inactive = \Mockery::mock(Principal::class, CanBeActive::class);
        $inactive->shouldReceive('getPrincipalIdentifier')->andReturn('p-1');
        $inactive->shouldReceive('isActive')->andReturnFalse();
        $inactive->shouldNotReceive('getTenant');

        $this->resolver->shouldReceive('resolve')->once()->with($identity, 'p-1')->andReturn($inactive);

        $principalRefusal = $this->admission()->admit($session, 'p-1');

        $member = $this->expectPrincipal($identity, 'p-2', 'p-2', self::tenant(false));

        $tenantRefusal = $this->admission()->admit($session, 'p-2');

        self::assertInstanceOf(Refused::class, $principalRefusal);
        self::assertSame(FailureReason::PRINCIPAL_INACTIVE, $principalRefusal->reason);
        self::assertSame($inactive, $principalRefusal->principal);
        self::assertInstanceOf(Refused::class, $tenantRefusal);
        self::assertSame(FailureReason::TENANT_INACTIVE, $tenantRefusal->reason);
        self::assertSame($member, $tenantRefusal->principal);
        self::assertNull($tenantRefusal->tenant);
    }

    /**
     * A method no longer allowed is refused as `method_not_allowed`, and an
     * ineligible principal as `principal_ineligible`, each with the session.
     *
     * @return void
     */
    public function testThePolicyRefusesWithTheAdmittedSession(): void
    {
        $removed  = $this->seedSession();
        $unstated = $this->seedSession(['sign_in_method' => null]);
        $identity = $this->expectOwner(true, 3);
        $tenant   = self::tenant(true);

        $this->expectPrincipal($identity, 'p-1', 'p-1', $tenant, 3);

        $this->policy->shouldReceive('allowsMethod')->once()->with(self::GUARD, 'password')->andReturnFalse();

        $notAllowed = $this->admission()->admit($removed, 'p-1');
        $noMethod   = $this->admission()->admit($unstated, 'p-1');

        $this->policy->shouldReceive('allowsMethod')->with(self::GUARD, 'password')->andReturnTrue();
        $this->access->shouldReceive('mayUse')
            ->once()
            ->withArgs(static fn (string $guard, Principal $acting): bool => $guard === self::GUARD && $acting->getPrincipalIdentifier() === 'p-1')
            ->andReturnFalse();

        $ineligible = $this->admission()->admit($removed, 'p-1');

        $expected = [[$notAllowed, FailureReason::METHOD_NOT_ALLOWED], [$noMethod, FailureReason::METHOD_NOT_ALLOWED], [$ineligible, FailureReason::PRINCIPAL_INELIGIBLE]];

        foreach ($expected as [$refused, $reason]) {
            self::assertInstanceOf(Refused::class, $refused);
            self::assertSame($reason, $refused->reason);
            self::assertSame($identity, $refused->identity);
            self::assertSame($tenant, $refused->tenant);
        }
    }

    /**
     * A session that records its principal is admitted in the tenant it acts
     * in, while `TenantAccess` allows it.
     *
     * @return void
     */
    public function testTheSessionsActiveTenantIsTheOneAdmitted(): void
    {
        $identity   = $this->expectOwner(true, 2);
        $own        = self::tenant(true, 'own');
        $descendant = self::tenant(true, 'descendant');
        $principal  = $this->expectPrincipal($identity, 'p-1', 'p-1', $own, 2);
        $inOwn      = $this->seedSession(self::recordedPrincipal($principal));
        $below      = $this->seedSession([...self::recordedPrincipal($principal), 'tenant_id' => 'descendant']);

        $resolver = \Mockery::mock(TenantResolver::class);
        $resolver->shouldReceive('resolve')->once()->with('descendant')->andReturn($descendant);

        $access = \Mockery::mock(TenantAccess::class);
        $access->shouldReceive('mayActIn')->once()->with($principal, $own)->andReturnTrue();
        $access->shouldReceive('mayActIn')->once()->with($principal, $descendant)->andReturnTrue();

        $this->app?->instance(TenantResolver::class, $resolver);
        $this->app?->instance(TenantAccess::class, $access);

        $owned  = $this->admission()->admit($inOwn, 'p-1');
        $placed = $this->admission()->admit($below, 'p-1');

        self::assertInstanceOf(Admitted::class, $owned);
        self::assertSame($own, $owned->tenant);
        self::assertSame($inOwn, $owned->session);
        self::assertInstanceOf(Admitted::class, $placed);
        self::assertSame($descendant, $placed->tenant);
        self::assertSame($below, $placed->session);
    }

    /**
     * A tenant `TenantAccess` no longer allows is refused as
     * `tenant_ineligible`, and one no longer found as `tenant_inactive`.
     *
     * @return void
     */
    public function testAnActiveTenantNoLongerAllowedOrFoundIsRefused(): void
    {
        $identity  = $this->expectOwner(true, 2);
        $own       = self::tenant(true, 'own');
        $principal = $this->expectPrincipal($identity, 'p-1', 'p-1', $own, 2);
        $inOwn     = $this->seedSession(self::recordedPrincipal($principal));
        $gone      = $this->seedSession([...self::recordedPrincipal($principal), 'tenant_id' => 'gone']);

        $resolver = \Mockery::mock(TenantResolver::class);
        $resolver->shouldReceive('resolve')->once()->with('gone')->andReturnNull();

        $access = \Mockery::mock(TenantAccess::class);
        $access->shouldReceive('mayActIn')->once()->with($principal, $own)->andReturnFalse();

        $this->app?->instance(TenantResolver::class, $resolver);
        $this->app?->instance(TenantAccess::class, $access);

        $refused = $this->admission()->admit($inOwn, 'p-1');
        $missing = $this->admission()->admit($gone, 'p-1');

        self::assertInstanceOf(Refused::class, $refused);
        self::assertSame(FailureReason::TENANT_INELIGIBLE, $refused->reason);
        self::assertSame($own, $refused->tenant);
        self::assertSame($inOwn, $refused->session);
        self::assertInstanceOf(Refused::class, $missing);
        self::assertSame(FailureReason::TENANT_INACTIVE, $missing->reason);
        self::assertSame($gone, $missing->session);
    }

    /**
     * A principal the session does not record, or one admitted for a switch, is
     * admitted in its own tenant.
     *
     * @return void
     */
    public function testAPrincipalAdmittedOutsideTheSessionKeepsItsOwnTenant(): void
    {
        $identity  = $this->expectOwner(true, 2);
        $own       = self::tenant(true, 'own');
        $principal = $this->expectPrincipal($identity, 'p-1', 'p-1', $own, 2);
        $other     = $this->seedSession([...self::recordedPrincipal(new PlainPrincipalFixture('p-2')), 'tenant_id' => 'elsewhere']);
        $recorded  = $this->seedSession([...self::recordedPrincipal($principal), 'tenant_id' => 'elsewhere']);

        $resolver = \Mockery::mock(TenantResolver::class);
        $resolver->shouldNotReceive('resolve');

        $access = \Mockery::mock(TenantAccess::class);
        $access->shouldNotReceive('mayActIn');

        $this->app?->instance(TenantResolver::class, $resolver);
        $this->app?->instance(TenantAccess::class, $access);

        foreach ([$this->admission()->admit($other, 'p-1'), $this->admission()->admitPrincipal($recorded, 'p-1')] as $admitted) {
            self::assertInstanceOf(Admitted::class, $admitted);
            self::assertSame($own, $admitted->tenant);
        }
    }

    /**
     * Use the shipped stub session model on the in-memory database.
     *
     * @param  mixed  $app
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        assert($app instanceof Application);

        /** @var \Illuminate\Config\Repository $config */
        $config = $app->make(ConfigRepository::class);

        $config->set('database.default', 'testing');
        $config->set('database.connections.testing', ['driver' => 'sqlite', 'database' => ':memory:', 'prefix' => '']);
        $config->set('authentication.session.model', StubSession::class);
        $config->set('authentication.session.table', 'stub_sessions');
    }

    /**
     * The admission under test, for the guard's collaborators.
     *
     * @return \SineMacula\Laravel\Authentication\Jwt\RefreshAdmission
     */
    private function admission(): RefreshAdmission
    {
        return new RefreshAdmission(self::GUARD, $this->provider, $this->resolver);
    }

    /**
     * Persist a live session of the guard owned by identity 7.
     *
     * @param  array<string, mixed>  $state
     * @return \Tests\Unit\Stubs\StubSession
     */
    private function seedSession(array $state = []): StubSession
    {
        $session = new StubSession;
        $session->forceFill([...self::liveSession(self::GUARD), 'authenticatable_type' => StubIdentity::class, 'authenticatable_id' => '7', ...$state])->save();

        return StubSession::query()->findOrFail($session->id);
    }

    /**
     * Expect the provider to reload the session's owner, active or not.
     *
     * @param  bool  $active
     * @param  int  $times
     * @return \Tests\Unit\Stubs\StubIdentity
     */
    private function expectOwner(bool $active = true, int $times = 1): StubIdentity
    {
        $identity = new class extends StubIdentity implements CanBeActive {
            /** @var bool Whether the identity reports active. */
            public bool $active = true;

            /**
             * Whether the identity reports active.
             *
             * @return bool
             */
            #[\Override]
            public function isActive(): bool
            {
                return $this->active;
            }

            /**
             * Record the identity under the stub's own class, as the session
             * does.
             *
             * @return string
             */
            #[\Override]
            public function getMorphClass(): string
            {
                return StubIdentity::class;
            }
        };

        $identity->forceFill(['id' => 7]);

        $identity->active = $active;

        $this->provider->shouldReceive('retrieveById')->times($times)->with('7')->andReturn($identity);

        return $identity;
    }

    /**
     * Expect the resolver to answer the hint with a principal of the given
     * identifier, acting within the tenant.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  string  $hint
     * @param  string  $identifier
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Tenant  $tenant
     * @param  int  $times
     * @return \Mockery\MockInterface&\SineMacula\Laravel\Authentication\Contracts\Principal
     */
    private function expectPrincipal(Identity $identity, string $hint, string $identifier, ?Tenant $tenant, int $times = 1): MockInterface
    {
        $principal = \Mockery::mock(Principal::class);
        $principal->shouldReceive('getPrincipalIdentifier')->andReturn($identifier);
        $principal->shouldReceive('getTenant')->andReturn($tenant);

        $this->resolver->shouldReceive('resolve')->times($times)->with($identity, $hint)->andReturn($principal);

        return $principal;
    }

    /**
     * A tenant that opts into activation and reports the given state, with the
     * identifier.
     *
     * @param  bool  $active
     * @param  string  $id
     * @return \Mockery\MockInterface&\SineMacula\Laravel\Authentication\Contracts\Tenant
     */
    private static function tenant(bool $active, string $id = 'tenant'): MockInterface
    {
        $tenant = \Mockery::mock(Tenant::class, CanBeActive::class);
        $tenant->shouldReceive('isActive')->andReturn($active);
        $tenant->shouldReceive('getTenantIdentifier')->andReturn($id);

        return $tenant;
    }
}
