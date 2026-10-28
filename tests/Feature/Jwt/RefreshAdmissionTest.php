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
use SineMacula\Laravel\Authentication\Contracts\AudiencePolicy;
use SineMacula\Laravel\Authentication\Contracts\CanBeActive;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\IdentityProvider;
use SineMacula\Laravel\Authentication\Contracts\MachineIdentity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\PrincipalResolver;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Jwt\RefreshAdmission;
use SineMacula\Laravel\Authentication\Sessions\Admission\AdmittedSignIn;
use SineMacula\Laravel\Authentication\Sessions\Admission\RefusedSignIn;
use Tests\Concerns\InteractsWithDevices;
use Tests\Unit\Stubs\StubDevice;
use Tests\Unit\Stubs\StubIdentity;

/**
 * Feature tests for whom a device's refresh token signs in again: the device's
 * owner, as the principal the token names, active, in an active tenant, and
 * still allowed by the guard's audience policy. Each refusal carries as much of
 * the session as was resolved before it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RefreshAdmission::class)]
final class RefreshAdmissionTest extends TestCase
{
    use InteractsWithDevices, MockeryPHPUnitIntegration;

    /** @var string Guard the admission is for. */
    private const string GUARD = 'api';

    /** @var \Mockery\MockInterface&\SineMacula\Laravel\Authentication\Contracts\IdentityProvider The guard's provider. */
    private MockInterface $provider;

    /** @var \Mockery\MockInterface&\SineMacula\Laravel\Authentication\Contracts\PrincipalResolver The guard's resolver. */
    private MockInterface $resolver;

    /** @var \Mockery\MockInterface&\SineMacula\Laravel\Authentication\Contracts\AudiencePolicy The audience policy. */
    private MockInterface $audience;

    /**
     * Build the collaborators and the device table.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->provider = \Mockery::mock(IdentityProvider::class);
        $this->resolver = \Mockery::mock(PrincipalResolver::class);
        $this->audience = \Mockery::mock(AudiencePolicy::class);

        $this->audience->shouldReceive('allowsMethod')->with(self::GUARD, 'password')->andReturnTrue()->byDefault();
        $this->audience->shouldReceive('admit')->andReturnNull()->byDefault();

        $this->app?->instance(AudiencePolicy::class, $this->audience);

        self::createDeviceTable('stub_devices');
    }

    /**
     * Drop the device table.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Schema::dropIfExists('stub_devices');

        parent::tearDown();
    }

    /**
     * The owner, active, as the principal the hint names, in an active tenant
     * and allowed by the policy, is admitted with the tenant its check loaded
     * and the device.
     *
     * @return void
     */
    public function testTheActiveOwnerIsAdmittedAsTheNamedPrincipal(): void
    {
        $device    = $this->seedDevice();
        $identity  = $this->expectOwner();
        $tenant    = self::tenant(true);
        $principal = $this->expectPrincipal($identity, 'p-1', 'p-1', $tenant);

        $admitted = $this->admission()->admit($device, 'p-1');

        self::assertInstanceOf(AdmittedSignIn::class, $admitted);
        self::assertSame($identity, $admitted->identity);
        self::assertSame($principal, $admitted->principal);
        self::assertSame($tenant, $admitted->tenant);
        self::assertSame($device, $admitted->device);
    }

    /**
     * A token without a hint is admitted as the resolver's default principal.
     *
     * @return void
     */
    public function testATokenWithoutAHintIsAdmittedAsTheDefaultPrincipal(): void
    {
        $device    = $this->seedDevice();
        $identity  = $this->expectOwner();
        $principal = \Mockery::mock(Principal::class);
        $principal->shouldReceive('getTenant')->andReturnNull();

        $this->resolver->shouldReceive('resolve')->once()->withArgs(static fn (mixed ...$arguments): bool => $arguments === [$identity])->andReturn($principal);

        $admitted = $this->admission()->admit($device, null);

        self::assertInstanceOf(AdmittedSignIn::class, $admitted);
        self::assertSame($principal, $admitted->principal);
        self::assertNull($admitted->tenant);
    }

    /**
     * An owner the guard's provider does not return, or returns as another
     * model, is refused as `identity_unknown` with no identity, before any
     * principal is resolved.
     *
     * @return void
     */
    public function testAnOwnerTheProviderDoesNotReturnIsUnknown(): void
    {
        $device = $this->seedDevice();

        $this->provider->shouldReceive('retrieveById')->once()->with('7')->andReturnNull();
        $this->resolver->shouldNotReceive('resolve');

        $refused = $this->admission()->admit($device, 'p-1');

        self::assertInstanceOf(RefusedSignIn::class, $refused);
        self::assertSame(FailureReason::IDENTITY_UNKNOWN, $refused->reason);
        self::assertNull($refused->identity);
    }

    /**
     * An owner that is a non-human identity is refused as `machine_identity`,
     * carrying the owner, even when it is inactive too: a machine has no device
     * refresh and no switch of principal, and that reason comes first.
     *
     * @return void
     */
    public function testAMachineOwnerIsRefusedWithTheOwner(): void
    {
        $device  = $this->seedDevice();
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
             * Record the identity under the stub's own class, as the device
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

        $refused = $this->admission()->admit($device, 'p-1');

        self::assertInstanceOf(RefusedSignIn::class, $refused);
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
        $device   = $this->seedDevice();
        $identity = $this->expectOwner(false);

        $this->resolver->shouldNotReceive('resolve');

        $refused = $this->admission()->admit($device, 'p-1');

        self::assertInstanceOf(RefusedSignIn::class, $refused);
        self::assertSame(FailureReason::IDENTITY_INACTIVE, $refused->reason);
        self::assertSame($identity, $refused->identity);
        self::assertNull($refused->principal);
    }

    /**
     * A hint that resolves to another principal, or to none, is refused as
     * `principal_mismatch`, and a token without a hint whose identity has no
     * default principal as `principal_unresolved`; none carries a principal.
     *
     * @return void
     */
    public function testAPrincipalThatIsNotTheNamedOneIsRefused(): void
    {
        $device   = $this->seedDevice();
        $identity = $this->expectOwner(true, 3);

        $this->expectPrincipal($identity, 'p-1', 'p-2', null);

        $mismatch = $this->admission()->admit($device, 'p-1');

        $this->resolver->shouldReceive('resolve')->once()->with($identity, 'p-9')->andReturnNull();

        $missing = $this->admission()->admit($device, 'p-9');

        self::assertInstanceOf(RefusedSignIn::class, $missing);
        self::assertSame(FailureReason::PRINCIPAL_MISMATCH, $missing->reason);

        $this->resolver->shouldReceive('resolve')->once()->withArgs(static fn (mixed ...$arguments): bool => $arguments === [$identity])->andReturnNull();

        $unresolved = $this->admission()->admit($device, null);

        self::assertInstanceOf(RefusedSignIn::class, $mismatch);
        self::assertSame(FailureReason::PRINCIPAL_MISMATCH, $mismatch->reason);
        self::assertSame($identity, $mismatch->identity);
        self::assertNull($mismatch->principal);
        self::assertInstanceOf(RefusedSignIn::class, $unresolved);
        self::assertSame(FailureReason::PRINCIPAL_UNRESOLVED, $unresolved->reason);
    }

    /**
     * An inactive principal is refused as `principal_inactive`, and one in an
     * inactive tenant as `tenant_inactive`; both carry the principal and no
     * tenant.
     *
     * @return void
     */
    public function testAnInactivePrincipalOrTenantIsRefusedWithThePrincipal(): void
    {
        $device   = $this->seedDevice();
        $identity = $this->expectOwner(true, 2);

        $inactive = \Mockery::mock(Principal::class, CanBeActive::class);
        $inactive->shouldReceive('getPrincipalIdentifier')->andReturn('p-1');
        $inactive->shouldReceive('isActive')->andReturnFalse();
        $inactive->shouldNotReceive('getTenant');

        $this->resolver->shouldReceive('resolve')->once()->with($identity, 'p-1')->andReturn($inactive);

        $principalRefusal = $this->admission()->admit($device, 'p-1');

        $member = $this->expectPrincipal($identity, 'p-2', 'p-2', self::tenant(false));

        $tenantRefusal = $this->admission()->admit($device, 'p-2');

        self::assertInstanceOf(RefusedSignIn::class, $principalRefusal);
        self::assertSame(FailureReason::PRINCIPAL_INACTIVE, $principalRefusal->reason);
        self::assertSame($inactive, $principalRefusal->principal);
        self::assertInstanceOf(RefusedSignIn::class, $tenantRefusal);
        self::assertSame(FailureReason::TENANT_INACTIVE, $tenantRefusal->reason);
        self::assertSame($member, $tenantRefusal->principal);
        self::assertNull($tenantRefusal->tenant);
    }

    /**
     * A method the guard no longer allows, or a device that records none, is
     * refused as `method_not_allowed`, and a principal the policy no longer
     * admits as `principal_ineligible`; each carries the admitted session,
     * tenant included.
     *
     * @return void
     */
    public function testThePolicyRefusesWithTheAdmittedSession(): void
    {
        $removed  = $this->seedDevice();
        $unstated = $this->seedDevice(['sign_in_method' => null]);
        $identity = $this->expectOwner(true, 3);
        $tenant   = self::tenant(true);

        $this->expectPrincipal($identity, 'p-1', 'p-1', $tenant, 3);

        $this->audience->shouldReceive('allowsMethod')->once()->with(self::GUARD, 'password')->andReturnFalse();

        $notAllowed = $this->admission()->admit($removed, 'p-1');
        $noMethod   = $this->admission()->admit($unstated, 'p-1');

        $this->audience->shouldReceive('allowsMethod')->with(self::GUARD, 'password')->andReturnTrue();
        $this->audience->shouldReceive('admit')
            ->once()
            ->withArgs(static fn (string $guard, Identity $admitted, Principal $acting, ?string $type): bool => $guard === self::GUARD && $admitted === $identity && $type === null)
            ->andReturn(FailureReason::PRINCIPAL_INELIGIBLE);

        $ineligible = $this->admission()->admit($removed, 'p-1');

        $expected = [[$notAllowed, FailureReason::METHOD_NOT_ALLOWED], [$noMethod, FailureReason::METHOD_NOT_ALLOWED], [$ineligible, FailureReason::PRINCIPAL_INELIGIBLE]];

        foreach ($expected as [$refused, $reason]) {
            self::assertInstanceOf(RefusedSignIn::class, $refused);
            self::assertSame($reason, $refused->reason);
            self::assertSame($identity, $refused->identity);
            self::assertSame($tenant, $refused->tenant);
        }
    }

    /**
     * Use the shipped stub device model on the in-memory database.
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
        $config->set('authentication.device.model', StubDevice::class);
        $config->set('authentication.device.table', 'stub_devices');
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
     * Persist a live device of the guard owned by identity 7.
     *
     * @param  array<string, mixed>  $state
     * @return \Tests\Unit\Stubs\StubDevice
     */
    private function seedDevice(array $state = []): StubDevice
    {
        $device = new StubDevice;
        $device->forceFill([...self::liveSession(self::GUARD), 'authenticatable_type' => StubIdentity::class, 'authenticatable_id' => '7', ...$state])->save();

        return StubDevice::query()->findOrFail($device->id);
    }

    /**
     * Expect the provider to reload the device's owner, active or not.
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
             * Record the identity under the stub's own class, as the device
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
     * A tenant that opts into activation and reports the given state.
     *
     * @param  bool  $active
     * @return \Mockery\MockInterface&\SineMacula\Laravel\Authentication\Contracts\Tenant
     */
    private static function tenant(bool $active): MockInterface
    {
        $tenant = \Mockery::mock(Tenant::class, CanBeActive::class);
        $tenant->shouldReceive('isActive')->andReturn($active);

        return $tenant;
    }
}
