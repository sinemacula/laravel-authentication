<?php

declare(strict_types = 1);

namespace Tests\Unit\Admission;

use Illuminate\Config\Repository;
use Illuminate\Container\Container;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use Mockery\MockInterface;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Admission\Admitted;
use SineMacula\Laravel\Authentication\Admission\Refused;
use SineMacula\Laravel\Authentication\Admission\SignInAdmission;
use SineMacula\Laravel\Authentication\Applications\GuardApplicationPolicy;
use SineMacula\Laravel\Authentication\Contracts\ApplicationAccess;
use SineMacula\Laravel\Authentication\Contracts\ApplicationPolicy;
use SineMacula\Laravel\Authentication\Contracts\CanBeActive;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\MachineIdentity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Contracts\TenantAccess;
use SineMacula\Laravel\Authentication\Contracts\TenantResolver;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenServiceFactory;
use SineMacula\Laravel\Authentication\Tenancy\TenantSelection;
use Tests\Unit\Stubs\StubVerifiableIdentity;

/**
 * Unit tests for the checks every sign-in passes once its identity is known.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SignInAdmission::class)]
final class SignInAdmissionTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    /** @var \Mockery\MockInterface&\SineMacula\Laravel\Authentication\Contracts\ApplicationPolicy The guards' application policy. */
    private MockInterface $policy;

    /** @var \Mockery\MockInterface&\SineMacula\Laravel\Authentication\Contracts\ApplicationAccess Whether a principal may use the application. */
    private MockInterface $access;

    /** @var \Mockery\MockInterface&\SineMacula\Laravel\Authentication\Contracts\TenantAccess Whether a principal may act in a tenant. */
    private MockInterface $tenants;

    /** @var \Mockery\MockInterface&\SineMacula\Laravel\Authentication\Contracts\TenantResolver The tenant an identifier names. */
    private MockInterface $resolver;

    /** @var ?\Illuminate\Container\Container The container before the test. */
    private ?Container $previous = null;

    /**
     * Build fresh mocks of the application policy and the access contracts, and
     * bind the contracts in a container of the test's own.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->previous = Container::getInstance();
        $this->policy   = \Mockery::mock(ApplicationPolicy::class);
        $this->access   = \Mockery::mock(ApplicationAccess::class);
        $this->tenants  = \Mockery::mock(TenantAccess::class);
        $this->resolver = \Mockery::mock(TenantResolver::class);

        $this->policy->shouldReceive('admitIdentifier')->byDefault()->andReturnNull();
        $this->access->shouldReceive('mayUse')->byDefault()->andReturnTrue();
        $this->tenants->shouldReceive('mayActIn')->byDefault()->andReturnTrue();

        $container = new Container;

        $container->instance(ApplicationAccess::class, $this->access);
        $container->instance(TenantAccess::class, $this->tenants);
        $container->instance(TenantResolver::class, $this->resolver);

        Container::setInstance($container);
    }

    /**
     * Restore the container.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Container::setInstance($this->previous);

        parent::tearDown();
    }

    /**
     * An active identity, principal and tenant are admitted together in the
     * principal's own tenant.
     *
     * @return void
     */
    public function testAdmitsWhenEveryCheckPasses(): void
    {
        $identity  = \Mockery::mock(Identity::class);
        $tenant    = $this->tenant(true);
        $principal = $this->principal(true, $tenant);

        $this->policy->shouldReceive('admitIdentifier')->once()->with('api', $identity, 'email')->andReturnNull();
        $this->access->shouldReceive('mayUse')->once()->with('api', $principal)->andReturnTrue();
        $this->tenants->shouldReceive('mayActIn')->once()->with($principal, $tenant)->andReturnTrue();
        $this->resolver->shouldNotReceive('resolve');

        $admitted = $this->admission()->admit('api', $identity, static fn (): Principal => $principal, FailureReason::PRINCIPAL_UNRESOLVED, 'email');

        self::assertInstanceOf(Admitted::class, $admitted);
        self::assertSame($identity, $admitted->identity);
        self::assertSame($principal, $admitted->principal);
        self::assertSame($tenant, $admitted->tenant);
    }

    /**
     * An inactive identity is refused before its principal is resolved, so the
     * resolver never runs for it.
     *
     * @return void
     */
    public function testRefusesAnInactiveIdentityWithoutResolvingAPrincipal(): void
    {
        $identity = $this->inactiveIdentity();
        $resolved = false;

        $this->policy->shouldNotReceive('admitIdentifier');
        $this->access->shouldNotReceive('mayUse');

        $refused = $this->admission()->admit('api', $identity, static function () use (&$resolved): ?Principal {
            $resolved = true;

            return null;
        }, FailureReason::PRINCIPAL_UNRESOLVED, 'email');

        self::assertFalse($resolved);
        self::assertInstanceOf(Refused::class, $refused);
        self::assertSame(FailureReason::IDENTITY_INACTIVE, $refused->reason);
        self::assertSame($identity, $refused->identity);
        self::assertNull($refused->principal);
    }

    /**
     * A non-human identity is refused as `machine_identity` before the policy
     * is asked or a principal resolved.
     *
     * @return void
     */
    public function testRefusesAMachineIdentityFirst(): void
    {
        $identity = \Mockery::mock(MachineIdentity::class, CanBeActive::class);
        $identity->shouldNotReceive('isActive');
        $resolved = false;

        $this->policy->shouldNotReceive('admitIdentifier');
        $this->access->shouldNotReceive('mayUse');

        $refused = $this->admission()->admit('api', $identity, static function () use (&$resolved): ?Principal {
            $resolved = true;

            return null;
        }, FailureReason::PRINCIPAL_UNRESOLVED, 'email');

        self::assertFalse($resolved);
        self::assertInstanceOf(Refused::class, $refused);
        self::assertSame(FailureReason::MACHINE_IDENTITY, $refused->reason);
        self::assertSame($identity, $refused->identity);
    }

    /**
     * A policy's refusal of the identity comes before any principal is
     * resolved.
     *
     * @return void
     */
    public function testAnyPolicysRefusalOfTheIdentityComesBeforeItsPrincipal(): void
    {
        $identity = \Mockery::mock(Identity::class);
        $resolved = false;

        $this->policy->shouldReceive('admitIdentifier')->once()->with('api', $identity, 'phone')->andReturn(FailureReason::IDENTIFIER_UNVERIFIED);
        $this->access->shouldNotReceive('mayUse');

        $refused = $this->admission()->admit('api', $identity, static function () use (&$resolved): ?Principal {
            $resolved = true;

            return null;
        }, FailureReason::PRINCIPAL_UNRESOLVED, 'phone');

        self::assertFalse($resolved);
        self::assertInstanceOf(Refused::class, $refused);
        self::assertSame(FailureReason::IDENTIFIER_UNVERIFIED, $refused->reason);
        self::assertSame($identity, $refused->identity);
        self::assertNull($refused->principal);
    }

    /**
     * With a guard that requires a verified identifier, an unverified one is
     * refused before its principal is resolved.
     *
     * @return void
     */
    public function testThePackagePolicyRefusesAnUnverifiedIdentifierWithoutResolvingAPrincipal(): void
    {
        $admission  = new SignInAdmission($this->packagePolicy());
        $unverified = new StubVerifiableIdentity(1, ['email' => 'ben@example.com']);
        $resolved   = false;

        $refused = $admission->admit('api', $unverified, static function () use (&$resolved): ?Principal {
            $resolved = true;

            return null;
        }, FailureReason::PRINCIPAL_UNRESOLVED, 'email');

        self::assertFalse($resolved);
        self::assertInstanceOf(Refused::class, $refused);
        self::assertSame(FailureReason::IDENTIFIER_UNVERIFIED, $refused->reason);
        self::assertSame($unverified, $refused->identity);
        self::assertNull($refused->principal);

        $unnamed = $admission->admit('api', $unverified, static fn (): ?Principal => null, FailureReason::PRINCIPAL_UNRESOLVED, null);

        self::assertInstanceOf(Refused::class, $unnamed);
        self::assertSame(FailureReason::PRINCIPAL_UNRESOLVED, $unnamed->reason);

        $verified = new StubVerifiableIdentity(2, ['email' => 'ada@example.com']);
        $verified->markIdentifierAsVerified('email', 'ada@example.com');

        $afterGate = $admission->admit('api', $verified, static fn (): ?Principal => null, FailureReason::PRINCIPAL_UNRESOLVED, 'email');

        self::assertInstanceOf(Refused::class, $afterGate);
        self::assertSame(FailureReason::PRINCIPAL_UNRESOLVED, $afterGate->reason);
    }

    /**
     * An unresolved principal is refused with the reason the caller gave for
     * it.
     *
     * @return void
     */
    public function testRefusesAnUnresolvedPrincipalWithTheCallersReason(): void
    {
        $identity = \Mockery::mock(Identity::class);

        $this->access->shouldNotReceive('mayUse');

        foreach ([FailureReason::PRINCIPAL_UNRESOLVED, FailureReason::PRINCIPAL_MISMATCH] as $reason) {

            $refused = $this->admission()->admit('api', $identity, static fn (): ?Principal => null, $reason, null);

            self::assertInstanceOf(Refused::class, $refused);
            self::assertSame($reason, $refused->reason);
            self::assertSame($identity, $refused->identity);
            self::assertNull($refused->principal);
        }
    }

    /**
     * An inactive principal is refused without its tenant being read or the
     * access contracts being asked.
     *
     * @return void
     */
    public function testRefusesAnInactivePrincipal(): void
    {
        $identity  = \Mockery::mock(Identity::class);
        $principal = \Mockery::mock(Principal::class, CanBeActive::class);
        $principal->shouldReceive('isActive')->once()->andReturnFalse();
        $principal->shouldNotReceive('getTenant');

        $this->access->shouldNotReceive('mayUse');

        $refused = $this->admission()->admit('api', $identity, static fn (): Principal => $principal, FailureReason::PRINCIPAL_UNRESOLVED, null);

        self::assertInstanceOf(Refused::class, $refused);
        self::assertSame(FailureReason::PRINCIPAL_INACTIVE, $refused->reason);
        self::assertSame($principal, $refused->principal);
        self::assertNull($refused->tenant);
    }

    /**
     * A principal whose own tenant is inactive is refused, carrying the
     * principal, before the access contracts are asked.
     *
     * @return void
     */
    public function testRefusesAPrincipalWhoseTenantIsInactive(): void
    {
        $identity  = \Mockery::mock(Identity::class);
        $principal = $this->principal(true, $this->tenant(false));

        $this->access->shouldNotReceive('mayUse');

        $refused = $this->admission()->admit('api', $identity, static fn (): Principal => $principal, FailureReason::PRINCIPAL_UNRESOLVED, null);

        self::assertInstanceOf(Refused::class, $refused);
        self::assertSame(FailureReason::TENANT_INACTIVE, $refused->reason);
        self::assertSame($identity, $refused->identity);
        self::assertSame($principal, $refused->principal);
        self::assertNull($refused->tenant);
    }

    /**
     * A principal `ApplicationAccess` refuses is refused as
     * `principal_ineligible` with the whole context.
     *
     * @return void
     */
    public function testRefusesAPrincipalTheApplicationAccessRefuses(): void
    {
        $identity  = \Mockery::mock(Identity::class);
        $tenant    = \Mockery::mock(Tenant::class);
        $principal = $this->principal(true, $tenant);

        $this->access->shouldReceive('mayUse')->once()->with('admin', $principal)->andReturnFalse();
        $this->tenants->shouldNotReceive('mayActIn');

        $refused = $this->admission()->admit('admin', $identity, static fn (): Principal => $principal, FailureReason::PRINCIPAL_UNRESOLVED, null);

        self::assertInstanceOf(Refused::class, $refused);
        self::assertSame(FailureReason::PRINCIPAL_INELIGIBLE, $refused->reason);
        self::assertSame($identity, $refused->identity);
        self::assertSame($principal, $refused->principal);
        self::assertSame($tenant, $refused->tenant);
        self::assertNull($refused->session);
        self::assertNull($refused->retryAfter);
    }

    /**
     * A selected tenant `TenantAccess` refuses is refused as
     * `tenant_ineligible`, naming no tenant.
     *
     * @return void
     */
    public function testRefusesATenantTheTenantAccessRefuses(): void
    {
        $identity  = \Mockery::mock(Identity::class);
        $own       = $this->tenant(true);
        $other     = \Mockery::mock(Tenant::class);
        $principal = $this->principal(true, $own);

        $own->shouldReceive('getTenantIdentifier')->andReturn('own');
        $other->shouldReceive('getTenantIdentifier')->andReturn('other');

        $this->resolver->shouldReceive('resolve')->once()->with('other')->andReturn($other);
        $this->tenants->shouldReceive('mayActIn')->twice()->andReturnFalse();

        foreach ([null, TenantSelection::of('other')] as $selection) {

            $refused = $this->admission()->admit('api', $identity, static fn (): Principal => $principal, FailureReason::PRINCIPAL_UNRESOLVED, null, $selection);

            self::assertInstanceOf(Refused::class, $refused);
            self::assertSame(FailureReason::TENANT_INELIGIBLE, $refused->reason);
            self::assertSame($principal, $refused->principal);
            self::assertNull($refused->tenant);
        }
    }

    /**
     * A sign-in is admitted in the tenant it names, or in no tenant when it
     * names none.
     *
     * @return void
     */
    public function testAdmitsInTheTenantTheSignInSelects(): void
    {
        $identity  = \Mockery::mock(Identity::class);
        $own       = $this->tenant(true);
        $other     = $this->tenant(true);
        $principal = $this->principal(true, $own);

        $own->shouldReceive('getTenantIdentifier')->andReturn('own');
        $other->shouldReceive('getTenantIdentifier')->andReturn('other');

        $this->resolver->shouldReceive('resolve')->once()->with('other')->andReturn($other);
        $this->tenants->shouldReceive('mayActIn')->once()->with($principal, $other)->andReturnTrue();
        $this->tenants->shouldReceive('mayActIn')->once()->with($principal, null)->andReturnTrue();

        $elsewhere = $this->admission()->admit('api', $identity, static fn (): Principal => $principal, FailureReason::PRINCIPAL_UNRESOLVED, null, TenantSelection::of('other'));
        $nowhere   = $this->admission()->admit('api', $identity, static fn (): Principal => $principal, FailureReason::PRINCIPAL_UNRESOLVED, null, TenantSelection::none());

        self::assertInstanceOf(Admitted::class, $elsewhere);
        self::assertSame($other, $elsewhere->tenant);
        self::assertInstanceOf(Admitted::class, $nowhere);
        self::assertNull($nowhere->tenant);
    }

    /**
     * The package's application policy over a configuration whose `api` guard
     * requires a verified identifier; it needs no token service to admit.
     *
     * @return \SineMacula\Laravel\Authentication\Applications\GuardApplicationPolicy
     */
    private function packagePolicy(): GuardApplicationPolicy
    {
        $config = new Repository([
            'auth'           => ['guards' => ['api' => ['driver' => 'jwt', 'application' => ['require_verified_identifier' => true]]]],
            'authentication' => ['application' => ['methods' => ['password'], 'require_verified_identifier' => false, 'client_secret_post' => false]],
        ]);

        return new GuardApplicationPolicy($config, (new \ReflectionClass(JwtTokenServiceFactory::class))->newInstanceWithoutConstructor());
    }

    /**
     * Build the admission over the application policy mock.
     *
     * @return \SineMacula\Laravel\Authentication\Admission\SignInAdmission
     */
    private function admission(): SignInAdmission
    {
        return new SignInAdmission($this->policy);
    }

    /**
     * Build an activatable principal reporting the given state and belonging to
     * the given tenant.
     *
     * @param  bool  $active
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Tenant  $tenant
     * @return \Mockery\MockInterface&\SineMacula\Laravel\Authentication\Contracts\Principal
     */
    private function principal(bool $active, ?Tenant $tenant): MockInterface
    {
        $principal = \Mockery::mock(Principal::class, CanBeActive::class);
        $principal->shouldReceive('isActive')->andReturn($active);
        $principal->shouldReceive('getTenant')->andReturn($tenant);

        return $principal;
    }

    /**
     * Build an activatable identity that reports inactive once.
     *
     * @return \Mockery\MockInterface&\SineMacula\Laravel\Authentication\Contracts\Identity
     */
    private function inactiveIdentity(): MockInterface
    {
        $identity = \Mockery::mock(Identity::class, CanBeActive::class);
        $identity->shouldReceive('isActive')->once()->andReturnFalse();

        return $identity;
    }

    /**
     * Build an activatable tenant that reports the given state.
     *
     * @param  bool  $active
     * @return \Mockery\MockInterface&\SineMacula\Laravel\Authentication\Contracts\Tenant
     */
    private function tenant(bool $active): MockInterface
    {
        $tenant = \Mockery::mock(Tenant::class, CanBeActive::class);
        $tenant->shouldReceive('isActive')->andReturn($active);

        return $tenant;
    }
}
