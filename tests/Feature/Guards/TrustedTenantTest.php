<?php

declare(strict_types = 1);

namespace Tests\Feature\Guards;

use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use Mockery\MockInterface;
use Orchestra\Testbench\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\AuthenticationServiceProvider;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\Session;
use SineMacula\Laravel\Authentication\Contracts\TenantAccess;
use SineMacula\Laravel\Authentication\Contracts\TenantResolver;
use SineMacula\Laravel\Authentication\Exceptions\TenantUnavailableException;
use SineMacula\Laravel\Authentication\Guards\TrustedTenant;
use Tests\Unit\Stubs\PlainPrincipalFixture;
use Tests\Unit\Stubs\PlainTenantFixture;

/**
 * Feature tests for the active tenant a trusted bind gives a principal.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(TrustedTenant::class)]
final class TrustedTenantTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    /** @var \Mockery\MockInterface&\SineMacula\Laravel\Authentication\Contracts\TenantResolver The resolver a recorded tenant is named through. */
    private MockInterface $resolver;

    /**
     * Bind a tenant resolver mock and an access that is never asked.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->resolver = \Mockery::mock(TenantResolver::class);

        $access = \Mockery::mock(TenantAccess::class);
        $access->shouldNotReceive('mayActIn');

        $this->app?->instance(TenantResolver::class, $this->resolver);
        $this->app?->instance(TenantAccess::class, $access);
    }

    /**
     * Without a session the tenant is the principal's own, or none.
     *
     * @return void
     */
    public function testWithoutASessionTheTenantIsThePrincipalsOwn(): void
    {
        $own = new PlainTenantFixture(7);

        $this->resolver->shouldNotReceive('resolve');

        self::assertSame($own, TrustedTenant::of(new PlainPrincipalFixture(1, tenant: $own), null));
        self::assertNull(TrustedTenant::of(new PlainPrincipalFixture(2), null));
    }

    /**
     * Without a session an own tenant that cannot be loaded is returned as the
     * reason, not thrown.
     *
     * @return void
     */
    public function testWithoutASessionAnUnavailableOwnTenantIsReturned(): void
    {
        $unavailable = new TenantUnavailableException('The tenant is gone.');

        self::assertSame($unavailable, TrustedTenant::of(self::unavailablePrincipal($unavailable), null));
    }

    /**
     * A session that records no tenant gives none, even to a principal with its
     * own.
     *
     * @return void
     */
    public function testASessionRecordingNoTenantGivesNone(): void
    {
        $this->resolver->shouldNotReceive('resolve');

        self::assertNull(TrustedTenant::of(new PlainPrincipalFixture(1, tenant: new PlainTenantFixture(7)), self::recording(null)));
    }

    /**
     * A recorded tenant is the principal's own without the resolver, or one the
     * resolver finds.
     *
     * @return void
     */
    public function testARecordedTenantIsTheOwnOrTheResolved(): void
    {
        $own       = new PlainTenantFixture(7);
        $principal = new PlainPrincipalFixture(1, tenant: $own);
        $resolved  = new PlainTenantFixture(9);

        $this->resolver->shouldReceive('resolve')->once()->with('9')->andReturn($resolved);

        self::assertSame($own, TrustedTenant::of($principal, self::recording('7')));
        self::assertSame($resolved, TrustedTenant::of($principal, self::recording('9')));
    }

    /**
     * A recorded tenant that no longer resolves is returned as a reason naming
     * it.
     *
     * @return void
     */
    public function testARecordedTenantThatNoLongerResolvesIsUnavailable(): void
    {
        $this->resolver->shouldReceive('resolve')->once()->with('gone')->andReturnNull();

        $tenant = TrustedTenant::of(new PlainPrincipalFixture(1, tenant: new PlainTenantFixture(7)), self::recording('gone'));

        self::assertInstanceOf(TenantUnavailableException::class, $tenant);
        self::assertSame('The tenant gone the bound session records cannot be resolved.', $tenant->getMessage());
    }

    /**
     * When the principal's own tenant cannot be loaded, a recorded tenant the
     * resolver finds is given, and one it does not find gives the own reason.
     *
     * @return void
     */
    public function testAnUnavailableOwnTenantIsTheReasonARecordedOneCannotBeNamed(): void
    {
        $unavailable = new TenantUnavailableException('The tenant is gone.');
        $principal   = self::unavailablePrincipal($unavailable);
        $resolved    = new PlainTenantFixture(9);

        $this->resolver->shouldReceive('resolve')->once()->with('7')->andReturnNull();
        $this->resolver->shouldReceive('resolve')->once()->with('9')->andReturn($resolved);

        self::assertSame($unavailable, TrustedTenant::of($principal, self::recording('7')));
        self::assertSame($resolved, TrustedTenant::of($principal, self::recording('9')));
    }

    /**
     * The class is a static utility that cannot be instantiated from outside.
     *
     * @return void
     */
    public function testConstructorIsPrivate(): void
    {
        $reflection  = new \ReflectionClass(TrustedTenant::class);
        $constructor = $reflection->getConstructor();

        self::assertNotNull($constructor);
        self::assertTrue($constructor->isPrivate());

        $instance = $reflection->newInstanceWithoutConstructor();
        $constructor->invoke($instance);

        self::assertInstanceOf(TrustedTenant::class, $instance);
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
     * A principal whose own tenant throws the reason given.
     *
     * @param  \SineMacula\Laravel\Authentication\Exceptions\TenantUnavailableException  $unavailable
     * @return \Mockery\MockInterface&\SineMacula\Laravel\Authentication\Contracts\Principal
     */
    private static function unavailablePrincipal(TenantUnavailableException $unavailable): MockInterface
    {
        $principal = \Mockery::mock(Principal::class);
        $principal->shouldReceive('getTenant')->andThrow($unavailable);

        return $principal;
    }

    /**
     * A session that records the tenant given.
     *
     * @param  ?string  $tenantId
     * @return \Mockery\MockInterface&\SineMacula\Laravel\Authentication\Contracts\Session
     */
    private static function recording(?string $tenantId): MockInterface
    {
        $session = \Mockery::mock(Session::class);
        $session->shouldReceive('getTenantId')->andReturn($tenantId);

        return $session;
    }
}
