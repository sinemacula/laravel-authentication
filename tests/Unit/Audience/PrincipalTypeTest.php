<?php

declare(strict_types = 1);

namespace Tests\Unit\Audience;

use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Audience\PrincipalType;
use SineMacula\Laravel\Authentication\Contracts\HasType;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Exceptions\TenantUnavailableException;
use Tests\Unit\Stubs\PlainPrincipalFixture;
use Tests\Unit\Stubs\StubTenant;

/**
 * Unit tests for reading a principal's type: its own, else its tenant's.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PrincipalType::class)]
final class PrincipalTypeTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    /**
     * A principal that reports a type of its own has that type, and its tenant
     * is never loaded, so a typed principal costs no tenant query.
     *
     * @return void
     */
    public function testPrincipalsOwnTypeWinsWithoutLoadingTheTenant(): void
    {
        $principal = \Mockery::mock(Principal::class, HasType::class);
        $principal->shouldReceive('getType')->once()->andReturn('client_admin');
        $principal->shouldNotReceive('getTenant');

        self::assertSame('client_admin', PrincipalType::of($principal));
    }

    /**
     * A principal without the capability takes the type of the tenant it acts
     * within.
     *
     * @return void
     */
    public function testUntypedPrincipalFallsBackToItsTenantsType(): void
    {
        self::assertSame('staff', PrincipalType::of(new PlainPrincipalFixture(1, tenant: $this->tenantOfType('staff'))));
    }

    /**
     * A principal that declares the capability but reports an empty type (an
     * empty type column) declares none, so its tenant's type applies.
     *
     * @return void
     */
    public function testPrincipalReportingAnEmptyTypeFallsBackToItsTenantsType(): void
    {
        $principal = \Mockery::mock(Principal::class, HasType::class);
        $principal->shouldReceive('getType')->once()->andReturn('');
        $principal->shouldReceive('getTenant')->once()->andReturn($this->tenantOfType('customer'));

        self::assertSame('customer', PrincipalType::of($principal));
    }

    /**
     * Neither the principal nor its tenant declaring a type, a tenant reporting
     * an empty one, and no tenant at all each read as no type.
     *
     * @return void
     */
    public function testNoTypeAnywhereReadsAsNull(): void
    {
        $untypedTenant = \Mockery::mock(Tenant::class);

        self::assertNull(PrincipalType::of(new PlainPrincipalFixture(1)));
        self::assertNull(PrincipalType::of(new PlainPrincipalFixture(1, tenant: $untypedTenant)));
        self::assertNull(PrincipalType::of(new PlainPrincipalFixture(1, tenant: $this->tenantOfType(''))));
    }

    /**
     * A tenant that cannot be loaded surfaces as `getTenant()` reports it, so a
     * type is never read from a principal whose tenant is unknown.
     *
     * @return void
     */
    public function testTenantExceptionsPropagate(): void
    {
        $unavailable = \Mockery::mock(Principal::class);
        $unavailable->shouldReceive('getTenant')->andThrow(new TenantUnavailableException('gone'));

        $unloaded = \Mockery::mock(Principal::class);
        $unloaded->shouldReceive('getTenant')->andThrow(new \LogicException('not loaded'));

        $this->assertThrowsWith(TenantUnavailableException::class, 'gone', static fn (): ?string => PrincipalType::of($unavailable));
        $this->assertThrowsWith(\LogicException::class, 'not loaded', static fn (): ?string => PrincipalType::of($unloaded));
    }

    /**
     * `PrincipalType` is a static utility; instantiation is disallowed via the
     * private constructor. Reflection invokes the private constructor so the
     * line is covered while still documenting the access modifier.
     *
     * @return void
     *
     * @SuppressWarnings("php:S3011")
     */
    public function testConstructorIsPrivate(): void
    {
        $reflection  = new \ReflectionClass(PrincipalType::class);
        $constructor = $reflection->getConstructor();

        self::assertNotNull($constructor);
        self::assertTrue($constructor->isPrivate());

        $instance = $reflection->newInstanceWithoutConstructor();
        $constructor->invoke($instance);

        self::assertInstanceOf(PrincipalType::class, $instance);
    }

    /**
     * Build a typed tenant model reporting the supplied type.
     *
     * @param  string  $type
     * @return \Tests\Unit\Stubs\StubTenant
     */
    private function tenantOfType(string $type): StubTenant
    {
        $tenant = new StubTenant;
        $tenant->setRawAttributes(['type' => $type]);

        return $tenant;
    }

    /**
     * Assert the callback throws exactly the given exception class with the
     * given message.
     *
     * @param  class-string<\Throwable>  $class
     * @param  string  $message
     * @param  \Closure(): mixed  $callback
     * @return void
     */
    private function assertThrowsWith(string $class, string $message, \Closure $callback): void
    {
        try {
            $callback();
        } catch (\Throwable $e) {
            self::assertSame($class, $e::class);
            self::assertSame($message, $e->getMessage());

            return;
        }

        self::fail("Expected {$class} to be thrown.");
    }
}
