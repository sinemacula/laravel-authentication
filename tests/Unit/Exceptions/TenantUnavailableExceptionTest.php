<?php

declare(strict_types = 1);

namespace Tests\Unit\Exceptions;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Exceptions\TenantUnavailableException;
use Tests\Unit\Stubs\StubActivatableTenant;
use Tests\Unit\Stubs\StubTenant;

/**
 * Unit tests for telling which tenant a principal names when that tenant cannot
 * be loaded.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(TenantUnavailableException::class)]
final class TenantUnavailableExceptionTest extends TestCase
{
    /**
     * The exception is for a tenant model of the named class holding the named
     * key under the named attribute, compared as identifiers are, and for no
     * other.
     *
     * @return void
     */
    public function testIsForTheTenantOfTheNamedClassAndKey(): void
    {
        $exception = new TenantUnavailableException('gone', StubTenant::class, 'id', 7);

        self::assertSame('gone', $exception->getMessage());
        self::assertTrue($exception->isFor(self::tenant(StubTenant::class, ['id' => '7'])));
        self::assertFalse($exception->isFor(self::tenant(StubTenant::class, ['id' => 8])));
        self::assertFalse($exception->isFor(self::tenant(StubTenant::class, ['uuid' => 7])));
        self::assertFalse($exception->isFor(self::tenant(StubActivatableTenant::class, ['id' => 7])));
    }

    /**
     * Without a reference, as a principal whose relation cannot say throws it,
     * it is for no tenant.
     *
     * @return void
     */
    public function testWithoutAReferenceItIsForNoTenant(): void
    {
        self::assertFalse((new TenantUnavailableException('gone'))->isFor(self::tenant(StubTenant::class, ['id' => 7])));
        self::assertFalse((new TenantUnavailableException('gone', StubTenant::class, null, 7))->isFor(self::tenant(StubTenant::class, ['id' => 7])));
    }

    /**
     * A tenant that is not an Eloquent model holds no key to compare.
     *
     * @return void
     */
    public function testATenantThatIsNotAModelIsNotMatched(): void
    {
        $tenant = new class implements Tenant {
            /**
             * The tenant identifier.
             *
             * @return mixed
             */
            #[\Override]
            public function getTenantIdentifier(): mixed
            {
                return 7;
            }
        };

        self::assertFalse((new TenantUnavailableException('gone', $tenant::class, 'id', 7))->isFor($tenant));
    }

    /**
     * A tenant model of the class holding the attributes.
     *
     * @param  class-string<\Tests\Unit\Stubs\StubTenant>  $class
     * @param  array<string, mixed>  $attributes
     * @return \Tests\Unit\Stubs\StubTenant
     */
    private static function tenant(string $class, array $attributes): StubTenant
    {
        $tenant = new $class;
        $tenant->setRawAttributes($attributes, true);

        return $tenant;
    }
}
