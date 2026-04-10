<?php

declare(strict_types = 1);

namespace Tests\Unit\Traits;

use Illuminate\Database\Eloquent\Model;
use PHPUnit\Framework\Attributes\CoversMethod;
use PHPUnit\Framework\Attributes\CoversTrait;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Traits\ActsAsTenant;

/**
 * Unit tests for the package ActsAsTenant trait.
 *
 * The companion `#[CoversMethod]` attribute satisfies the
 * `php_unit_test_class_requires_covers` formatter rule (older
 * php-cs-fixer releases do not yet recognise the `CoversTrait`
 * attribute on its own). The `#[CoversTrait]` attribute is what
 * actually drives PHPUnit's coverage attribution for the trait.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 *
 * @internal
 */
#[CoversMethod(ActsAsTenant::class, 'getTenantIdentifier')]
#[CoversTrait(ActsAsTenant::class)]
final class ActsAsTenantTest extends TestCase
{
    /**
     * Asserts the tenant identifier getter reads the model's `id`
     * attribute when no attribute-name override is supplied.
     *
     * @return void
     */
    public function testGetTenantIdentifierReturnsIdAttribute(): void
    {
        $tenant = new class extends Model {
            use ActsAsTenant;

            /** @var bool Indicates whether the IDs are auto-incrementing. */
            public $incrementing = false;

            /** @var string The "type" of the primary key ID. */
            protected $keyType = 'string';

            /** @var array<string> Mass-assignment guard list. */
            protected $guarded = [];
        };

        $tenant->setRawAttributes(['id' => 'tenant-123']);

        self::assertSame('tenant-123', $tenant->getTenantIdentifier());
    }

    /**
     * Asserts a subclass override of the protected
     * `getTenantIdentifierName()` hook is honoured by the public
     * `getTenantIdentifier()` getter.
     *
     * @return void
     */
    public function testGetTenantIdentifierHonoursAttributeNameOverride(): void
    {
        $tenant = new class extends Model {
            use ActsAsTenant;

            /** @var bool Indicates whether the IDs are auto-incrementing. */
            public $incrementing = false;

            /** @var string The "type" of the primary key ID. */
            protected $keyType = 'string';

            /** @var array<string> Mass-assignment guard list. */
            protected $guarded = [];

            /**
             * Source the tenant identifier from a different column.
             *
             * @return string
             */
            protected function getTenantIdentifierName(): string
            {
                return 'tenant_uuid';
            }
        };

        $tenant->setRawAttributes(['tenant_uuid' => 'tenant-from-override']);

        self::assertSame('tenant-from-override', $tenant->getTenantIdentifier());
    }
}
