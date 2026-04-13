<?php

declare(strict_types = 1);

namespace Tests\Unit\Traits;

use Illuminate\Database\Eloquent\Model;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Traits\ActsAsTenant;

/**
 * Unit tests for the package ActsAsTenant trait.
 *
 * Exercises the public trait surface through anonymous Eloquent models without
 * relying on explicit PHPUnit coverage metadata for traits.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[\PHPUnit\Framework\Attributes\CoversNothing]
final class ActsAsTenantTest extends TestCase
{
    /**
     * Asserts the tenant identifier getter reads the model's `id` attribute
     * when no attribute-name override is supplied.
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
     * Asserts a subclass override of the protected `getTenantIdentifierName()`
     * hook is honoured by the public `getTenantIdentifier()` getter.
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
