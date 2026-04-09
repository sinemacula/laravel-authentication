<?php

declare(strict_types = 1);

namespace Tests\Unit\Traits;

use Illuminate\Database\Eloquent\Model;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Traits\ActsAsTenant;

/**
 * Unit tests for the package ActsAsTenant trait.
 *
 * Marked `#[CoversNothing]` so phpunit does not attribute the
 * trait's runtime behaviour to a single concrete class - the
 * trait's real consumers carry their own coverage via the
 * integration suites.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 *
 * @internal
 */
#[CoversNothing]
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
}
