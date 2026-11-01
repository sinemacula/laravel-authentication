<?php

declare(strict_types = 1);

namespace Tests\Integration\Fixtures;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Concerns\ActsAsTenant;
use SineMacula\Laravel\Authentication\Contracts\Tenant;

/**
 * Tenant fixture with a `category` column the package never reads.
 *
 * @property int $id
 * @property ?string $category
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class TypedTenant extends Model implements Tenant
{
    use ActsAsTenant;

    /** @var string|null The table associated with the model. */
    protected $table = 'typed_tenants';

    /** @var array<string> The attributes that aren't mass assignable. */
    protected $guarded = [];
}
