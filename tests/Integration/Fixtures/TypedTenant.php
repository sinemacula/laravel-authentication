<?php

declare(strict_types = 1);

namespace Tests\Integration\Fixtures;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Concerns\ActsAsTenant;
use SineMacula\Laravel\Authentication\Concerns\ProvidesType;
use SineMacula\Laravel\Authentication\Contracts\HasType;
use SineMacula\Laravel\Authentication\Contracts\Tenant;

/**
 * Tenant fixture whose type, in its `category` column, its memberships fall
 * back to when they declare none.
 *
 * @property int $id
 * @property ?string $category
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class TypedTenant extends Model implements HasType, Tenant
{
    use ActsAsTenant, ProvidesType;

    /** @var string|null The table associated with the model. */
    protected $table = 'typed_tenants';

    /** @var array<string> The attributes that aren't mass assignable. */
    protected $guarded = [];

    /**
     * Column name holding the tenant's type.
     *
     * @return string
     */
    protected function getTypeAttributeName(): string
    {
        return 'category';
    }
}
