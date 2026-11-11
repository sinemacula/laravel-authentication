<?php

declare(strict_types = 1);

namespace Tests\Integration\Fixtures;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use SineMacula\Laravel\Authentication\Concerns\ActsAsTenant;
use SineMacula\Laravel\Authentication\Contracts\CanBeActive;
use SineMacula\Laravel\Authentication\Contracts\Tenant;

/**
 * Tenant that is active while it and its parent, if any, are.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @property int $id
 * @property ?int $parent_id
 * @property bool $is_active
 *
 * @internal
 */
final class ParentedTenant extends Model implements CanBeActive, Tenant
{
    use ActsAsTenant;

    /** @var string|null The table associated with the model. */
    protected $table = 'parented_tenants';

    /** @var array<string> The attributes that aren't mass assignable. */
    protected $guarded = [];

    /**
     * Whether the tenant and its parent, if any, are active.
     *
     * @return bool
     */
    #[\Override]
    public function isActive(): bool
    {
        $parent = $this->getAttribute('parent');

        return (bool) $this->getAttribute('is_active') && (!$parent instanceof self || $parent->isActive());
    }

    /**
     * The tenant this one belongs to.
     *
     * @formatter:off
     *
     * @return \Illuminate\Database\Eloquent\Relations\BelongsTo<\Tests\Integration\Fixtures\ParentedTenant, covariant $this>
     *
     * @formatter:on
     */
    public function parent(): BelongsTo
    {
        return $this->belongsTo(self::class, 'parent_id');
    }
}
