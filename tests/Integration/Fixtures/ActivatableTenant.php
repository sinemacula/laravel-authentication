<?php

declare(strict_types = 1);

namespace Tests\Integration\Fixtures;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\SoftDeletes;
use SineMacula\Laravel\Authentication\Concerns\ActsAsTenant;
use SineMacula\Laravel\Authentication\Concerns\ProvidesActiveState;
use SineMacula\Laravel\Authentication\Contracts\CanBeActive;
use SineMacula\Laravel\Authentication\Contracts\Tenant;

/**
 * Tenant fixture that opts into activation through its `is_active` column and
 * is soft-deletable.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @property int $id
 * @property string $name
 * @property bool $is_active
 *
 * @internal
 */
final class ActivatableTenant extends Model implements CanBeActive, Tenant
{
    use ActsAsTenant, ProvidesActiveState, SoftDeletes;

    /** @var string|null The table associated with the model. */
    protected $table = 'activatable_tenants';

    /** @var array<string> The attributes that aren't mass assignable. */
    protected $guarded = [];

    /**
     * The attributes that should be cast.
     *
     * @return array<string, string>
     */
    #[\Override]
    protected function casts(): array
    {
        return [
            'is_active' => 'boolean',
        ];
    }
}
