<?php

declare(strict_types = 1);

namespace Tests\Integration\Fixtures;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Concerns\ActsAsTenant;
use SineMacula\Laravel\Authentication\Concerns\ProvidesActiveState;
use SineMacula\Laravel\Authentication\Contracts\CanBeActive;
use SineMacula\Laravel\Authentication\Contracts\Tenant;

/**
 * Tenant fixture that opts into activation and lives on the separate `landlord`
 * connection rather than the default one its members use.
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
final class LandlordTenant extends Model implements CanBeActive, Tenant
{
    use ActsAsTenant, ProvidesActiveState;

    /** @var string|\UnitEnum|null The database connection for the model. */
    protected $connection = 'landlord';

    /** @var string|null The table associated with the model. */
    protected $table = 'landlord_tenants';

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
