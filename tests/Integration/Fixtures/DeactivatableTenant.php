<?php

declare(strict_types = 1);

namespace Tests\Integration\Fixtures;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Concerns\ActsAsTenant;
use SineMacula\Laravel\Authentication\Concerns\ProvidesDeactivationTime;
use SineMacula\Laravel\Authentication\Contracts\CanBeActive;
use SineMacula\Laravel\Authentication\Contracts\Tenant;

/**
 * Tenant fixture, over the `deactivatable_tenants` rows, that records its
 * deactivation in `deactivated_at`, read as stored, without a cast.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @property int $id
 * @property string $name
 * @property ?string $deactivated_at
 *
 * @internal
 */
final class DeactivatableTenant extends Model implements CanBeActive, Tenant
{
    use ActsAsTenant, ProvidesDeactivationTime;

    /** @var string|null The table associated with the model. */
    protected $table = 'deactivatable_tenants';

    /** @var array<string> The attributes that aren't mass assignable. */
    protected $guarded = [];
}
