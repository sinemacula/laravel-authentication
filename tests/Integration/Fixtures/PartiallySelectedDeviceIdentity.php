<?php

declare(strict_types = 1);

namespace Tests\Integration\Fixtures;

use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\MorphMany;
use SineMacula\Laravel\Authentication\Concerns\ActsAsPrincipal;
use SineMacula\Laravel\Authentication\Concerns\Authenticatable;
use SineMacula\Laravel\Authentication\Contracts\HasDevices;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Models\Device;

/**
 * 2D identity whose `devices()` relation selects only some device columns,
 * leaving out `revoked_at`, as an application narrowing the relation might.
 *
 * Keyed by UUID so the polymorphic `authenticatable_id` string column compares
 * against a string key on every database driver.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @property string $id
 * @property string $email
 * @property string $password
 *
 * @internal
 */
final class PartiallySelectedDeviceIdentity extends Model implements HasDevices, Identity, Principal
{
    use ActsAsPrincipal, Authenticatable, HasUuids;

    /** @var string|null The table associated with the model. */
    protected $table = 'partially_selected_device_identities';

    /** @var array<string> The attributes that aren't mass assignable. */
    protected $guarded = [];

    /**
     * The identity's devices, loaded without their revocation column.
     *
     * @return \Illuminate\Database\Eloquent\Relations\MorphMany<\SineMacula\Laravel\Authentication\Models\Device, $this>
     */
    #[\Override]
    public function devices(): MorphMany
    {
        return $this->morphMany(Device::class, 'authenticatable')
            ->select(['id', 'authenticatable_type', 'authenticatable_id', 'client_name']);
    }
}
