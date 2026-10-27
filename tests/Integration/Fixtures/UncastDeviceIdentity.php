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

/**
 * 2D identity whose devices are `UncastDevice` rows, a custom device model
 * without a `datetime` cast on `revoked_at`.
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
final class UncastDeviceIdentity extends Model implements HasDevices, Identity, Principal
{
    use ActsAsPrincipal, Authenticatable, HasUuids;

    /** @var string|null The table associated with the model. */
    protected $table = 'uncast_device_identities';

    /** @var array<string> The attributes that aren't mass assignable. */
    protected $guarded = [];

    /**
     * The identity's devices through the polymorphic `authenticatable`
     * relation.
     *
     * @return \Illuminate\Database\Eloquent\Relations\MorphMany<\Tests\Integration\Fixtures\UncastDevice, $this>
     */
    #[\Override]
    public function devices(): MorphMany
    {
        return $this->morphMany(UncastDevice::class, 'authenticatable');
    }
}
