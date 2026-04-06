<?php

declare(strict_types=1);

namespace Tests\Integration\Fixtures;

use Illuminate\Contracts\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Contracts\HasDevices;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Models\Device;
use SineMacula\Laravel\Authentication\Traits\ActsAsPrincipal;
use SineMacula\Laravel\Authentication\Traits\Authenticatable;

/**
 * Minimal Eloquent fixture used by the integration tests.
 *
 * Implements `Identity` and `Principal` so the package guards can
 * operate in 2D mode, and `HasDevices` so the JwtGuard's device-hint
 * resolution path has a real relation to query against the shipped
 * Device model. Tests create rows in the backing `integration_identities`
 * table (seeded in `Tests\TestCase::defineDatabaseMigrations()`).
 *
 * @author    Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright 2026 Sine Macula Limited.
 *
 * @property int         $id
 * @property string      $email
 * @property string      $password
 * @property bool        $is_active
 *
 * @internal
 */
final class IntegrationIdentity extends Model implements Identity, Principal, HasDevices
{
    use ActsAsPrincipal;
    use Authenticatable;

    /** @var string|null The table associated with the model. */
    protected $table = 'integration_identities';

    /** @var array<string> The attributes that aren't mass assignable. */
    protected $guarded = [];

    /** @var array<string, string> The attributes that should be cast. */
    protected $casts = [
        'is_active' => 'boolean',
    ];

    /**
     * Eloquent relation builder for the identity's devices.
     *
     * Filters the shipped Device model by the polymorphic
     * authenticatable columns so `JwtGuard::resolveDeviceFromHint()`
     * can resolve a device by its id through a real query.
     */
    public function devices(): Builder
    {
        return Device::query()
            ->where('authenticatable_type', static::class)
            ->where('authenticatable_id', (string) $this->getKey());
    }
}
