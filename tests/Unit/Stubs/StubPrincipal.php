<?php

declare(strict_types = 1);

namespace Tests\Unit\Stubs;

use Illuminate\Contracts\Database\Eloquent\Builder as BuilderContract;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Contracts\HasDevices;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Models\Device;
use SineMacula\Laravel\Authentication\Traits\ActsAsPrincipal;
use SineMacula\Laravel\Authentication\Traits\Authenticatable;

/**
 * Eloquent stub implementing Principal (and Identity for 2D mode)
 * via the package's ActsAsPrincipal trait.
 *
 * Also implements `HasDevices` so JWT integration tests can resolve
 * a device from a token hint via the polymorphic devices table.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 *
 * @property int $id
 * @property string $email
 * @property string $password
 * @property bool $is_active
 *
 * @internal
 */
class StubPrincipal extends Model implements HasDevices, Identity, Principal
{
    use ActsAsPrincipal;
    use Authenticatable;

    /** @var string|null The table associated with the model. */
    protected $table = 'stub_principals';

    /** @var array<string> The attributes that aren't mass assignable. */
    protected $guarded = [];

    /**
     * Eloquent relation builder for the identity's devices, filtered
     * by the polymorphic `authenticatable_*` columns on the shipped
     * Device model.
     *
     * @return \Illuminate\Contracts\Database\Eloquent\Builder
     */
    public function devices(): BuilderContract
    {
        return Device::query()
            ->where('authenticatable_type', static::class)
            ->where('authenticatable_id', (string) $this->getKey()); // @phpstan-ignore cast.string
    }
}
