<?php

declare(strict_types = 1);

namespace Tests\Integration\Fixtures;

use Illuminate\Contracts\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Concerns\ActsAsPrincipal;
use SineMacula\Laravel\Authentication\Concerns\Authenticatable;
use SineMacula\Laravel\Authentication\Concerns\ProvidesActiveState;
use SineMacula\Laravel\Authentication\Concerns\ProvidesTokensValidAfter;
use SineMacula\Laravel\Authentication\Contracts\CanBeActive;
use SineMacula\Laravel\Authentication\Contracts\HasDevices;
use SineMacula\Laravel\Authentication\Contracts\HasTokensValidAfter;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Models\Device;

/**
 * Activatable 2D identity that records, through `ProvidesTokensValidAfter`,
 * when its access tokens issued without a device become valid, in the
 * `tokens_valid_after` column of `active_cutoff_identities`, and owns devices
 * of the shipped model.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @property int $id
 * @property string $email
 * @property string $password
 * @property bool $is_active
 * @property ?\Carbon\CarbonInterface $tokens_valid_after
 *
 * @internal
 */
final class ActiveCutoffIdentity extends Model implements CanBeActive, HasDevices, HasTokensValidAfter, Identity, Principal
{
    use ActsAsPrincipal, Authenticatable, ProvidesActiveState, ProvidesTokensValidAfter;

    /** @var string|null The table associated with the model. */
    protected $table = 'active_cutoff_identities';

    /** @var array<string> The attributes that aren't mass assignable. */
    protected $guarded = [];

    /**
     * The identity's devices of the shipped model.
     *
     * @return \Illuminate\Contracts\Database\Eloquent\Builder
     */
    #[\Override]
    public function devices(): Builder
    {
        return Device::query()
            ->where('authenticatable_type', self::class)
            ->where('authenticatable_id', (string) $this->id);
    }

    /**
     * The attributes that should be cast.
     *
     * @return array<string, string>
     */
    #[\Override]
    protected function casts(): array
    {
        return [
            'is_active'          => 'boolean',
            'tokens_valid_after' => 'datetime',
        ];
    }
}
