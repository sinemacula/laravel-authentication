<?php

declare(strict_types = 1);

namespace Tests\Integration\Fixtures;

use Illuminate\Contracts\Database\Eloquent\Builder as BuilderContract;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Concerns\ActsAsPrincipal;
use SineMacula\Laravel\Authentication\Concerns\Authenticatable;
use SineMacula\Laravel\Authentication\Concerns\ProvidesActiveState;
use SineMacula\Laravel\Authentication\Contracts\CanBeActive;
use SineMacula\Laravel\Authentication\Contracts\HasDevices;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Models\Device;

/**
 * 2D identity that opts into activation from its `is_active` column but whose
 * global scope selects only the sign-in columns, as an application narrowing
 * its user queries might, so every lookup loads it without the flag.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @property int $id
 * @property string $email
 * @property string $password
 *
 * @internal
 */
final class PartiallySelectedIdentity extends Model implements CanBeActive, HasDevices, Identity, Principal
{
    use ActsAsPrincipal, Authenticatable, ProvidesActiveState;

    /** @var string|null The table associated with the model. */
    protected $table = 'partially_selected_identities';

    /** @var array<string> The attributes that aren't mass assignable. */
    protected $guarded = [];

    /**
     * Eloquent relation builder for the identity's devices.
     *
     * @return \Illuminate\Contracts\Database\Eloquent\Builder
     */
    #[\Override]
    public function devices(): BuilderContract
    {
        return Device::query()
            ->where('authenticatable_type', self::class)
            ->where('authenticatable_id', (string) $this->getKey()); // @phpstan-ignore cast.string
    }

    /**
     * Narrow every query to the sign-in columns.
     *
     * @return void
     */
    #[\Override]
    protected static function booted(): void
    {
        self::addGlobalScope('sign_in_columns', static function (Builder $query): void {
            $query->select(['id', 'email', 'password']);
        });
    }
}
