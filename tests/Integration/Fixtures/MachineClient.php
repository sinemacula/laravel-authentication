<?php

declare(strict_types = 1);

namespace Tests\Integration\Fixtures;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Concerns\ActsAsPrincipal;
use SineMacula\Laravel\Authentication\Concerns\Authenticatable;
use SineMacula\Laravel\Authentication\Concerns\ProvidesActiveState;
use SineMacula\Laravel\Authentication\Contracts\CanBeActive;
use SineMacula\Laravel\Authentication\Contracts\MachineIdentity;
use SineMacula\Laravel\Authentication\Contracts\Principal;

/**
 * A non-human identity (an API client) that acts as its own principal, stored
 * in `machine_clients`. It has a password column only so the tests can prove a
 * machine is refused even when a password happens to match.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @property int $id
 * @property string $email
 * @property ?string $password
 * @property bool $is_active
 *
 * @internal
 */
final class MachineClient extends Model implements CanBeActive, MachineIdentity, Principal
{
    use ActsAsPrincipal, Authenticatable, ProvidesActiveState;

    /** @var string|null The table associated with the model. */
    protected $table = 'machine_clients';

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
