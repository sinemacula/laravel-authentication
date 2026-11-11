<?php

declare(strict_types = 1);

namespace Tests\Integration\Fixtures;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Concerns\ActsAsTenant;
use SineMacula\Laravel\Authentication\Contracts\Tenant;

/**
 * Second tenant type for a service account's membership, whose keys can equal
 * an `ActivatableTenant`'s.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @property int $id
 * @property string $name
 *
 * @internal
 */
final class MachineWorkspace extends Model implements Tenant
{
    use ActsAsTenant;

    /** @var string|null The table associated with the model. */
    protected $table = 'machine_workspaces';

    /** @var array<string> The attributes that aren't mass assignable. */
    protected $guarded = [];
}
