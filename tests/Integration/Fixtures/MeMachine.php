<?php

declare(strict_types = 1);

namespace Tests\Integration\Fixtures;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Concerns\ActsAsPrincipal;
use SineMacula\Laravel\Authentication\Concerns\Authenticatable;
use SineMacula\Laravel\Authentication\Concerns\ResolvesMeRouteBinding;
use SineMacula\Laravel\Authentication\Contracts\MachineIdentity;
use SineMacula\Laravel\Authentication\Contracts\Principal;

/**
 * Non-human identity fixture for the `me` route binding, over the
 * `machine_clients` rows: its own principal, authenticated by API key.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class MeMachine extends Model implements MachineIdentity, Principal
{
    use ActsAsPrincipal, Authenticatable, ResolvesMeRouteBinding;

    /** @var string|null The table associated with the model. */
    protected $table = 'machine_clients';

    /** @var array<string> The attributes that aren't mass assignable. */
    protected $guarded = [];
}
