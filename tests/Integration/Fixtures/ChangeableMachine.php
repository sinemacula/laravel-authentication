<?php

declare(strict_types = 1);

namespace Tests\Integration\Fixtures;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Concerns\ActsAsPrincipal;
use SineMacula\Laravel\Authentication\Concerns\Authenticatable;
use SineMacula\Laravel\Authentication\Concerns\ProvidesIdentifierChanges;
use SineMacula\Laravel\Authentication\Contracts\HasChangeableIdentifiers;
use SineMacula\Laravel\Authentication\Contracts\MachineIdentity;
use SineMacula\Laravel\Authentication\Contracts\Principal;

/**
 * A non-human identity that, though it can report and replace identifiers in
 * `changeable_identities`, must never have one changed: it has no interactive
 * identifiers.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @property int $id
 *
 * @internal
 */
final class ChangeableMachine extends Model implements HasChangeableIdentifiers, MachineIdentity, Principal
{
    use ActsAsPrincipal, Authenticatable, ProvidesIdentifierChanges;

    /** @var string|null The table associated with the model. */
    protected $table = 'changeable_identities';

    /** @var array<string> The attributes that aren't mass assignable. */
    protected $guarded = [];
}
