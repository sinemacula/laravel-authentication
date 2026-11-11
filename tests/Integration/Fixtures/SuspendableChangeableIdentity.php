<?php

declare(strict_types = 1);

namespace Tests\Integration\Fixtures;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Casts\NormalizedIdentifier;
use SineMacula\Laravel\Authentication\Concerns\ActsAsPrincipal;
use SineMacula\Laravel\Authentication\Concerns\Authenticatable;
use SineMacula\Laravel\Authentication\Concerns\ProvidesActiveState;
use SineMacula\Laravel\Authentication\Concerns\ProvidesIdentifierChanges;
use SineMacula\Laravel\Authentication\Contracts\CanBeActive;
use SineMacula\Laravel\Authentication\Contracts\HasChangeableIdentifiers;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;

/**
 * 2D identity whose identifiers can be changed and that can be deactivated
 * through `is_active`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @property int $id
 * @property ?string $email
 * @property ?string $phone
 * @property bool $is_active
 *
 * @internal
 */
final class SuspendableChangeableIdentity extends Model implements CanBeActive, HasChangeableIdentifiers, Identity, Principal
{
    use ActsAsPrincipal, Authenticatable, ProvidesActiveState, ProvidesIdentifierChanges;

    /** @var string|null The table associated with the model. */
    protected $table = 'changeable_identities';

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
            'email'             => NormalizedIdentifier::using('email'),
            'email_verified_at' => 'datetime',
            'phone'             => NormalizedIdentifier::using('phone'),
            'phone_verified_at' => 'datetime',
            'is_active'         => 'boolean',
        ];
    }
}
