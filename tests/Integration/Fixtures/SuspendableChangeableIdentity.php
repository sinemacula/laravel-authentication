<?php

declare(strict_types = 1);

namespace Tests\Integration\Fixtures;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Casts\NormalisedIdentifier;
use SineMacula\Laravel\Authentication\Concerns\ActsAsPrincipal;
use SineMacula\Laravel\Authentication\Concerns\Authenticatable;
use SineMacula\Laravel\Authentication\Concerns\ProvidesActiveState;
use SineMacula\Laravel\Authentication\Concerns\ProvidesIdentifierVerification;
use SineMacula\Laravel\Authentication\Contracts\CanBeActive;
use SineMacula\Laravel\Authentication\Contracts\HasChangeableIdentifiers;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;

/**
 * 2D identity fixture over `changeable_identities` whose identifiers can be
 * changed and which can be deactivated, through its `is_active` column, so a
 * change requested while it was active can be confirmed after it is not.
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
    use ActsAsPrincipal, Authenticatable, ProvidesActiveState, ProvidesIdentifierVerification;

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
            'email'             => NormalisedIdentifier::using('email'),
            'email_verified_at' => 'datetime',
            'phone'             => NormalisedIdentifier::using('phone'),
            'phone_verified_at' => 'datetime',
            'is_active'         => 'boolean',
        ];
    }
}
