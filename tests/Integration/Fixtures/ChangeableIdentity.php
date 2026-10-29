<?php

declare(strict_types = 1);

namespace Tests\Integration\Fixtures;

use Illuminate\Contracts\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Casts\NormalisedIdentifier;
use SineMacula\Laravel\Authentication\Concerns\ActsAsPrincipal;
use SineMacula\Laravel\Authentication\Concerns\Authenticatable;
use SineMacula\Laravel\Authentication\Concerns\ProvidesIdentifierVerification;
use SineMacula\Laravel\Authentication\Contracts\HasChangeableIdentifiers;
use SineMacula\Laravel\Authentication\Contracts\HasDevices;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Models\Device;

/**
 * 2D identity fixture whose identifiers can be changed, stored in
 * `changeable_identities`: a designated email address and phone number, each
 * normalised, unique and with a verification time beside it, a password, and
 * devices, so the session service can sign it in and the identifier change
 * service can change either identifier.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @property int $id
 * @property ?string $email
 * @property ?\Carbon\CarbonInterface $email_verified_at
 * @property ?string $phone
 * @property ?\Carbon\CarbonInterface $phone_verified_at
 * @property ?string $password
 * @property ?\Carbon\CarbonInterface $updated_at
 *
 * @internal
 */
final class ChangeableIdentity extends Model implements HasChangeableIdentifiers, HasDevices, Identity, Principal
{
    use ActsAsPrincipal, Authenticatable, ProvidesIdentifierVerification;

    /** @var string|null The table associated with the model. */
    protected $table = 'changeable_identities';

    /** @var array<string> The attributes that aren't mass assignable. */
    protected $guarded = [];

    /**
     * Eloquent relation builder for the identity's devices.
     *
     * @return \Illuminate\Contracts\Database\Eloquent\Builder
     */
    #[\Override]
    public function devices(): Builder
    {
        return Device::query()
            ->where('authenticatable_type', self::class)
            ->where('authenticatable_id', (string) $this->getKey()); // @phpstan-ignore cast.string
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
            'email'             => NormalisedIdentifier::using('email'),
            'email_verified_at' => 'datetime',
            'phone'             => NormalisedIdentifier::using('phone'),
            'phone_verified_at' => 'datetime',
        ];
    }
}
