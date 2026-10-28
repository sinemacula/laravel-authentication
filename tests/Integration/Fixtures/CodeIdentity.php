<?php

declare(strict_types = 1);

namespace Tests\Integration\Fixtures;

use Illuminate\Contracts\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Casts\NormalisedIdentifier;
use SineMacula\Laravel\Authentication\Concerns\ActsAsPrincipal;
use SineMacula\Laravel\Authentication\Concerns\Authenticatable;
use SineMacula\Laravel\Authentication\Concerns\ProvidesActiveState;
use SineMacula\Laravel\Authentication\Concerns\ProvidesIdentifierVerification;
use SineMacula\Laravel\Authentication\Contracts\CanBeActive;
use SineMacula\Laravel\Authentication\Contracts\HasDevices;
use SineMacula\Laravel\Authentication\Contracts\HasVerifiableIdentifiers;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Models\Device;

/**
 * 2D identity fixture for one-time codes, stored in `code_identities`: a
 * designated phone number and email address, each normalised and with a
 * verification time beside it, an activity flag, and devices, so the session
 * service can sign it in with a code.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @property int $id
 * @property ?string $phone
 * @property ?\Carbon\CarbonInterface $phone_verified_at
 * @property ?string $email
 * @property ?\Carbon\CarbonInterface $email_verified_at
 * @property ?string $password
 * @property bool $is_active
 *
 * @internal
 */
final class CodeIdentity extends Model implements CanBeActive, HasDevices, HasVerifiableIdentifiers, Identity, Principal
{
    use ActsAsPrincipal, Authenticatable, ProvidesActiveState, ProvidesIdentifierVerification;

    /** @var string|null The table associated with the model. */
    protected $table = 'code_identities';

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
            'phone'             => NormalisedIdentifier::using('phone'),
            'phone_verified_at' => 'datetime',
            'email'             => NormalisedIdentifier::using('email'),
            'email_verified_at' => 'datetime',
            'is_active'         => 'boolean',
        ];
    }
}
