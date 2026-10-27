<?php

declare(strict_types = 1);

namespace Tests\Integration\Fixtures;

use Illuminate\Contracts\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Casts\NormalisedIdentifier;
use SineMacula\Laravel\Authentication\Concerns\ActsAsPrincipal;
use SineMacula\Laravel\Authentication\Concerns\Authenticatable;
use SineMacula\Laravel\Authentication\Concerns\ProvidesIdentifierVerification;
use SineMacula\Laravel\Authentication\Contracts\HasDevices;
use SineMacula\Laravel\Authentication\Contracts\HasVerifiableIdentifiers;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Models\Device;

/**
 * A second model class over `VerifiableIdentity`'s table, as an application
 * gives an admin guard a model of its own over its users table: the same rows,
 * read as another class.
 *
 * @property int $id
 * @property ?string $email
 * @property ?\Carbon\CarbonInterface $email_verified_at
 * @property ?string $phone
 * @property ?\Carbon\CarbonInterface $phone_verified_at
 * @property string $password
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class VerifiableStaffIdentity extends Model implements HasDevices, HasVerifiableIdentifiers, Identity, Principal
{
    use ActsAsPrincipal, Authenticatable, ProvidesIdentifierVerification;

    /** @var string|null The table associated with the model. */
    protected $table = 'verifiable_identities';

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
            'phone_verified_at' => 'datetime',
        ];
    }
}
