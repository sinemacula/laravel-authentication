<?php

declare(strict_types = 1);

namespace Tests\Integration\Fixtures;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Casts\NormalisedIdentifier;
use SineMacula\Laravel\Authentication\Concerns\ActsAsPrincipal;
use SineMacula\Laravel\Authentication\Concerns\Authenticatable;
use SineMacula\Laravel\Authentication\Concerns\ProvidesIdentifierVerification;
use SineMacula\Laravel\Authentication\Contracts\HasVerifiableIdentifiers;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;

/**
 * 2D identity fixture with a designated email address and a phone number, each
 * with a verification time beside it.
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
final class VerifiableIdentity extends Model implements HasVerifiableIdentifiers, Identity, Principal
{
    use ActsAsPrincipal, Authenticatable, ProvidesIdentifierVerification;

    /** @var string|null The table associated with the model. */
    protected $table = 'verifiable_identities';

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
            'phone_verified_at' => 'datetime',
        ];
    }
}
