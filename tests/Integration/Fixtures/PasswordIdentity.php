<?php

declare(strict_types = 1);

namespace Tests\Integration\Fixtures;

use Illuminate\Auth\Passwords\CanResetPassword;
use Illuminate\Contracts\Auth\CanResetPassword as CanResetPasswordContract;
use Illuminate\Contracts\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Notifications\Notifiable;
use SineMacula\Laravel\Authentication\Casts\NormalisedIdentifier;
use SineMacula\Laravel\Authentication\Concerns\ActsAsPrincipal;
use SineMacula\Laravel\Authentication\Concerns\Authenticatable;
use SineMacula\Laravel\Authentication\Concerns\ProvidesActiveState;
use SineMacula\Laravel\Authentication\Concerns\ProvidesIdentifierVerification;
use SineMacula\Laravel\Authentication\Concerns\ProvidesTokensValidAfter;
use SineMacula\Laravel\Authentication\Contracts\CanBeActive;
use SineMacula\Laravel\Authentication\Contracts\HasDevices;
use SineMacula\Laravel\Authentication\Contracts\HasTokensValidAfter;
use SineMacula\Laravel\Authentication\Contracts\HasVerifiableIdentifiers;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Models\Device;

/**
 * 2D identity fixture for the password helpers, stored in
 * `password_identities`: a normalised email address and phone number, each with
 * a verification time, a password, a nickname a test leaves dirty, an activity
 * flag, a "tokens valid after" cutoff, devices of the shipped model, and
 * Laravel's password reset notification.
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
 * @property ?string $nickname
 * @property bool $is_active
 * @property ?\Carbon\CarbonInterface $tokens_valid_after
 * @property ?\Carbon\CarbonInterface $updated_at
 *
 * @internal
 */
final class PasswordIdentity extends Model implements CanBeActive, CanResetPasswordContract, HasDevices, HasTokensValidAfter, HasVerifiableIdentifiers, Identity, Principal
{
    use ActsAsPrincipal, Authenticatable, CanResetPassword, Notifiable, ProvidesActiveState, ProvidesIdentifierVerification, ProvidesTokensValidAfter;

    /** @var string|null The table associated with the model. */
    protected $table = 'password_identities';

    /** @var array<string> The attributes that aren't mass assignable. */
    protected $guarded = [];

    /**
     * The identity's devices of the shipped model.
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
            'email'              => NormalisedIdentifier::using('email'),
            'email_verified_at'  => 'datetime',
            'phone'              => NormalisedIdentifier::using('phone'),
            'phone_verified_at'  => 'datetime',
            'is_active'          => 'boolean',
            'tokens_valid_after' => 'datetime',
        ];
    }
}
