<?php

declare(strict_types = 1);

namespace Tests\Integration\Fixtures;

use Illuminate\Auth\Passwords\CanResetPassword;
use Illuminate\Contracts\Auth\CanResetPassword as CanResetPasswordContract;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Notifications\Notifiable;
use SineMacula\Laravel\Authentication\Casts\NormalisedIdentifier;
use SineMacula\Laravel\Authentication\Concerns\ActsAsPrincipal;
use SineMacula\Laravel\Authentication\Concerns\Authenticatable;
use SineMacula\Laravel\Authentication\Concerns\ProvidesIdentifierVerification;
use SineMacula\Laravel\Authentication\Contracts\HasVerifiableIdentifiers;
use SineMacula\Laravel\Authentication\Contracts\MachineIdentity;
use SineMacula\Laravel\Authentication\Contracts\Principal;

/**
 * A non-human identity over the `password_identities` table that could
 * otherwise be sent a reset: it holds a password, a verified email address and
 * Laravel's password reset notification, so only its being a machine refuses
 * it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class PasswordMachine extends Model implements CanResetPasswordContract, HasVerifiableIdentifiers, MachineIdentity, Principal
{
    use ActsAsPrincipal, Authenticatable, CanResetPassword, Notifiable, ProvidesIdentifierVerification;

    /** @var string|null The table associated with the model. */
    protected $table = 'password_identities';

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
        ];
    }
}
