<?php

declare(strict_types = 1);

namespace Tests\Integration\Fixtures;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Concerns\ActsAsPrincipal;
use SineMacula\Laravel\Authentication\Concerns\Authenticatable;
use SineMacula\Laravel\Authentication\Concerns\ProvidesIdentifierVerification;
use SineMacula\Laravel\Authentication\Contracts\HasVerifiableIdentifiers;
use SineMacula\Laravel\Authentication\Contracts\MachineIdentity;
use SineMacula\Laravel\Authentication\Contracts\Principal;

/**
 * A non-human identity that, unlike `MachineClient`, holds a verified phone
 * number and email address in `code_identities`, so the tests prove a machine
 * gets no one-time code because it is a machine, not because it lacks a
 * verified identifier.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @property int $id
 * @property ?string $phone
 * @property ?string $email
 *
 * @internal
 */
final class CodeMachineClient extends Model implements HasVerifiableIdentifiers, MachineIdentity, Principal
{
    use ActsAsPrincipal, Authenticatable, ProvidesIdentifierVerification;

    /** @var string|null The table associated with the model. */
    protected $table = 'code_identities';

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
            'phone_verified_at' => 'datetime',
            'email_verified_at' => 'datetime',
        ];
    }
}
