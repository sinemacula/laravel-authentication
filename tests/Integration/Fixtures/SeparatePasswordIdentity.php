<?php

declare(strict_types = 1);

namespace Tests\Integration\Fixtures;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Concerns\ActsAsPrincipal;
use SineMacula\Laravel\Authentication\Concerns\Authenticatable;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;

/**
 * 2D identity whose password hash is read from `identity_passwords`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @property int $id
 * @property string $email
 *
 * @internal
 */
final class SeparatePasswordIdentity extends Model implements Identity, Principal
{
    use ActsAsPrincipal, Authenticatable;

    /** @var string|null The table associated with the model. */
    protected $table = 'separate_password_identities';

    /** @var array<string> The attributes that aren't mass assignable. */
    protected $guarded = [];

    /**
     * The password hash recorded for the identity in `identity_passwords`.
     *
     * @return string
     */
    #[\Override]
    public function getAuthPassword(): string
    {
        $hash = $this->getConnection()
            ->table('identity_passwords')
            ->where('identity_id', $this->getKey())
            ->value('hash');

        return is_string($hash) ? $hash : '';
    }
}
