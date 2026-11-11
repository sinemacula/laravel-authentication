<?php

declare(strict_types = 1);

namespace Tests\Integration\Fixtures;

use Illuminate\Contracts\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Concerns\Authenticatable;
use SineMacula\Laravel\Authentication\Contracts\HasPrincipals;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;

/**
 * 3D identity for the guard coexistence test whose principal is a separate
 * `Coexist3dPrincipal`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @property int $id
 * @property string $email
 * @property string $password
 * @property bool $is_active
 *
 * @internal
 */
final class Coexist3dIdentity extends Model implements HasPrincipals, Identity
{
    use Authenticatable;

    /** @var string|null The table associated with the model. */
    protected $table = 'coexist_3d_identities';

    /** @var array<string> The attributes that aren't mass assignable. */
    protected $guarded = [];

    /**
     * Return the identity's first active principal.
     *
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Principal
     */
    #[\Override]
    public function resolveDefaultPrincipal(): ?Principal
    {
        $principal = $this->principals()
            ->where('is_active', true)
            ->first();

        return $principal instanceof Principal ? $principal : null;
    }

    /**
     * Eloquent relation builder for the identity's principals.
     *
     * @return \Illuminate\Contracts\Database\Eloquent\Builder
     */
    #[\Override]
    public function principals(): Builder
    {
        return Coexist3dPrincipal::query()
            ->where('identity_id', $this->getKey());
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
            'is_active' => 'boolean',
        ];
    }
}
