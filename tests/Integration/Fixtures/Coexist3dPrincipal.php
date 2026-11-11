<?php

declare(strict_types = 1);

namespace Tests\Integration\Fixtures;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Concerns\ActsAsPrincipal;
use SineMacula\Laravel\Authentication\Concerns\ProvidesActiveState;
use SineMacula\Laravel\Authentication\Contracts\CanBeActive;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;

/**
 * Principal of a `Coexist3dIdentity` for the guard coexistence test, a model
 * distinct from its identity.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @property int $id
 * @property int $identity_id
 * @property string $name
 * @property bool $is_active
 *
 * @internal
 */
final class Coexist3dPrincipal extends Model implements CanBeActive, Principal
{
    use ActsAsPrincipal, ProvidesActiveState;

    /** @var string|null The table associated with the model. */
    protected $table = 'coexist_3d_principals';

    /** @var array<string> The attributes that aren't mass assignable. */
    protected $guarded = [];

    /**
     * Return the owning identity for this principal.
     *
     * @return \SineMacula\Laravel\Authentication\Contracts\Identity
     *
     * @throws \LogicException
     */
    #[\Override]
    public function getIdentity(): Identity
    {
        $identity = Coexist3dIdentity::query()->find($this->identity_id);

        if (!$identity instanceof Identity) {
            throw new \LogicException(sprintf('Coexist3dPrincipal %s could not resolve its owning identity row.', (string) $this->getKey())); // @phpstan-ignore cast.string
        }

        return $identity;
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
            'is_active'   => 'boolean',
            'identity_id' => 'integer',
        ];
    }
}
