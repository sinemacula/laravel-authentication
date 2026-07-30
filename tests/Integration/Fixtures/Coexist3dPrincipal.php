<?php

declare(strict_types = 1);

namespace Tests\Integration\Fixtures;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Concerns\ActsAsPrincipal;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;

/**
 * Eloquent fixture for the 3D guard coexistence test.
 *
 * Implements `Principal` only - distinct from its owning identity - so the
 * default principal resolver's 3D branch resolves a separate acting principal
 * via `HasPrincipals::resolveDefaultPrincipal()`. Rows on the backing
 * `coexist_3d_principals` table carry an `identity_id` foreign key to
 * `coexist_3d_identities` plus the `is_active` flag consulted by the guard's
 * active-principal check.
 *
 * The model intentionally does NOT implement `Identity`: the integration test
 * asserts that `Auth::identity()` and `Auth::principal()` expose distinct model
 * classes on the 3D guard, which is only true when the principal is a
 * first-class model in its own right.
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
final class Coexist3dPrincipal extends Model implements Principal
{
    use ActsAsPrincipal;

    /** @var string|null The table associated with the model. */
    protected $table = 'coexist_3d_principals';

    /** @var array<string> The attributes that aren't mass assignable. */
    protected $guarded = [];

    /**
     * Return the owning identity for this principal.
     *
     * Eager-loads from the `coexist_3d_identities` table via the `identity_id`
     * foreign key. Called by `ActsAsPrincipal::getIdentity` when the principal
     * is not itself an Identity (i.e. 3D mode).
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
