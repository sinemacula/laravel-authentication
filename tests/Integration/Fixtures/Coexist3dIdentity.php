<?php

declare(strict_types = 1);

namespace Tests\Integration\Fixtures;

use Illuminate\Contracts\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Contracts\HasPrincipals;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Traits\Authenticatable;

/**
 * Eloquent fixture for the 3D guard coexistence test.
 *
 * Implements `Identity` + `HasPrincipals` but NOT `Principal`, so the default
 * principal resolver's 3D branch delegates to `resolveDefaultPrincipal()` and
 * returns a distinct principal model (`Coexist3dPrincipal`) rather than the
 * identity itself. Paired with `Coexist2dIdentity` in
 * `GuardCoexistenceIntegrationTest` to prove that both adoption modes can
 * coexist in a single Laravel application without guard cross-contamination.
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

    /** @var array<string, string> The attributes that should be cast. */
    protected $casts = [
        'is_active' => 'boolean',
    ];

    /**
     * Application-defined default principal lookup.
     *
     * Returns the first active principal owned by this identity, or `null`
     * when none exists. The integration test seeds exactly one active principal
     * per identity so the default-principal branch of the resolver returns a
     * deterministic row.
     *
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Principal
     */
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
     * Returns a fresh query against `Coexist3dPrincipal` scoped to this
     * identity's foreign key so the resolver's hint path
     * (`principals()->find($hint)`) resolves against a real Eloquent query
     * rather than a mock.
     *
     * @return \Illuminate\Contracts\Database\Eloquent\Builder
     */
    public function principals(): Builder
    {
        return Coexist3dPrincipal::query()
            ->where('identity_id', $this->getKey());
    }
}
