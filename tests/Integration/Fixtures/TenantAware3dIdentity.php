<?php

declare(strict_types = 1);

namespace Tests\Integration\Fixtures;

use Illuminate\Contracts\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Query\Builder as QueryBuilder;
use Illuminate\Support\Facades\DB;
use SineMacula\Laravel\Authentication\Contracts\HasPrincipals;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\ResolvesHintedPrincipal;
use SineMacula\Laravel\Authentication\Traits\Authenticatable;

/**
 * Identity fixture for tenant-aware 3D resolution tests.
 *
 * Resolves principals through a single joined principal+tenant query so
 * `tenant()` and `type()` do not trigger an extra SQL read after auth.
 *
 * @property int $id
 * @property string $email
 * @property string $password
 * @property bool $is_active
 *
 * @internal
 */
final class TenantAware3dIdentity extends Model implements HasPrincipals, Identity, ResolvesHintedPrincipal
{
    use Authenticatable;

    /** @var string|null The table associated with the model. */
    protected $table = 'tenant_aware_3d_identities';

    /** @var array<string> The attributes that aren't mass assignable. */
    protected $guarded = [];

    /** @var array<string, string> The attributes that should be cast. */
    protected $casts = [
        'is_active' => 'boolean',
    ];

    /**
     * Eloquent relation builder for the identity's principals.
     *
     * @return \Illuminate\Contracts\Database\Eloquent\Builder
     */
    public function principals(): Builder
    {
        return TenantAware3dPrincipal::query()
            ->where('identity_id', $this->getKey());
    }

    /**
     * Resolve the identity's default active principal with tenant context.
     *
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Principal
     */
    public function resolveDefaultPrincipal(): ?Principal
    {
        return $this->queryTenantAwarePrincipal(
            static fn (QueryBuilder $query): QueryBuilder => $query
                ->where('tenant_aware_3d_principals.is_active', true)
                ->orderBy('tenant_aware_3d_principals.id'),
        );
    }

    /**
     * Resolve a hinted principal with tenant context already attached.
     *
     * @param  mixed  $hint
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Principal
     */
    public function resolveHintedPrincipal(mixed $hint): ?Principal
    {
        return $this->queryTenantAwarePrincipal(
            static fn (QueryBuilder $query): QueryBuilder => $query
                ->where('tenant_aware_3d_principals.id', $hint),
        );
    }

    /**
     * Build a tenant-aware principal from a single joined query.
     *
     * @param  \Closure(\Illuminate\Database\Query\Builder): \Illuminate\Database\Query\Builder  $scope
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Principal
     */
    private function queryTenantAwarePrincipal(\Closure $scope): ?Principal
    {
        $query = DB::table('tenant_aware_3d_principals')
            ->join(
                'tenant_aware_3d_tenants',
                'tenant_aware_3d_tenants.id',
                '=',
                'tenant_aware_3d_principals.tenant_id',
            )
            ->where('tenant_aware_3d_principals.identity_id', $this->getKey())
            ->select($this->principalSelectColumns());

        $row = $scope($query)->first();

        if ($row === null) {
            return null;
        }

        $principal = (new TenantAware3dPrincipal)->newFromBuilder([
            'id'         => $row->id,
            'identity_id' => $row->identity_id,
            'tenant_id'  => $row->tenant_id,
            'name'       => $row->name,
            'is_active'  => $row->is_active,
            'created_at' => $row->created_at,
            'updated_at' => $row->updated_at,
        ]);

        $tenant = (new TenantAware3dTenant)->newFromBuilder([
            'id'         => $row->joined_tenant_id,
            'name'       => $row->joined_tenant_name,
            'type'       => $row->joined_tenant_type,
            'created_at' => $row->joined_tenant_created_at,
            'updated_at' => $row->joined_tenant_updated_at,
        ]);

        $principal->setRelation('identity', $this);
        $principal->setRelation('tenant', $tenant);

        return $principal;
    }

    /**
     * Select list for the joined principal+tenant query.
     *
     * @return list<string>
     */
    private function principalSelectColumns(): array
    {
        return [
            'tenant_aware_3d_principals.id',
            'tenant_aware_3d_principals.identity_id',
            'tenant_aware_3d_principals.tenant_id',
            'tenant_aware_3d_principals.name',
            'tenant_aware_3d_principals.is_active',
            'tenant_aware_3d_principals.created_at',
            'tenant_aware_3d_principals.updated_at',
            'tenant_aware_3d_tenants.id as joined_tenant_id',
            'tenant_aware_3d_tenants.name as joined_tenant_name',
            'tenant_aware_3d_tenants.type as joined_tenant_type',
            'tenant_aware_3d_tenants.created_at as joined_tenant_created_at',
            'tenant_aware_3d_tenants.updated_at as joined_tenant_updated_at',
        ];
    }
}
