<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Exceptions;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Jwt\IdentifierCoercion;

/**
 * Thrown by `Principal::getTenant()` when the principal names a tenant that
 * cannot be loaded: deleted, soft-deleted, or hidden by a global scope.
 *
 * The activation policy reads it as an inactive tenant, so the principal cannot
 * authenticate, rather than as a principal that acts within no tenant. When the
 * principal's relation says which tenant it names (its model class, and the key
 * the principal holds for it), the exception carries that, so a caller holding
 * the tenant, such as a tenant's deactivation after the tenant was deleted, can
 * still tell that the principal acts within it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class TenantUnavailableException extends \RuntimeException
{
    /**
     * Constructor.
     *
     * @param  string  $message
     * @param  ?string  $tenantClass
     * @param  ?string  $tenantKeyName
     * @param  mixed  $tenantKey
     */
    public function __construct(

        // Which principal names the tenant, and through which relation.
        string $message,

        /** Class of the tenant model the principal names, when its relation says. */
        private readonly ?string $tenantClass = null,

        /** Attribute of that model the principal's key refers to. */
        private readonly ?string $tenantKeyName = null,

        /** Key the principal holds for the tenant. */
        private readonly mixed $tenantKey = null,
    ) {
        parent::__construct($message);
    }

    /**
     * Whether the tenant that cannot be loaded is the given one: a model of the
     * class the principal names, holding the key the principal holds. `false`
     * when the principal's relation does not say.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Tenant  $tenant
     * @return bool
     */
    public function isFor(Tenant $tenant): bool
    {
        return $tenant instanceof Model
            && $this->tenantKeyName !== null
            && $tenant::class === $this->tenantClass
            && IdentifierCoercion::matches($tenant->getAttributes()[$this->tenantKeyName] ?? null, $this->tenantKey);
    }
}
