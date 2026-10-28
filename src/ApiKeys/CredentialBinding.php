<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\ApiKeys;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Jwt\IdentifierCoercion;
use SineMacula\Laravel\Authentication\Models\ApiKey;
use SineMacula\Laravel\Authentication\Sessions\PrincipalReference;

/**
 * Holds a machine credential to what it was issued for: one owner, one
 * principal, one tenant. The owner's recorded type and identifier, the
 * principal's recorded type and identifier, and the tenant identifier must all
 * equal what was loaded for the request; matching identifiers alone never
 * suffice, since two types may share them. One check serves an API key on its
 * guard, a client credentials exchange, and the access tokens that exchange
 * issued, so a principal moved to another tenant, or another type under the
 * same identifiers, is refused the same way on every path.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class CredentialBinding
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Why the key may not authenticate as the loaded identity, principal and
     * tenant, or `null` when it may: `credential_invalid` for another owner,
     * `principal_mismatch` for another principal or tenant.
     *
     * @param  \SineMacula\Laravel\Authentication\Models\ApiKey  $key
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Tenant  $tenant
     * @return ?\SineMacula\Laravel\Authentication\Events\Enums\FailureReason
     */
    public static function refusal(ApiKey $key, Identity $identity, Principal $principal, ?Tenant $tenant): ?FailureReason
    {
        if (!self::isOwnedBy($key, $identity)) {
            return FailureReason::CREDENTIAL_INVALID;
        }

        $tenantId = IdentifierCoercion::stringify($tenant?->getTenantIdentifier());

        return $key->principal_type === PrincipalReference::type($principal)
            && IdentifierCoercion::matches($key->principal_id, PrincipalReference::id($principal))
            && $key->tenant_id === $tenantId
            ? null
            : FailureReason::PRINCIPAL_MISMATCH;
    }

    /**
     * Whether the key records the identity as its owner: the same type and
     * identifier.
     *
     * @param  \SineMacula\Laravel\Authentication\Models\ApiKey  $key
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @return bool
     */
    public static function isOwnedBy(ApiKey $key, Identity $identity): bool
    {
        return $key->authenticatable_type === self::ownerType($identity)
            && IdentifierCoercion::matches($key->authenticatable_id, $identity->getAuthIdentifier());
    }

    /**
     * The type recorded for an owner: an Eloquent identity's morph class, any
     * other identity's class name.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @return string
     */
    public static function ownerType(Identity $identity): string
    {
        return $identity instanceof Model ? $identity->getMorphClass() : $identity::class;
    }
}
