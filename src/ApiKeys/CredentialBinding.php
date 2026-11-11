<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\ApiKeys;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Models\ApiKey;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use SineMacula\Laravel\Authentication\Support\PrincipalReference;

/**
 * Holds a machine credential to the owner, principal and tenant it was issued
 * for, by type as well as identifier, since two types may share identifiers.
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
     * tenant, or `null` when it may.
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

        $recorded = [$key->principal_type, $key->tenant_type, $key->tenant_id];
        $loaded   = [PrincipalReference::type($principal), self::tenantType($tenant), IdentifierCoercion::stringify($tenant?->getTenantIdentifier())];

        return $recorded === $loaded && IdentifierCoercion::matches($key->principal_id, PrincipalReference::id($principal))
            ? null
            : FailureReason::PRINCIPAL_MISMATCH;
    }

    /**
     * Whether the key records the identity as its owner.
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
        return self::typeOf($identity);
    }

    /**
     * The type recorded for a tenant, as for an owner, or `null` for none.
     *
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Tenant  $tenant
     * @return ?string
     */
    public static function tenantType(?Tenant $tenant): ?string
    {
        return $tenant === null ? null : self::typeOf($tenant);
    }

    /**
     * An Eloquent model's morph class, any other object's class name.
     *
     * @param  object  $subject
     * @return string
     */
    private static function typeOf(object $subject): string
    {
        return $subject instanceof Model ? $subject->getMorphClass() : $subject::class;
    }
}
