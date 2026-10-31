<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\ApiKeys;

use SineMacula\Laravel\Authentication\Admission\ActivationPolicy;
use SineMacula\Laravel\Authentication\Admission\Admitted;
use SineMacula\Laravel\Authentication\Admission\Refused;
use SineMacula\Laravel\Authentication\Contracts\AudiencePolicy;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\IdentityProvider;
use SineMacula\Laravel\Authentication\Contracts\MachineIdentity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\PrincipalResolver;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Models\ApiKey;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;

/**
 * Admits the owner of a live key as the principal it was issued for, on the
 * guard it authenticates for, each failure with its own reason: the owner,
 * reloaded through the guard's provider, must be the very identity the key
 * records (`identity_unknown`), a non-human one (`credential_invalid`: keys are
 * a machine's credential only) and active (`identity_inactive`); the principal
 * must resolve exactly to the one the key records (`principal_mismatch`) and
 * be active (`principal_inactive`) in an active tenant (`tenant_inactive`);
 * the key's binding to its owner, principal and tenant must hold
 * (`CredentialBinding`); and the guard's audience policy must admit the
 * principal (`principal_ineligible`).
 *
 * Built for one use with the guard's current collaborators, so it keeps nothing
 * between requests.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ApiKeyAdmission
{
    /**
     * Constructor.
     *
     * @param  string  $guard
     * @param  \SineMacula\Laravel\Authentication\Contracts\IdentityProvider  $provider
     * @param  \SineMacula\Laravel\Authentication\Contracts\PrincipalResolver  $resolver
     * @param  \SineMacula\Laravel\Authentication\Contracts\AudiencePolicy  $audience
     */
    public function __construct(

        /** Name of the guard the key authenticates for. */
        private string $guard,

        /** The guard's identity provider, which reloads the key's owner. */
        private IdentityProvider $provider,

        /** The guard's principal resolver. */
        private PrincipalResolver $resolver,

        /** The audience policy the principal must be admitted by. */
        private AudiencePolicy $audience,
    ) {}

    /**
     * Admit the key's owner as the key's principal, or refuse it with the
     * context established by then.
     *
     * @param  \SineMacula\Laravel\Authentication\Models\ApiKey  $key
     * @return \SineMacula\Laravel\Authentication\Admission\Admitted|\SineMacula\Laravel\Authentication\Admission\Refused
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    public function admit(ApiKey $key): Admitted|Refused
    {
        $identity = $this->provider->retrieveById($key->authenticatable_id);

        if (!$identity instanceof Identity || !CredentialBinding::isOwnedBy($key, $identity)) {
            return new Refused(FailureReason::IDENTITY_UNKNOWN);
        }

        $refusal = match (true) {
            !$identity instanceof MachineIdentity  => FailureReason::CREDENTIAL_INVALID,
            !ActivationPolicy::isActive($identity) => FailureReason::IDENTITY_INACTIVE,
            default                                => null,
        };

        return $refusal === null ? $this->admitAs($key, $identity) : new Refused($refusal, $identity);
    }

    /**
     * Admit the active owner as the principal the key records.
     *
     * @param  \SineMacula\Laravel\Authentication\Models\ApiKey  $key
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @return \SineMacula\Laravel\Authentication\Admission\Admitted|\SineMacula\Laravel\Authentication\Admission\Refused
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    private function admitAs(ApiKey $key, Identity $identity): Admitted|Refused
    {
        $principal = $this->resolver->resolve($identity, $key->principal_id);

        if (!$principal instanceof Principal || !IdentifierCoercion::matches($principal->getPrincipalIdentifier(), $key->principal_id)) {
            return new Refused(FailureReason::PRINCIPAL_MISMATCH, $identity);
        }

        if (!ActivationPolicy::isActive($principal)) {
            return new Refused(FailureReason::PRINCIPAL_INACTIVE, $identity, $principal);
        }

        return $this->admitWithin($key, $identity, $principal, ActivationPolicy::activeTenant($principal));
    }

    /**
     * Admit the owner as the active principal within its tenant (`false` for
     * one that is inactive or cannot be loaded), once the key's binding holds
     * and the guard's audience admits the principal.
     *
     * @param  \SineMacula\Laravel\Authentication\Models\ApiKey  $key
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  false|\SineMacula\Laravel\Authentication\Contracts\Tenant|null  $tenant
     * @return \SineMacula\Laravel\Authentication\Admission\Admitted|\SineMacula\Laravel\Authentication\Admission\Refused
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    private function admitWithin(ApiKey $key, Identity $identity, Principal $principal, false|Tenant|null $tenant): Admitted|Refused
    {
        if ($tenant === false) {
            return new Refused(FailureReason::TENANT_INACTIVE, $identity, $principal);
        }

        $refusal = CredentialBinding::refusal($key, $identity, $principal, $tenant) ?? $this->audience->admit($this->guard, $identity, $principal, null);

        return $refusal === null
            ? new Admitted($identity, $principal, $tenant)
            : new Refused($refusal, $identity, $principal, $tenant);
    }
}
