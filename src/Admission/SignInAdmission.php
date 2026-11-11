<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Admission;

use SineMacula\Laravel\Authentication\Contracts\ApplicationPolicy;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\MachineIdentity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Tenancy\TenantSelection;

/**
 * The checks every sign-in passes once its identity is known, whichever way it
 * was proven.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class SignInAdmission
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\ApplicationPolicy  $policy
     */
    public function __construct(

        /** The guards' application policy. */
        private ApplicationPolicy $policy,
    ) {}

    /**
     * Admit the identity as the principal the callback resolves, in the tenant
     * selected for it, or say why not.
     *
     * @param  string  $guard
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \Closure(): ?\SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\FailureReason  $unresolved
     * @param  ?string  $identifierType
     * @param  ?\SineMacula\Laravel\Authentication\Tenancy\TenantSelection  $tenant
     * @return \SineMacula\Laravel\Authentication\Admission\Admitted|\SineMacula\Laravel\Authentication\Admission\Refused
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    public function admit(
        string $guard,
        Identity $identity,
        \Closure $principal,
        FailureReason $unresolved,
        ?string $identifierType,
        ?TenantSelection $tenant = null,
    ): Admitted|Refused {
        $refusal = match (true) {
            $identity instanceof MachineIdentity   => FailureReason::MACHINE_IDENTITY,
            !ActivationPolicy::isActive($identity) => FailureReason::IDENTITY_INACTIVE,
            default                                => ApplicationAdmission::admitIdentifier($this->policy, $guard, $identity, $identifierType),
        };

        if ($refusal !== null) {
            return new Refused($refusal, $identity);
        }

        $resolved = $principal();

        return $resolved instanceof Principal
            ? $this->admitAs($guard, $identity, $resolved, $tenant ?? TenantSelection::principalDefault())
            : new Refused($unresolved, $identity);
    }

    /**
     * Admit the active identity as the resolved principal in the selected
     * tenant.
     *
     * @param  string  $guard
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  \SineMacula\Laravel\Authentication\Tenancy\TenantSelection  $selection
     * @return \SineMacula\Laravel\Authentication\Admission\Admitted|\SineMacula\Laravel\Authentication\Admission\Refused
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \LogicException
     */
    private function admitAs(string $guard, Identity $identity, Principal $principal, TenantSelection $selection): Admitted|Refused
    {
        $refused = self::refusalOf($guard, $identity, $principal);
        $tenant  = $refused === null ? TenantAdmission::select($principal, $selection) : null;

        return match (true) {
            $refused !== null                => $refused,
            $tenant instanceof FailureReason => new Refused($tenant, $identity, $principal),
            default                          => new Admitted($identity, $principal, $tenant),
        };
    }

    /**
     * Why the principal may not hold a session of the application, before any
     * tenant is selected.
     *
     * @param  string  $guard
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @return ?\SineMacula\Laravel\Authentication\Admission\Refused
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private static function refusalOf(string $guard, Identity $identity, Principal $principal): ?Refused
    {
        if (!ActivationPolicy::isActive($principal)) {
            return new Refused(FailureReason::PRINCIPAL_INACTIVE, $identity, $principal);
        }

        $own = ActivationPolicy::activeTenant($principal);

        return match (true) {
            $own === false                                  => new Refused(FailureReason::TENANT_INACTIVE, $identity, $principal),
            !PrincipalAdmission::mayUse($guard, $principal) => new Refused(FailureReason::PRINCIPAL_INELIGIBLE, $identity, $principal, $own),
            default                                         => null,
        };
    }
}
