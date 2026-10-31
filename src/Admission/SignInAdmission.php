<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Admission;

use SineMacula\Laravel\Authentication\Contracts\AudiencePolicy;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\MachineIdentity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;

/**
 * The checks every sign-in passes once its identity is known, whichever way it
 * was proven: the identity is a human one (a non-human identity has no
 * interactive sign-in and no session, so it is refused as `machine_identity`
 * whatever method proved it), the identity is active, the principal resolves
 * and is active, the tenant it acts within is active, and the guard's audience
 * policy admits the identity as that principal.
 *
 * Shared by `attempt()` and the session service, so a password sign-in, a
 * sign-in started for an externally verified identity, and the completion of a
 * pending one are held to the same rules in the same order.
 *
 * The audience policy's identity-level answer (`admitIdentifier()`: with the
 * package's policy, an identifier the guard requires verified and is not) is
 * asked before any principal is resolved, so its refusal is the same whether
 * the identity has principals or not.
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
     * @param  \SineMacula\Laravel\Authentication\Contracts\AudiencePolicy  $audience
     */
    public function __construct(

        /** The guards' audience policy. */
        private AudiencePolicy $audience,
    ) {}

    /**
     * Admit the identity to the guard as the principal the callback resolves,
     * or say why not. The callback runs only once the identity is known to be
     * human and active and the audience policy admits it with the identifier
     * type (`admitIdentifier()`); when it resolves no principal, the sign-in
     * fails with `$unresolved`.
     *
     * @param  string  $guard
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \Closure(): ?\SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\FailureReason  $unresolved
     * @param  ?string  $identifierType
     * @return \SineMacula\Laravel\Authentication\Admission\Admitted|\SineMacula\Laravel\Authentication\Admission\Refused
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    public function admit(string $guard, Identity $identity, \Closure $principal, FailureReason $unresolved, ?string $identifierType): Admitted|Refused
    {
        $refusal = match (true) {
            $identity instanceof MachineIdentity   => FailureReason::MACHINE_IDENTITY,
            !ActivationPolicy::isActive($identity) => FailureReason::IDENTITY_INACTIVE,
            default                                => $this->audience->admitIdentifier($guard, $identity, $identifierType),
        };

        if ($refusal !== null) {
            return new Refused($refusal, $identity);
        }

        $resolved = $principal();

        return $resolved instanceof Principal
            ? $this->admitAs($guard, $identity, $resolved, $identifierType)
            : new Refused($unresolved, $identity);
    }

    /**
     * Admit the active identity as the resolved principal: the principal and
     * its tenant must be active, and the audience policy must admit them.
     *
     * @param  string  $guard
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?string  $identifierType
     * @return \SineMacula\Laravel\Authentication\Admission\Admitted|\SineMacula\Laravel\Authentication\Admission\Refused
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    private function admitAs(string $guard, Identity $identity, Principal $principal, ?string $identifierType): Admitted|Refused
    {
        if (!ActivationPolicy::isActive($principal)) {
            return new Refused(FailureReason::PRINCIPAL_INACTIVE, $identity, $principal);
        }

        $tenant = ActivationPolicy::activeTenant($principal);

        if ($tenant === false) {
            return new Refused(FailureReason::TENANT_INACTIVE, $identity, $principal);
        }

        $admitted = new Admitted($identity, $principal, $tenant);
        $refusal  = $this->audience->admit($guard, $identity, $principal, $identifierType);

        return $refusal === null ? $admitted : Refused::after($refusal, $admitted);
    }
}
