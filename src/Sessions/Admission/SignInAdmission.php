<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions\Admission;

use SineMacula\Laravel\Authentication\Contracts\AudiencePolicy;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Guards\ActivationPolicy;

/**
 * The checks every sign-in passes once its identity is known, whichever way it
 * was proven: the identity is active, the principal resolves and is active, the
 * tenant it acts within is active, and the guard's audience policy admits the
 * identity as that principal.
 *
 * Shared by `attempt()` and the session service, so a password sign-in, a
 * sign-in started for an externally verified identity, and the completion of a
 * pending one are held to the same rules in the same order.
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
     * active; when it resolves no principal, the sign-in fails with
     * `$unresolved`.
     *
     * @param  string  $guard
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \Closure(): ?\SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\FailureReason  $unresolved
     * @param  ?string  $identifierType
     * @return \SineMacula\Laravel\Authentication\Sessions\Admission\AdmittedSignIn|\SineMacula\Laravel\Authentication\Sessions\Admission\RefusedSignIn
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    public function admit(string $guard, Identity $identity, \Closure $principal, FailureReason $unresolved, ?string $identifierType): AdmittedSignIn|RefusedSignIn
    {
        if (!ActivationPolicy::isActive($identity)) {
            return new RefusedSignIn(FailureReason::IDENTITY_INACTIVE, $identity);
        }

        $resolved = $principal();

        return $resolved instanceof Principal
            ? $this->admitAs($guard, $identity, $resolved, $identifierType)
            : new RefusedSignIn($unresolved, $identity);
    }

    /**
     * Admit the active identity as the resolved principal: the principal and
     * its tenant must be active, and the audience policy must admit them.
     *
     * @param  string  $guard
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?string  $identifierType
     * @return \SineMacula\Laravel\Authentication\Sessions\Admission\AdmittedSignIn|\SineMacula\Laravel\Authentication\Sessions\Admission\RefusedSignIn
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    private function admitAs(string $guard, Identity $identity, Principal $principal, ?string $identifierType): AdmittedSignIn|RefusedSignIn
    {
        if (!ActivationPolicy::isActive($principal)) {
            return new RefusedSignIn(FailureReason::PRINCIPAL_INACTIVE, $identity, $principal);
        }

        $tenant = ActivationPolicy::activeTenant($principal);

        if ($tenant === false) {
            return new RefusedSignIn(FailureReason::TENANT_INACTIVE, $identity, $principal);
        }

        $admitted = new AdmittedSignIn($identity, $principal, $tenant);
        $refusal  = $this->audience->admit($guard, $identity, $principal, $identifierType);

        return $refusal === null ? $admitted : RefusedSignIn::after($refusal, $admitted);
    }
}
