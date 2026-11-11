<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Jwt;

use Illuminate\Container\Container;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Admission\ActivationPolicy;
use SineMacula\Laravel\Authentication\Admission\Admitted;
use SineMacula\Laravel\Authentication\Admission\PrincipalAdmission;
use SineMacula\Laravel\Authentication\Admission\Refused;
use SineMacula\Laravel\Authentication\Admission\TenantAdmission;
use SineMacula\Laravel\Authentication\Contracts\ApplicationPolicy;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\IdentityProvider;
use SineMacula\Laravel\Authentication\Contracts\MachineIdentity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\PrincipalResolver;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\SessionRecords\SessionOwnership;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use SineMacula\Laravel\Authentication\Support\PrincipalReference;

/**
 * Decides whom a session's refresh token signs in again; none of its refusals
 * revokes the session.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class RefreshAdmission
{
    /**
     * Constructor.
     *
     * @param  string  $guard
     * @param  \SineMacula\Laravel\Authentication\Contracts\IdentityProvider  $provider
     * @param  \SineMacula\Laravel\Authentication\Contracts\PrincipalResolver  $resolver
     */
    public function __construct(

        /** Name of the guard exchanging the token. */
        private string $guard,

        /** The guard's identity provider, which reloads the session owner. */
        private IdentityProvider $provider,

        /** The guard's principal resolver. */
        private PrincipalResolver $resolver,
    ) {}

    /**
     * Admit the session's owner as the hinted principal in the session's active
     * tenant.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @param  mixed  $principalHint
     * @return \SineMacula\Laravel\Authentication\Admission\Admitted|\SineMacula\Laravel\Authentication\Admission\Refused
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function admit(EloquentSession&Model $session, mixed $principalHint): Admitted|Refused
    {
        $admitted = $this->admitPrincipal($session, $principalHint);

        return $admitted instanceof Admitted && PrincipalReference::isRecordedOn($session, $admitted->principal)
            ? self::inActiveTenant($session, $admitted)
            : $admitted;
    }

    /**
     * Admit the session's owner as the hinted principal in the principal's own
     * tenant, for a switch, which admits its destination tenant itself.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @param  mixed  $principalHint
     * @return \SineMacula\Laravel\Authentication\Admission\Admitted|\SineMacula\Laravel\Authentication\Admission\Refused
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function admitPrincipal(EloquentSession&Model $session, mixed $principalHint): Admitted|Refused
    {
        $identity = $this->owner($session);

        if ($identity === null) {
            return new Refused(FailureReason::IDENTITY_UNKNOWN);
        }

        $refusal = match (true) {
            $identity instanceof MachineIdentity   => FailureReason::MACHINE_IDENTITY,
            !ActivationPolicy::isActive($identity) => FailureReason::IDENTITY_INACTIVE,
            default                                => null,
        };

        return $refusal === null ? $this->admitAs($session, $identity, $principalHint) : new Refused($refusal, $identity);
    }

    /**
     * Admit the session's active owner as the principal the token names, or the
     * resolver's default.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  mixed  $principalHint
     * @return \SineMacula\Laravel\Authentication\Admission\Admitted|\SineMacula\Laravel\Authentication\Admission\Refused
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function admitAs(EloquentSession&Model $session, Identity $identity, mixed $principalHint): Admitted|Refused
    {
        $principal = $this->principal($identity, $principalHint);

        if ($principal instanceof FailureReason || !ActivationPolicy::isActive($principal)) {
            return $principal instanceof FailureReason
                ? new Refused($principal, $identity)
                : new Refused(FailureReason::PRINCIPAL_INACTIVE, $identity, $principal);
        }

        $tenant = ActivationPolicy::activeTenant($principal);

        return $tenant === false
            ? new Refused(FailureReason::TENANT_INACTIVE, $identity, $principal)
            : $this->admitByPolicy($session, new Admitted($identity, $principal, $tenant, $session));
    }

    /**
     * Hold an admitted refresh to the application policy and
     * `ApplicationAccess`.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @param  \SineMacula\Laravel\Authentication\Admission\Admitted  $admitted
     * @return \SineMacula\Laravel\Authentication\Admission\Admitted|\SineMacula\Laravel\Authentication\Admission\Refused
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function admitByPolicy(EloquentSession&Model $session, Admitted $admitted): Admitted|Refused
    {
        $policy  = Container::getInstance()->make(ApplicationPolicy::class);
        $method  = WriteConnection::during($session, static fn (): ?string => $session->getSignInMethod());
        $allowed = $method !== null && $policy->allowsMethod($this->guard, $method);

        $refusal = match (true) {
            !$allowed                                                       => FailureReason::METHOD_NOT_ALLOWED,
            !PrincipalAdmission::mayUse($this->guard, $admitted->principal) => FailureReason::PRINCIPAL_INELIGIBLE,
            default                                                         => null,
        };

        return $refusal === null ? $admitted : Refused::after($refusal, $admitted);
    }

    /**
     * Hold the admitted principal to the session's active tenant, read on the
     * write connection.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @param  \SineMacula\Laravel\Authentication\Admission\Admitted  $admitted
     * @return \SineMacula\Laravel\Authentication\Admission\Admitted|\SineMacula\Laravel\Authentication\Admission\Refused
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \LogicException
     */
    private static function inActiveTenant(EloquentSession&Model $session, Admitted $admitted): Admitted|Refused
    {
        $tenantId = WriteConnection::during($session, static fn (): ?string => $session->getTenantId());
        $tenant   = TenantAdmission::recorded($admitted->principal, $tenantId, true);

        return $tenant instanceof FailureReason
            ? Refused::after($tenant, $admitted)
            : new Admitted($admitted->identity, $admitted->principal, $tenant, $session);
    }

    /**
     * Reload the session's owner through the guard's identity provider and
     * confirm it is that exact owner.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Identity
     */
    private function owner(EloquentSession&Model $session): ?Identity
    {
        $ownerKey = SessionOwnership::ownerKey($session);
        $identity = $ownerKey === null ? null : $this->provider->retrieveById($ownerKey);

        return $identity instanceof Identity && SessionOwnership::isOwner($session, $identity) ? $identity : null;
    }

    /**
     * Resolve a principal for the identity, with the token's hint when it
     * carries one.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  mixed  $hint
     * @return \SineMacula\Laravel\Authentication\Contracts\Principal|\SineMacula\Laravel\Authentication\Events\Enums\FailureReason
     *
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    private function principal(Identity $identity, mixed $hint): FailureReason|Principal
    {
        $principal = $hint === null
            ? $this->resolver->resolve($identity)
            : $this->resolver->resolve($identity, $hint);

        if ($hint !== null && !IdentifierCoercion::matches($principal?->getPrincipalIdentifier(), $hint)) {
            return FailureReason::PRINCIPAL_MISMATCH;
        }

        return $principal instanceof Principal ? $principal : FailureReason::PRINCIPAL_UNRESOLVED;
    }
}
