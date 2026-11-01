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
 * Decides whom a session's refresh token signs in again: the session's owner,
 * reloaded through the guard's identity provider so the provider's scopes
 * apply, as the principal the token names (or the resolver's default), with the
 * identity, principal and its own tenant active, the application policy still
 * allowing the session's method, `ApplicationAccess` still letting the
 * principal use the application, and the session's active tenant still one the
 * principal may act in (`TenantAccess`) and active. None of its refusals
 * revokes the session.
 *
 * Built for one exchange with the guard's current provider and resolver, so it
 * keeps nothing between exchanges.
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
     * Admit the session: its owner, active, as the principal the token's hint
     * names (or the resolver's default), in the session's active tenant.
     * Returns the admitted session with that tenant, or the refusal with as
     * much of it as was resolved (`tenant_inactive` when the active tenant no
     * longer resolves or is inactive, `tenant_ineligible` when `TenantAccess`
     * no longer lets the principal act in it). A principal the session does not
     * record is admitted in its own tenant, for the caller to refuse as
     * `session_principal_mismatch` before anything is asked of a tenant the
     * session acts in for another principal.
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
     * Admit the session's owner, active, as the principal the hint names (or
     * the resolver's default), held to the application policy and
     * `ApplicationAccess`, in the principal's own tenant, whatever tenant the
     * session acts in: for a switch, which admits its destination tenant
     * itself.
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
     * Admit the session's active owner as the principal the token names (or the
     * resolver's default): the principal and its tenant must be active, the
     * application policy must still allow the session's method, and
     * `ApplicationAccess` the principal.
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
     * Hold an admitted refresh to the application: the policy must still allow
     * the method that started the session (a session that records none fails
     * closed, as `method_not_allowed`), and `ApplicationAccess` must still let
     * the principal use the application (`principal_ineligible`). A refresh
     * names no identifier, so the verified-identifier requirement does not
     * apply to it. The method is read, and the access contract asked, on the
     * write connection, so a lagging replica can neither allow a method the
     * primary no longer records for the session nor answer from rows the
     * primary has since changed.
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
     * write connection: the principal's own when the identifiers match, any
     * other through the `TenantResolver`, still one `TenantAccess` lets the
     * principal act in, and active.
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
     * Reload the session's owner through the guard's identity provider, so the
     * provider's own scoping applies, and confirm it is that exact owner. A
     * session row with no owner key, or a provider answer that is not the owner
     * (no row through this provider, or another model sharing the key), yields
     * `null`, which fails as `identity_unknown`.
     *
     * The provider is asked for the owner key the session row stores, which is
     * the identity's primary key; providers find identities by their auth
     * identifier, which is the primary key unless the identity model overrides
     * `getAuthIdentifierName()`.
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
     * Resolve a principal for the refresh-flow identity through the bound
     * resolver, with the token's hint when it carries one. An
     * `UnresolvableIdentityException` is a misconfiguration and propagates as a
     * server error rather than being reported as a refresh failure.
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
