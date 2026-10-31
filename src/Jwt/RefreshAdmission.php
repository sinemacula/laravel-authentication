<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Jwt;

use Illuminate\Container\Container;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Admission\ActivationPolicy;
use SineMacula\Laravel\Authentication\Admission\Admitted;
use SineMacula\Laravel\Authentication\Admission\Refused;
use SineMacula\Laravel\Authentication\Contracts\AudiencePolicy;
use SineMacula\Laravel\Authentication\Contracts\EloquentDevice;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\IdentityProvider;
use SineMacula\Laravel\Authentication\Contracts\MachineIdentity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\PrincipalResolver;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use SineMacula\Laravel\Authentication\Devices\DeviceOwnership;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;

/**
 * Decides whom a device's refresh token signs in again: the device's owner,
 * reloaded through the guard's identity provider so the provider's scopes
 * apply, as the principal the token names (or the resolver's default), with the
 * identity, principal and tenant active and the guard's audience policy still
 * allowing the session. None of its refusals revokes the device.
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

        /** The guard's identity provider, which reloads the device owner. */
        private IdentityProvider $provider,

        /** The guard's principal resolver. */
        private PrincipalResolver $resolver,
    ) {}

    /**
     * Admit the device's session: its owner, active, as the principal the
     * token's hint names (or the resolver's default). Returns the admitted
     * session with the tenant its activity check loaded, or the refusal with as
     * much of it as was resolved.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentDevice  $device
     * @param  mixed  $principalHint
     * @return \SineMacula\Laravel\Authentication\Admission\Admitted|\SineMacula\Laravel\Authentication\Admission\Refused
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function admit(EloquentDevice&Model $device, mixed $principalHint): Admitted|Refused
    {
        $identity = $this->owner($device);

        if ($identity === null) {
            return new Refused(FailureReason::IDENTITY_UNKNOWN);
        }

        $refusal = match (true) {
            $identity instanceof MachineIdentity   => FailureReason::MACHINE_IDENTITY,
            !ActivationPolicy::isActive($identity) => FailureReason::IDENTITY_INACTIVE,
            default                                => null,
        };

        return $refusal === null ? $this->admitAs($device, $identity, $principalHint) : new Refused($refusal, $identity);
    }

    /**
     * Admit the device's active owner as the principal the token names (or the
     * resolver's default): the principal and its tenant must be active, and the
     * guard's audience policy must still allow the session.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentDevice  $device
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  mixed  $principalHint
     * @return \SineMacula\Laravel\Authentication\Admission\Admitted|\SineMacula\Laravel\Authentication\Admission\Refused
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function admitAs(EloquentDevice&Model $device, Identity $identity, mixed $principalHint): Admitted|Refused
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
            : $this->admitByPolicy($device, new Admitted($identity, $principal, $tenant, $device));
    }

    /**
     * Hold an admitted refresh to the guard's audience policy: the method that
     * started the session must still be allowed to (a device that records none
     * fails closed, as `method_not_allowed`), and the policy must still admit
     * the identity as the principal (`principal_ineligible`). A refresh names
     * no identifier, so the verified-identifier requirement does not apply to
     * it. The method is read on the write connection, so a lagging replica
     * cannot allow a method the primary no longer records for the device.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentDevice  $device
     * @param  \SineMacula\Laravel\Authentication\Admission\Admitted  $admitted
     * @return \SineMacula\Laravel\Authentication\Admission\Admitted|\SineMacula\Laravel\Authentication\Admission\Refused
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function admitByPolicy(EloquentDevice&Model $device, Admitted $admitted): Admitted|Refused
    {
        $policy  = Container::getInstance()->make(AudiencePolicy::class);
        $method  = WriteConnection::during($device, static fn (): ?string => $device->getSignInMethod());
        $allowed = $method !== null && $policy->allowsMethod($this->guard, $method);

        $refusal = match (true) {
            !$allowed                                                                              => FailureReason::METHOD_NOT_ALLOWED,
            $policy->admit($this->guard, $admitted->identity, $admitted->principal, null) !== null => FailureReason::PRINCIPAL_INELIGIBLE,
            default                                                                                => null,
        };

        return $refusal === null ? $admitted : Refused::after($refusal, $admitted);
    }

    /**
     * Reload the device's owner through the guard's identity provider, so the
     * provider's own scoping applies, and confirm it is that exact owner. A
     * device row with no owner key, or a provider answer that is not the owner
     * (no row through this provider, or another model sharing the key), yields
     * `null`, which fails as `identity_unknown`.
     *
     * The provider is asked for the owner key the device row stores, which is
     * the identity's primary key; providers find identities by their auth
     * identifier, which is the primary key unless the identity model overrides
     * `getAuthIdentifierName()`.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentDevice  $device
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Identity
     */
    private function owner(EloquentDevice&Model $device): ?Identity
    {
        $ownerKey = DeviceOwnership::ownerKey($device);
        $identity = $ownerKey === null ? null : $this->provider->retrieveById($ownerKey);

        return $identity instanceof Identity && DeviceOwnership::isOwner($device, $identity) ? $identity : null;
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
