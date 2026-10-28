<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Guards;

use Illuminate\Support\Carbon;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\IdentityProvider;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\PrincipalResolver;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\Enums\AuthenticationFlow;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\EventContext;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Jwt\Enums\Claims;
use SineMacula\Laravel\Authentication\Jwt\Enums\TokenType;
use SineMacula\Laravel\Authentication\Jwt\IdentifierCoercion;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenService;
use SineMacula\Laravel\Authentication\Sessions\Admission\AdmittedSignIn;
use SineMacula\Laravel\Authentication\Sessions\Admission\RefusedSignIn;

/**
 * Decides whom a request's access token authenticates, and why not when it does
 * not.
 *
 * Checked in order, each failure with its own reason: the token itself
 * (`token_invalid`); the identity its `sub` names, reloaded through the guard's
 * provider (`identity_unknown`) and active (`identity_inactive`); the principal
 * its `pid` names, which must resolve to exactly that principal
 * (`principal_mismatch`) and be active in an active tenant
 * (`principal_inactive`, `tenant_inactive`); and, for a token that names a
 * device, that device among the identity's own (`device_unknown`), of this
 * guard (`device_guard_mismatch`), not revoked (`device_revoked`) and with a
 * session that has not ended (`session_expired`). Fail closed: a token that
 * names a principal or device that does not resolve exactly is rejected rather
 * than downgraded.
 *
 * Built for one request with the guard's current collaborators, so it keeps
 * nothing between requests.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class BearerAuthentication
{
    /**
     * Constructor.
     *
     * @param  string  $guard
     * @param  \SineMacula\Laravel\Authentication\Jwt\JwtTokenService  $tokens
     * @param  \SineMacula\Laravel\Authentication\Contracts\IdentityProvider  $provider
     * @param  \SineMacula\Laravel\Authentication\Contracts\PrincipalResolver  $resolver
     */
    public function __construct(

        /** Name of the guard the token must belong to. */
        private string $guard,

        /** The guard's token service, which parses the token. */
        private JwtTokenService $tokens,

        /** The guard's identity provider, which reloads the token's subject. */
        private IdentityProvider $provider,

        /** The guard's principal resolver. */
        private PrincipalResolver $resolver,
    ) {}

    /**
     * Authenticate the access token for a request from the client: the admitted
     * identity, principal, the tenant its activity check loaded, and the
     * device, or the failure that reports why not, with as much of the context
     * as was established (the device id the token named included).
     *
     * @param  string  $token
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Authentication\Events\AuthenticationFailed|\SineMacula\Laravel\Authentication\Sessions\Admission\AdmittedSignIn
     *
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    public function authenticate(#[\SensitiveParameter] string $token, ClientContext $client): AdmittedSignIn|AuthenticationFailed
    {
        $claims = $this->tokens->parse($token, TokenType::ACCESS);

        if ($claims === null) {
            return $this->failed(new RefusedSignIn(FailureReason::TOKEN_INVALID), $client, null);
        }

        $deviceId = $claims[Claims::DEVICE_ID->value] ?? null;
        $admitted = $this->admit($claims);
        $admitted = $admitted instanceof AdmittedSignIn ? $this->onDevice($admitted, $deviceId) : $admitted;

        return $admitted instanceof RefusedSignIn ? $this->failed($admitted, $client, IdentifierCoercion::stringify($deviceId)) : $admitted;
    }

    /**
     * Admit the identity the claims name as the principal they name: the
     * identity must be found and active, and the principal must resolve exactly
     * and be active in an active tenant.
     *
     * @param  array<string, mixed>  $claims
     * @return \SineMacula\Laravel\Authentication\Sessions\Admission\AdmittedSignIn|\SineMacula\Laravel\Authentication\Sessions\Admission\RefusedSignIn
     *
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    private function admit(#[\SensitiveParameter] array $claims): AdmittedSignIn|RefusedSignIn
    {
        $identity = $this->provider->retrieveById($claims[Claims::SUBJECT->value]);

        if (!$identity instanceof Identity || !ActivationPolicy::isActive($identity)) {
            return $identity instanceof Identity
                ? new RefusedSignIn(FailureReason::IDENTITY_INACTIVE, $identity)
                : new RefusedSignIn(FailureReason::IDENTITY_UNKNOWN);
        }

        return $this->admitAs($identity, $claims[Claims::PRINCIPAL_ID->value]);
    }

    /**
     * Admit the active identity as the principal the `pid` names, which the
     * resolver must return exactly, and which must be active in an active
     * tenant.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  mixed  $hint
     * @return \SineMacula\Laravel\Authentication\Sessions\Admission\AdmittedSignIn|\SineMacula\Laravel\Authentication\Sessions\Admission\RefusedSignIn
     *
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    private function admitAs(Identity $identity, mixed $hint): AdmittedSignIn|RefusedSignIn
    {
        $principal = $this->resolver->resolve($identity, $hint);

        if (!$principal instanceof Principal || !IdentifierCoercion::matches($principal->getPrincipalIdentifier(), $hint)) {
            return new RefusedSignIn(FailureReason::PRINCIPAL_MISMATCH, $identity);
        }

        if (!ActivationPolicy::isActive($principal)) {
            return new RefusedSignIn(FailureReason::PRINCIPAL_INACTIVE, $identity, $principal);
        }

        $tenant = ActivationPolicy::activeTenant($principal);

        return $tenant === false
            ? new RefusedSignIn(FailureReason::TENANT_INACTIVE, $identity, $principal)
            : new AdmittedSignIn($identity, $principal, $tenant);
    }

    /**
     * Hold the admitted token to the device it names, when it names one: the
     * device must be one of the identity's own, of this guard, not revoked, and
     * with a session that has not ended. A token that names no device is
     * admitted as it is.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\Admission\AdmittedSignIn  $admitted
     * @param  mixed  $deviceId
     * @return \SineMacula\Laravel\Authentication\Sessions\Admission\AdmittedSignIn|\SineMacula\Laravel\Authentication\Sessions\Admission\RefusedSignIn
     *
     * @throws \LogicException
     */
    private function onDevice(AdmittedSignIn $admitted, mixed $deviceId): AdmittedSignIn|RefusedSignIn
    {
        if ($deviceId === null) {
            return $admitted;
        }

        $device  = OwnedDevice::find($admitted->identity, $deviceId);
        $refusal = $device === null ? FailureReason::DEVICE_UNKNOWN : OwnedDevice::refusal($device, $this->guard, Carbon::now());

        return $refusal === null ? $admitted->on($device) : RefusedSignIn::after($refusal, $admitted->on($device));
    }

    /**
     * The failure event of a refused token, with the guard, the client, the
     * context the refusal established, the method the device's session records
     * when a device was found, and the device id the token named.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\Admission\RefusedSignIn  $refused
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @param  ?string  $deviceId
     * @return \SineMacula\Laravel\Authentication\Events\AuthenticationFailed
     */
    private function failed(RefusedSignIn $refused, ClientContext $client, ?string $deviceId): AuthenticationFailed
    {
        $device  = $refused->device;
        $context = new EventContext($this->guard, $client, $refused->identity, $refused->principal, $refused->tenant, $device, $device?->getSignInMethod(), $deviceId);

        return new AuthenticationFailed($context, AuthenticationFlow::BEARER, $refused->reason);
    }
}
