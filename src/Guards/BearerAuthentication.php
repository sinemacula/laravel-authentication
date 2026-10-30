<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Guards;

use Carbon\CarbonImmutable;
use Carbon\CarbonInterface;
use Illuminate\Support\Carbon;
use SineMacula\Laravel\Authentication\ApiKeys\ApiKeyLookup;
use SineMacula\Laravel\Authentication\ApiKeys\CredentialBinding;
use SineMacula\Laravel\Authentication\ClientCredentials\ClientCredentialsExchange;
use SineMacula\Laravel\Authentication\Contracts\Device;
use SineMacula\Laravel\Authentication\Contracts\HasTokensValidAfter;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\IdentityProvider;
use SineMacula\Laravel\Authentication\Contracts\MachineIdentity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\PrincipalResolver;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use SineMacula\Laravel\Authentication\Devices\IdentityDevices;
use SineMacula\Laravel\Authentication\Devices\OwnedDevice;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\Enums\AuthenticationFlow;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\EventContext;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Jwt\Enums\Claims;
use SineMacula\Laravel\Authentication\Jwt\Enums\TokenType;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenService;
use SineMacula\Laravel\Authentication\Jwt\MachineTokens;
use SineMacula\Laravel\Authentication\Models\ApiKey;
use SineMacula\Laravel\Authentication\Sessions\Admission\AdmittedSignIn;
use SineMacula\Laravel\Authentication\Sessions\Admission\RefusedSignIn;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;

/**
 * Decides whom a request's access token authenticates, and why not when it does
 * not.
 *
 * Checked in order, each failure with its own reason: the token itself
 * (`token_invalid`); for a client credentials token (one with `cid`), its API
 * key: this guard's, live and not revoked (`credential_invalid`,
 * `credential_expired`, `credential_revoked`); the identity its `sub` names,
 * reloaded through the guard's provider (`identity_unknown`), of the kind the
 * token is for (`machine_identity` for a session's token, `credential_invalid`
 * for a client credentials token) and active (`identity_inactive`); the
 * principal its `pid` names, which must resolve to exactly that principal
 * (`principal_mismatch`) and be active in an active tenant
 * (`principal_inactive`, `tenant_inactive`); for a token that names no device,
 * an issue time after the identity's and the principal's "tokens valid after"
 * time (`issued_before_cutoff`); and, for a token that names a device, that
 * device among the identity's own (`device_unknown`), of this guard
 * (`device_guard_mismatch`), not revoked (`device_revoked`), with a session
 * that has not ended (`session_expired`), and acting as the token's principal
 * with no principal switch after the token was issued
 * (`device_principal_mismatch`). Fail closed: a token that names a principal or
 * device that does not resolve exactly is rejected rather than downgraded.
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
     * device, with, for a client credentials token, its API key and scopes; or
     * the failure that reports why not, with as much of the context as was
     * established (the device id the token named included).
     *
     * @param  string  $token
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Authentication\Events\AuthenticationFailed|\SineMacula\Laravel\Authentication\Guards\AuthenticatedBearer
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    public function authenticate(#[\SensitiveParameter] string $token, ClientContext $client): AuthenticatedBearer|AuthenticationFailed
    {
        $claims = $this->tokens->parse($token, TokenType::ACCESS);

        if ($claims === null) {
            return $this->failed(new RefusedSignIn(FailureReason::TOKEN_INVALID), $client, null, null);
        }

        $credential = MachineTokens::credential($claims) ?: null;
        $deviceId   = $claims[Claims::DEVICE_ID->value] ?? null;
        $admitted   = $credential === null ? $this->admit($claims, false) : $this->admitForKey($claims, $credential[0]);
        $admitted   = $admitted instanceof AdmittedSignIn ? $this->onDevice($admitted, $deviceId, $claims[Claims::ISSUED_AT->value]) : $admitted;

        return $admitted instanceof RefusedSignIn
            ? $this->failed($admitted, $client, IdentifierCoercion::stringify($deviceId), $credential)
            : new AuthenticatedBearer($admitted, $credential[0] ?? null, $credential[1] ?? null);
    }

    /**
     * Admit a client credentials token: its API key, read by its id on the
     * write connection, must be this guard's (`credential_invalid`), not
     * revoked (`credential_revoked`) and not expired (`credential_expired`);
     * the identity and principal are then admitted as for any access token, the
     * subject must be a non-human identity, and the key's binding to its owner,
     * principal and tenant must still hold. Revoking a key, or the end of a
     * rotation's overlap, so ends its tokens at the next request.
     *
     * @param  array<string, mixed>  $claims
     * @param  string  $credentialId
     * @return \SineMacula\Laravel\Authentication\Sessions\Admission\AdmittedSignIn|\SineMacula\Laravel\Authentication\Sessions\Admission\RefusedSignIn
     *
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    private function admitForKey(#[\SensitiveParameter] array $claims, #[\SensitiveParameter] string $credentialId): AdmittedSignIn|RefusedSignIn
    {
        $key = $this->liveKey($credentialId);

        if ($key instanceof FailureReason) {
            return new RefusedSignIn($key);
        }

        $admitted = $this->admit($claims, true);
        $binding  = $admitted instanceof AdmittedSignIn ? CredentialBinding::refusal($key, $admitted->identity, $admitted->principal, $admitted->tenant) : null;

        return $admitted instanceof AdmittedSignIn && $binding !== null ? RefusedSignIn::after($binding, $admitted) : $admitted;
    }

    /**
     * The API key with the id, read on the write connection, when it is this
     * guard's and live, or why not.
     *
     * @param  string  $credentialId
     * @return \SineMacula\Laravel\Authentication\Events\Enums\FailureReason|\SineMacula\Laravel\Authentication\Models\ApiKey
     */
    private function liveKey(#[\SensitiveParameter] string $credentialId): ApiKey|FailureReason
    {
        $key = ApiKeyLookup::findById($credentialId);

        if ($key === null) {
            return FailureReason::CREDENTIAL_INVALID;
        }

        return ($key->guard === $this->guard ? ApiKeyLookup::refusal($key, $this->guard, CarbonImmutable::now()->startOfSecond()) : FailureReason::CREDENTIAL_INVALID) ?? $key;
    }

    /**
     * Admit the identity the claims name as the principal they name: the
     * identity must be found, of the kind the token is for (a non-human
     * identity's tokens come only from a client credentials exchange, so a
     * session's token naming one is refused as `machine_identity`, and a client
     * credentials token naming a human one as `credential_invalid`) and active,
     * and the principal must resolve exactly and be active in an active tenant.
     *
     * @param  array<string, mixed>  $claims
     * @param  bool  $client
     * @return \SineMacula\Laravel\Authentication\Sessions\Admission\AdmittedSignIn|\SineMacula\Laravel\Authentication\Sessions\Admission\RefusedSignIn
     *
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    private function admit(#[\SensitiveParameter] array $claims, bool $client): AdmittedSignIn|RefusedSignIn
    {
        $identity = $this->provider->retrieveById($claims[Claims::SUBJECT->value]);

        if (!$identity instanceof Identity) {
            return new RefusedSignIn(FailureReason::IDENTITY_UNKNOWN);
        }

        $refusal = match (true) {
            !$client && $identity instanceof MachineIdentity  => FailureReason::MACHINE_IDENTITY,
            $client  && !$identity instanceof MachineIdentity => FailureReason::CREDENTIAL_INVALID,
            !ActivationPolicy::isActive($identity)            => FailureReason::IDENTITY_INACTIVE,
            default                                           => null,
        };

        return $refusal === null ? $this->admitAs($identity, $claims[Claims::PRINCIPAL_ID->value]) : new RefusedSignIn($refusal, $identity);
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
     * with a session that has not ended, and the session must act as the
     * token's principal and not have switched principal since the token was
     * issued (`device_principal_mismatch`), so a switch ends the tokens of the
     * principal it switched from at once. A token that names no device has no
     * device to revoke, so it must instead have been issued after the "tokens
     * valid after" time of its identity and of its principal, when they record
     * one (`issued_before_cutoff`).
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\Admission\AdmittedSignIn  $admitted
     * @param  mixed  $deviceId
     * @param  mixed  $issuedAt
     * @return \SineMacula\Laravel\Authentication\Sessions\Admission\AdmittedSignIn|\SineMacula\Laravel\Authentication\Sessions\Admission\RefusedSignIn
     *
     * @throws \LogicException
     */
    private function onDevice(AdmittedSignIn $admitted, mixed $deviceId, mixed $issuedAt): AdmittedSignIn|RefusedSignIn
    {
        if ($deviceId === null) {
            return self::isIssuedAfterCutoff($admitted, $issuedAt) ? $admitted : RefusedSignIn::after(FailureReason::ISSUED_BEFORE_CUTOFF, $admitted);
        }

        $device  = IdentityDevices::find($admitted->identity, $deviceId);
        $refusal = $device === null
            ? FailureReason::DEVICE_UNKNOWN
            : OwnedDevice::refusal($device, $this->guard, Carbon::now()) ?? self::principalRefusal($device, $admitted->principal, $issuedAt);

        return $refusal === null ? $admitted->on($device) : RefusedSignIn::after($refusal, $admitted->on($device));
    }

    /**
     * Why the device's session may not serve a token of the principal issued at
     * the given time, or `null` when it may: the session must act as the
     * principal, and must not have switched principal after the token was
     * issued.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Device  $device
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  mixed  $issuedAt
     * @return ?\SineMacula\Laravel\Authentication\Events\Enums\FailureReason
     *
     * @throws \LogicException
     */
    private static function principalRefusal(Device $device, Principal $principal, mixed $issuedAt): ?FailureReason
    {
        return OwnedDevice::actsAs($device, $principal) && OwnedDevice::isIssuedSinceSwitch($device, $issuedAt) ? null : FailureReason::DEVICE_PRINCIPAL_MISMATCH;
    }

    /**
     * Whether a token issued without a device was issued after the "tokens
     * valid after" time of the identity and of the principal, each read on the
     * write connection from the model already loaded. Whole seconds: a token
     * issued at or before the time is rejected, since its `iat` cannot tell the
     * same second before the cutoff from after it. A subject that does not
     * record a time, or records none yet, does not limit the token.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\Admission\AdmittedSignIn  $admitted
     * @param  mixed  $issuedAt
     * @return bool
     *
     * @throws \LogicException
     */
    private static function isIssuedAfterCutoff(AdmittedSignIn $admitted, mixed $issuedAt): bool
    {
        foreach ([$admitted->identity, $admitted->principal] as $subject) {

            if (!$subject instanceof HasTokensValidAfter) {
                continue;
            }

            $cutoff = WriteConnection::during($subject, static fn (): ?CarbonInterface => $subject->getTokensValidAfter());

            if ($cutoff !== null && (!is_int($issuedAt) || $issuedAt <= $cutoff->getTimestamp())) {
                return false;
            }
        }

        return true;
    }

    /**
     * The failure event of a refused token, with the guard, the client, the
     * context the refusal established, the method the device's session records
     * when a device was found (`client_credentials` for a client credentials
     * token, with its key and scopes), and the device id the token named.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\Admission\RefusedSignIn  $refused
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @param  ?string  $deviceId
     * @param  ?array{0: string, 1: list<string>}  $credential
     * @return \SineMacula\Laravel\Authentication\Events\AuthenticationFailed
     */
    private function failed(RefusedSignIn $refused, ClientContext $client, ?string $deviceId, #[\SensitiveParameter] ?array $credential): AuthenticationFailed
    {
        $device  = $refused->device;
        $method  = $credential === null ? $device?->getSignInMethod() : ClientCredentialsExchange::METHOD;
        $context = new EventContext(
            $this->guard,
            $client,
            $refused->identity,
            $refused->principal,
            $refused->tenant,
            $device,
            $method,
            $deviceId,
            credentialId: $credential[0] ?? null,
            scopes: $credential[1]       ?? null,
        );

        return new AuthenticationFailed($context, AuthenticationFlow::BEARER, $refused->reason);
    }
}
