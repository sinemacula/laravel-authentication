<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Guards;

use Carbon\CarbonImmutable;
use Carbon\CarbonInterface;
use Illuminate\Support\Carbon;
use SineMacula\Laravel\Authentication\Admission\ActivationPolicy;
use SineMacula\Laravel\Authentication\Admission\Admitted;
use SineMacula\Laravel\Authentication\Admission\Refused;
use SineMacula\Laravel\Authentication\Admission\TenantAdmission;
use SineMacula\Laravel\Authentication\ApiKeys\ApiKeyLookup;
use SineMacula\Laravel\Authentication\ApiKeys\CredentialBinding;
use SineMacula\Laravel\Authentication\ClientCredentials\ClientCredentialsExchange;
use SineMacula\Laravel\Authentication\Contracts\HasTokensValidAfter;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\IdentityProvider;
use SineMacula\Laravel\Authentication\Contracts\MachineIdentity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\PrincipalResolver;
use SineMacula\Laravel\Authentication\Contracts\Session;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
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
use SineMacula\Laravel\Authentication\SessionRecords\IdentitySessions;
use SineMacula\Laravel\Authentication\SessionRecords\OwnedSession;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;

/**
 * Decides whom a request's access token authenticates, and why not when it does
 * not.
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
     * Authenticate the access token for a request from the client, or report
     * why it was refused.
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
            return $this->failed(new Refused(FailureReason::TOKEN_INVALID), $client, null, null);
        }

        $credential = MachineTokens::credential($claims) ?: null;
        $sessionId  = $claims[Claims::SESSION_ID->value] ?? null;
        $admitted   = $credential === null ? $this->admit($claims, false) : $this->admitForKey($claims, $credential[0]);
        $admitted   = $admitted instanceof Admitted ? $this->onSession($admitted, $sessionId, $claims) : $admitted;

        return $admitted instanceof Refused
            ? $this->failed($admitted, $client, IdentifierCoercion::stringify($sessionId), $credential)
            : new AuthenticatedBearer($admitted, $credential[0] ?? null, $credential[1] ?? null);
    }

    /**
     * Admit a client credentials token on its live API key of this guard.
     *
     * @param  array<string, mixed>  $claims
     * @param  string  $credentialId
     * @return \SineMacula\Laravel\Authentication\Admission\Admitted|\SineMacula\Laravel\Authentication\Admission\Refused
     *
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    private function admitForKey(#[\SensitiveParameter] array $claims, #[\SensitiveParameter] string $credentialId): Admitted|Refused
    {
        $key = $this->liveKey($credentialId);

        if ($key instanceof FailureReason) {
            return new Refused($key);
        }

        $admitted = $this->admit($claims, true);
        $binding  = $admitted instanceof Admitted ? CredentialBinding::refusal($key, $admitted->identity, $admitted->principal, $admitted->tenant) : null;

        return $admitted instanceof Admitted && $binding !== null ? Refused::after($binding, $admitted) : $admitted;
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
     * Admit the identity the claims name, of the kind the token's subject type
     * says, as the principal they name.
     *
     * @param  array<string, mixed>  $claims
     * @param  bool  $machine
     * @return \SineMacula\Laravel\Authentication\Admission\Admitted|\SineMacula\Laravel\Authentication\Admission\Refused
     *
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    private function admit(#[\SensitiveParameter] array $claims, bool $machine): Admitted|Refused
    {
        $identity = $this->provider->retrieveById($claims[Claims::SUBJECT->value]);

        if (!$identity instanceof Identity) {
            return new Refused(FailureReason::IDENTITY_UNKNOWN);
        }

        $refusal = match (true) {
            !$machine && $identity instanceof MachineIdentity  => FailureReason::MACHINE_IDENTITY,
            $machine  && !$identity instanceof MachineIdentity => FailureReason::CREDENTIAL_INVALID,
            !ActivationPolicy::isActive($identity)             => FailureReason::IDENTITY_INACTIVE,
            default                                            => null,
        };

        return $refusal === null ? $this->admitAs($identity, $claims[Claims::PRINCIPAL->value]) : new Refused($refusal, $identity);
    }

    /**
     * Admit the active identity as exactly the principal the `principal` claim
     * names, active in an active tenant.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  mixed  $hint
     * @return \SineMacula\Laravel\Authentication\Admission\Admitted|\SineMacula\Laravel\Authentication\Admission\Refused
     *
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    private function admitAs(Identity $identity, mixed $hint): Admitted|Refused
    {
        $principal = $this->resolver->resolve($identity, $hint);

        if (!$principal instanceof Principal || !IdentifierCoercion::matches($principal->getPrincipalIdentifier(), $hint)) {
            return new Refused(FailureReason::PRINCIPAL_MISMATCH, $identity);
        }

        if (!ActivationPolicy::isActive($principal)) {
            return new Refused(FailureReason::PRINCIPAL_INACTIVE, $identity, $principal);
        }

        $tenant = ActivationPolicy::activeTenant($principal);

        return $tenant === false
            ? new Refused(FailureReason::TENANT_INACTIVE, $identity, $principal)
            : new Admitted($identity, $principal, $tenant);
    }

    /**
     * Hold the admitted token to the session it names, or to the subject's
     * "tokens valid after" cutoff when it names none.
     *
     * @param  \SineMacula\Laravel\Authentication\Admission\Admitted  $admitted
     * @param  mixed  $sessionId
     * @param  array<string, mixed>  $claims
     * @return \SineMacula\Laravel\Authentication\Admission\Admitted|\SineMacula\Laravel\Authentication\Admission\Refused
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \LogicException
     */
    private function onSession(Admitted $admitted, mixed $sessionId, #[\SensitiveParameter] array $claims): Admitted|Refused
    {
        $issuedAt = $claims[Claims::ISSUED_AT->value];

        if ($sessionId === null) {
            return self::isIssuedAfterCutoff($admitted, $issuedAt) ? $admitted : Refused::after(FailureReason::ISSUED_BEFORE_CUTOFF, $admitted);
        }

        $session = IdentitySessions::find($admitted->identity, $sessionId);

        if ($session === null) {
            return Refused::after(FailureReason::SESSION_UNKNOWN, $admitted);
        }

        $refusal = OwnedSession::refusal($session, $this->guard, Carbon::now()) ?? self::contextRefusal($session, $admitted->principal, $claims);

        return $refusal === null ? self::inActiveTenant($admitted, $session) : Refused::after($refusal, $admitted->on($session));
    }

    /**
     * Why the session may not serve a token of the principal with the claims,
     * or `null` when it may.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  array<string, mixed>  $claims
     * @return ?\SineMacula\Laravel\Authentication\Events\Enums\FailureReason
     *
     * @throws \LogicException
     */
    private static function contextRefusal(Session $session, Principal $principal, #[\SensitiveParameter] array $claims): ?FailureReason
    {
        return match (true) {
            !OwnedSession::actsIn($session, $claims[Claims::TENANT_ID->value] ?? null)      => FailureReason::SESSION_TENANT_MISMATCH,
            !OwnedSession::actsAs($session, $principal)                                     => FailureReason::SESSION_PRINCIPAL_MISMATCH,
            !OwnedSession::isIssuedSinceSwitch($session, $claims[Claims::ISSUED_AT->value]) => FailureReason::SESSION_SWITCHED,
            default                                                                         => null,
        };
    }

    /**
     * The admitted token on its session, in the session's active tenant, or
     * `tenant_inactive` when that tenant no longer resolves or is inactive.
     *
     * @param  \SineMacula\Laravel\Authentication\Admission\Admitted  $admitted
     * @param  \SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @return \SineMacula\Laravel\Authentication\Admission\Admitted|\SineMacula\Laravel\Authentication\Admission\Refused
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \LogicException
     */
    private static function inActiveTenant(Admitted $admitted, Session $session): Admitted|Refused
    {
        $tenantId = WriteConnection::during($session, static fn (): ?string => $session->getTenantId());
        $tenant   = $tenantId === IdentifierCoercion::stringify($admitted->tenant?->getTenantIdentifier())
            ? $admitted->tenant
            : TenantAdmission::recorded($admitted->principal, $tenantId, false);

        return $tenant instanceof FailureReason
            ? Refused::after($tenant, $admitted->on($session))
            : new Admitted($admitted->identity, $admitted->principal, $tenant, $session);
    }

    /**
     * Whether a token issued without a session was issued after the identity's
     * and the principal's "tokens valid after" time.
     *
     * @param  \SineMacula\Laravel\Authentication\Admission\Admitted  $admitted
     * @param  mixed  $issuedAt
     * @return bool
     *
     * @throws \LogicException
     */
    private static function isIssuedAfterCutoff(Admitted $admitted, mixed $issuedAt): bool
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
     * The failure event of a refused token, with as much of the context as the
     * refusal established.
     *
     * @param  \SineMacula\Laravel\Authentication\Admission\Refused  $refused
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @param  ?string  $sessionId
     * @param  ?array{0: string, 1: list<string>}  $credential
     * @return \SineMacula\Laravel\Authentication\Events\AuthenticationFailed
     */
    private function failed(Refused $refused, ClientContext $client, ?string $sessionId, #[\SensitiveParameter] ?array $credential): AuthenticationFailed
    {
        $session = $refused->session;
        $method  = $credential === null ? $session?->getSignInMethod() : ClientCredentialsExchange::METHOD;
        $context = new EventContext(
            $this->guard,
            $client,
            $refused->identity,
            $refused->principal,
            $refused->tenant,
            $session,
            $method,
            $sessionId,
            credentialId: $credential[0] ?? null,
            scopes: $credential[1]       ?? null,
        );

        return new AuthenticationFailed($context, AuthenticationFlow::BEARER, $refused->reason);
    }
}
