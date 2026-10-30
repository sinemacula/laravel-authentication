<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\ClientCredentials;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Container\Container;
use Illuminate\Http\Request;
use SineMacula\Laravel\Authentication\Admission\Admitted;
use SineMacula\Laravel\Authentication\Admission\Refused;
use SineMacula\Laravel\Authentication\ApiKeys\ApiKeyAuthentication;
use SineMacula\Laravel\Authentication\ApiKeys\ApiKeyLookup;
use SineMacula\Laravel\Authentication\ApiKeys\ApiKeyOutcome;
use SineMacula\Laravel\Authentication\Contracts\AttemptLimiter;
use SineMacula\Laravel\Authentication\Contracts\AudiencePolicy;
use SineMacula\Laravel\Authentication\Contracts\MachineIdentity;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\ClientCredentialsGranted;
use SineMacula\Laravel\Authentication\Events\Enums\AuthenticationFlow;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\EventContext;
use SineMacula\Laravel\Authentication\Exceptions\InvalidScopeException;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Jwt\Enums\Claims;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenServiceFactory;
use SineMacula\Laravel\Authentication\Models\ApiKey;
use SineMacula\Laravel\Authentication\RateLimiting\AttemptSubject;
use SineMacula\Laravel\Authentication\RateLimiting\Enums\AttemptFlow;
use SineMacula\Laravel\Authentication\Scopes\Scopes;

/**
 * A `jwt` guard's OAuth 2.0 client credentials exchange (RFC 6749 section 4.4),
 * `Auth::clientCredentials($guard)`: a non-human identity's API key, presented
 * as a client id (its public part) and secret, exchanged for a short-lived
 * access token of the guard. No device is created and no refresh token issued.
 *
 * In order: the guard's audience must list `client_credentials`
 * (`unauthorized_client`); the IP address must not have used up its failures
 * for now, nor the client id when the guard limits it, which it does not by
 * default, as a client id is no secret (`slow_down`, 429 with `Retry-After`);
 * the key must be this guard's, live, its secret right, and its owner and
 * principal admitted as on an `api_key` guard (`invalid_client`, or
 * `unauthorized_client` for a principal the audience does not admit); the
 * requested scope, space-separated, must be granted to the key (none asks for
 * every granted scope; else `invalid_scope`). The token then carries the key's
 * id in `cid` and the scopes in `scope`, lives the guard's access lifetime for
 * the principal's type and never past the key's expiry, and is checked against
 * its key on every request, so revoking the key, or the end of its rotation's
 * overlap, ends it at once. Only failures to authenticate the client are
 * counted. Every failure dispatches `AuthenticationFailed` (flow
 * `client_credentials`) with the client id when it is a key's public part in
 * form, and none otherwise, so a secret sent as the id is never reported; a
 * grant dispatches `ClientCredentialsGranted`.
 *
 * Reads the guard's provider, resolver, dispatcher and request each time it
 * runs, so it keeps nothing between calls.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class ClientCredentialsExchange
{
    /** @var string The credential kind a guard's audience lists to allow the exchange, and the method its contexts report. */
    public const string METHOD = 'client_credentials';

    /** @var string The grant type a token request names. */
    public const string GRANT_TYPE = 'client_credentials';

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Guards\JwtGuard  $guard
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** The guard the access tokens are for. */
        private JwtGuard $guard,

        /** Container the audience policy, the attempt limiter and the token services are resolved from. */
        private Container $container,
    ) {}

    /**
     * Exchange the client id and secret for an access token granting the
     * requested scope (every granted scope for none), for a request from the
     * client (the guard's request's by default).
     *
     * @param  string  $clientId
     * @param  string  $clientSecret
     * @param  ?string  $scope
     * @param  ?\SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Authentication\ClientCredentials\ClientCredentialsResult
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Random\RandomException
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    public function exchange(string $clientId, #[\SensitiveParameter] string $clientSecret, ?string $scope = null, ?ClientContext $client = null): ClientCredentialsResult
    {
        return $this->exchangeFor(new PresentedClient($clientId, $clientSecret, $scope, false), $client ?? ClientContext::fromRequest($this->guard->getRequest()));
    }

    /**
     * Read a token request (the guard's request by default) and exchange the
     * client it authenticates: `grant_type`, the client's authentication (HTTP
     * Basic or `client_id` and `client_secret` in the body, never both) and
     * `scope`, all from a form-encoded POST body. A request not in form is
     * refused (`invalid_request`, `unsupported_grant_type`, `invalid_client`)
     * and reported as `invalid_credentials`, without counting it.
     *
     * @param  ?\Illuminate\Http\Request  $request
     * @return \SineMacula\Laravel\Authentication\ClientCredentials\ClientCredentialsResult
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Random\RandomException
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    public function fromRequest(?Request $request = null): ClientCredentialsResult
    {
        $request ??= $this->guard->getRequest();
        $client    = ClientContext::fromRequest($request);
        $presented = ClientCredentialsRequest::read($request);

        if ($presented instanceof PresentedClient) {
            return $this->exchangeFor($presented, $client);
        }

        $basic = ClientCredentialsRequest::usesBasic($request) && $presented === ClientCredentialsResult::INVALID_CLIENT;

        return $this->refuse(new EventContext($this->guard->getName(), $client, method: self::METHOD), FailureReason::INVALID_CREDENTIALS, $presented, null, null, $basic);
    }

    /**
     * Exchange a presented client.
     *
     * @param  \SineMacula\Laravel\Authentication\ClientCredentials\PresentedClient  $presented
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Authentication\ClientCredentials\ClientCredentialsResult
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Random\RandomException
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    private function exchangeFor(PresentedClient $presented, ClientContext $client): ClientCredentialsResult
    {
        $guard    = $this->guard->getName();
        $context  = new EventContext($guard, $client, method: self::METHOD);
        $audience = $this->audience();

        if (!$audience->allowsMethod($guard, self::METHOD)) {
            return $this->refuse($context, FailureReason::METHOD_NOT_ALLOWED, ClientCredentialsResult::UNAUTHORIZED_CLIENT, $presented->reportedId());
        }

        /** @var \SineMacula\Laravel\Authentication\Contracts\AttemptLimiter $limiter */
        $limiter = $this->container->make(AttemptLimiter::class);
        $subject = new AttemptSubject($guard, AttemptFlow::CLIENT_CREDENTIALS, $presented->clientId, null, $client->ip);
        $wait    = $limiter->blocked($subject);

        if ($wait !== null) {
            return $this->refuse($context, FailureReason::RATE_LIMITED, ClientCredentialsResult::SLOW_DOWN, $presented->reportedId(), $wait);
        }

        return $this->authenticated($presented, $client, $limiter, $subject, $audience);
    }

    /**
     * Authenticate the presented client as an API key of the guard and grant it
     * an access token, or refuse it, counting the failure.
     *
     * @param  \SineMacula\Laravel\Authentication\ClientCredentials\PresentedClient  $presented
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @param  \SineMacula\Laravel\Authentication\Contracts\AttemptLimiter  $limiter
     * @param  \SineMacula\Laravel\Authentication\RateLimiting\AttemptSubject  $subject
     * @param  \SineMacula\Laravel\Authentication\Contracts\AudiencePolicy  $audience
     * @return \SineMacula\Laravel\Authentication\ClientCredentials\ClientCredentialsResult
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Random\RandomException
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    private function authenticated(
        PresentedClient $presented,
        ClientContext $client,
        AttemptLimiter $limiter,
        AttemptSubject $subject,
        AudiencePolicy $audience,
    ): ClientCredentialsResult {
        $now     = CarbonImmutable::now()->startOfSecond();
        $outcome = (new ApiKeyAuthentication($this->guard->getName(), self::METHOD, $this->guard->getProvider(), $this->guard->getPrincipalResolver(), $audience))
            ->authenticate($presented->clientId, $presented->clientSecret(), $now);

        if ($outcome->admission instanceof Refused || $outcome->key === null) {

            $limiter->recordFailure($subject);

            return $this->refuseClient($outcome, $presented, $client);
        }

        return $this->grant($outcome->key, $outcome->admission, $presented, $client, $now);
    }

    /**
     * Issue the access token for the admitted key, granting the requested scope
     * when the key grants it, and record the key's use.
     *
     * @param  \SineMacula\Laravel\Authentication\Models\ApiKey  $key
     * @param  \SineMacula\Laravel\Authentication\Admission\Admitted  $admitted
     * @param  \SineMacula\Laravel\Authentication\ClientCredentials\PresentedClient  $presented
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @param  \Carbon\CarbonImmutable  $now
     * @return \SineMacula\Laravel\Authentication\ClientCredentials\ClientCredentialsResult
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Random\RandomException
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function grant(ApiKey $key, Admitted $admitted, PresentedClient $presented, ClientContext $client, CarbonImmutable $now): ClientCredentialsResult
    {
        $scopes  = self::requested($presented->scope, $key->scopes);
        $context = new EventContext(
            $key->guard,
            $client,
            $admitted->identity,
            $admitted->principal,
            $admitted->tenant,
            method: self::METHOD,
            credentialId: $key->id,
            scopes: $scopes ?? $key->scopes,
        );

        if ($scopes === null) {
            return $this->refuse($context, FailureReason::SCOPE_INVALID, ClientCredentialsResult::INVALID_SCOPE, $presented->reportedId());
        }

        $identity = $admitted->identity;

        assert($identity instanceof MachineIdentity);

        /** @var \SineMacula\Laravel\Authentication\Jwt\JwtTokenServiceFactory $factory */
        $factory = $this->container->make(JwtTokenServiceFactory::class);
        $tokens  = $factory->forGuard($key->guard);
        $token   = $tokens->issueClientAccessToken($identity, $admitted->principal, $key->id, $scopes, $key->expires_at, $now);
        $expires = $tokens->parse($token)[Claims::EXPIRES_AT->value] ?? null;

        assert(is_int($expires));

        ApiKeyLookup::recordUse($key, $now);

        $this->guard->getDispatcher()->dispatch(new ClientCredentialsGranted($context));

        return ClientCredentialsResult::granted($token, $expires - $now->getTimestamp(), $scopes);
    }

    /**
     * Refuse a client that failed to authenticate: `unauthorized_client` for a
     * principal the guard's audience does not admit, `invalid_client`
     * otherwise, with the context established by then.
     *
     * @param  \SineMacula\Laravel\Authentication\ApiKeys\ApiKeyOutcome  $outcome
     * @param  \SineMacula\Laravel\Authentication\ClientCredentials\PresentedClient  $presented
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Authentication\ClientCredentials\ClientCredentialsResult
     */
    private function refuseClient(ApiKeyOutcome $outcome, PresentedClient $presented, ClientContext $client): ClientCredentialsResult
    {
        $refused = $outcome->admission instanceof Refused ? $outcome->admission : new Refused(FailureReason::CREDENTIAL_INVALID);
        $error   = $refused->reason === FailureReason::PRINCIPAL_INELIGIBLE ? ClientCredentialsResult::UNAUTHORIZED_CLIENT : ClientCredentialsResult::INVALID_CLIENT;

        $guard = $this->guard->getName();
        $realm = $presented->basic && $error === ClientCredentialsResult::INVALID_CLIENT ? $guard : null;

        $this->guard->getDispatcher()->dispatch($outcome->failure($refused, $guard, AuthenticationFlow::CLIENT_CREDENTIALS, self::METHOD, $client, $presented->reportedId()));

        return ClientCredentialsResult::failed($refused->reason, $error, null, $realm);
    }

    /**
     * Report a refusal and answer it.
     *
     * @param  \SineMacula\Laravel\Authentication\Events\EventContext  $context
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\FailureReason  $reason
     * @param  string  $error
     * @param  ?string  $clientId
     * @param  ?int  $retryAfter
     * @param  bool  $basic
     * @return \SineMacula\Laravel\Authentication\ClientCredentials\ClientCredentialsResult
     */
    private function refuse(EventContext $context, FailureReason $reason, string $error, ?string $clientId, ?int $retryAfter = null, bool $basic = false): ClientCredentialsResult
    {
        $failure = new AuthenticationFailed($context, AuthenticationFlow::CLIENT_CREDENTIALS, $reason, $clientId, $retryAfter);

        $this->guard->getDispatcher()->dispatch($failure);

        return ClientCredentialsResult::failed($reason, $error, $retryAfter, $basic ? $this->guard->getName() : null);
    }

    /**
     * The audience policy.
     *
     * @return \SineMacula\Laravel\Authentication\Contracts\AudiencePolicy
     */
    private function audience(): AudiencePolicy
    {
        /** @var \SineMacula\Laravel\Authentication\Contracts\AudiencePolicy */
        return $this->container->make(AudiencePolicy::class);
    }

    /**
     * The scopes a request for the scope string may be granted: every granted
     * scope for none or an empty one, else the requested ones when the key
     * grants them all, or `null` when the request is malformed or asks for
     * more.
     *
     * @param  ?string  $scope
     * @param  list<string>  $granted
     * @return ?list<string>
     */
    private static function requested(?string $scope, array $granted): ?array
    {
        if ($scope === null || $scope === '') {
            return $granted;
        }

        try {
            $requested = Scopes::parse($scope);
        } catch (InvalidScopeException) {
            return null;
        }

        return Scopes::isSubset($requested, $granted) ? $requested : null;
    }
}
