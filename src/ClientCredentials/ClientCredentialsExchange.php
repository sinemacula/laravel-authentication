<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\ClientCredentials;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Authentication\Admission\Admitted;
use SineMacula\Laravel\Authentication\Admission\Refused;
use SineMacula\Laravel\Authentication\ApiKeys\ApiKeyAuthentication;
use SineMacula\Laravel\Authentication\ApiKeys\ApiKeyLookup;
use SineMacula\Laravel\Authentication\ApiKeys\ApiKeyOutcome;
use SineMacula\Laravel\Authentication\ClientCredentials\Enums\ClientAuthentication;
use SineMacula\Laravel\Authentication\Contracts\ApplicationPolicy;
use SineMacula\Laravel\Authentication\Contracts\AttemptLimiter;
use SineMacula\Laravel\Authentication\Contracts\MachineIdentity;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\ClientCredentialsGranted;
use SineMacula\Laravel\Authentication\Events\Enums\AuthenticationFlow;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\EventContext;
use SineMacula\Laravel\Authentication\Exceptions\InvalidScopeException;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Jwt\Enums\Claims;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenServiceFactory;
use SineMacula\Laravel\Authentication\Models\ApiKey;
use SineMacula\Laravel\Authentication\RateLimiting\AttemptSubject;
use SineMacula\Laravel\Authentication\RateLimiting\Enums\AttemptFlow;
use SineMacula\Laravel\Authentication\Runtime\GuardContext;
use SineMacula\Laravel\Authentication\Scopes\Scopes;

/**
 * A `jwt` guard's OAuth 2.0 client credentials exchange (RFC 6749 section 4.4),
 * `Auth::clientCredentials($guard)`: a non-human identity's API key, presented
 * as a client id (its public part) and secret, exchanged for a short-lived
 * access token of the guard. No session is created and no refresh token issued.
 * It is off unless the guard's application lists `client_credentials`, and a
 * client authenticates with HTTP Basic, or in the body only where the
 * application sets `client_secret_post`. The grant is the client's own
 * authentication, so `invalid_grant` is never answered: a client that fails to
 * authenticate is `invalid_client`, always 401 with a Basic challenge.
 *
 * A token request `ClientCredentialsRequest::extract()` read is first refused
 * for its own form, before anything else is checked: `invalid_request` for one
 * not in form or authenticating the client both ways, `unsupported_grant_type`
 * for another grant, and `invalid_client` for client authentication that is
 * missing, malformed, or in the body where the application does not set
 * `client_secret_post`. Then, in order: the guard's application must list
 * `client_credentials` (`unauthorized_client`); the IP address must not have
 * used up its failures for now, nor the client id when the guard limits it,
 * which it does not by default, as a client id is no secret (`slow_down`, 429
 * with `Retry-After`); the key must be this guard's, live, its secret right,
 * and its owner and principal admitted as on an `api_key` guard
 * (`invalid_client`, or `unauthorized_client` for a principal
 * `ApplicationAccess` refuses, which is `principal_ineligible`); the requested
 * scope, space-separated, must be granted to the key (none asks for every
 * granted scope; else `invalid_scope`). The token then carries the key's id in
 * `cid` and the scopes in `scope`, lives the guard's access lifetime and never
 * past the key's expiry, and is checked against its key on every request, so
 * revoking the key, or the end of its rotation's overlap, ends it at once. Only
 * failures to authenticate the client are counted. Every failure dispatches
 * `AuthenticationFailed` (flow `client_credentials`) with the client id when it
 * is a key's public part in form, and none otherwise, so a secret sent as the
 * id is never reported; a grant dispatches `ClientCredentialsGranted`.
 *
 * Reads the provider, resolver and dispatcher from the guard's context each
 * time it runs, so it keeps nothing between calls; the client is the one each
 * call is given.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class ClientCredentialsExchange
{
    /** @var string The credential kind an application lists to allow the exchange, and the method its contexts report. */
    public const string METHOD = 'client_credentials';

    /** @var string The grant type a token request names. */
    public const string GRANT_TYPE = 'client_credentials';

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Runtime\GuardContext  $context
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** The context of the guard the access tokens are for. */
        private GuardContext $context,

        /** Container the application policy, the attempt limiter and the token services are resolved from. */
        private Container $container,
    ) {}

    /**
     * Exchange what a token request presented for an access token granting the
     * requested scope (every granted scope for none), for the client given:
     * what `ClientCredentialsRequest::extract()` answered (a `PresentedClient`
     * recording how the request authenticated the client, or the RFC 6749 error
     * it refused the request with), or a `PresentedClient` the application
     * built as its trusted description of a request it read itself, with the
     * request's `ClientContext`. Nothing is read from the guard's request.
     *
     * An error handed in is refused with it (`invalid_request`,
     * `unsupported_grant_type`, `invalid_client`), reported as
     * `invalid_credentials`, before any query and without counting it; any
     * other string is the caller's error (`InvalidArgumentException`), nothing
     * dispatched. A client authenticated in the body (`client_secret_post`) is
     * refused as `invalid_client` the same way unless the application allows
     * it. Then the exchange runs in the order the class describes, its limits
     * counting the client's IP address and its events carrying the client.
     *
     * @param  \SineMacula\Laravel\Authentication\ClientCredentials\PresentedClient|string  $presented
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Authentication\ClientCredentials\ClientCredentialsResult
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Random\RandomException
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    public function exchange(#[\SensitiveParameter] PresentedClient|string $presented, ClientContext $client): ClientCredentialsResult
    {
        $context = new EventContext($this->context->name(), $client, method: self::METHOD);

        if (is_string($presented)) {
            return $this->refuse($context, FailureReason::INVALID_CREDENTIALS, self::extractedError($presented), null);
        }

        $refusal = $this->authenticationRefusal($presented);

        return $refusal === null ? $this->exchangeFor($presented, $client) : $this->refuse($context, FailureReason::INVALID_CREDENTIALS, $refusal, null);
    }

    /**
     * The error an error `extract()` answered is refused with: the error itself
     * when it is one `extract()` answers, else a caller's error.
     *
     * @param  string  $error
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    private static function extractedError(string $error): string
    {
        if (!in_array($error, [ClientCredentialsResult::INVALID_REQUEST, ClientCredentialsResult::UNSUPPORTED_GRANT_TYPE, ClientCredentialsResult::INVALID_CLIENT], true)) {
            throw new \InvalidArgumentException("A token request is never refused as `{$error}`: hand in only what `ClientCredentialsRequest::extract()` answered.");
        }

        return $error;
    }

    /**
     * Why the way the client authenticated is refused, or `null` when it may:
     * in the body (`client_secret_post`) only where the application allows it.
     *
     * @param  \SineMacula\Laravel\Authentication\ClientCredentials\PresentedClient  $presented
     * @return ?string
     */
    private function authenticationRefusal(#[\SensitiveParameter] PresentedClient $presented): ?string
    {
        $allowed = $presented->authentication === ClientAuthentication::BASIC || $this->applicationPolicy()->allowsClientSecretPost($this->context->name());

        return $allowed ? null : ClientCredentialsResult::INVALID_CLIENT;
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
        $guard   = $this->context->name();
        $context = new EventContext($guard, $client, method: self::METHOD);
        $policy  = $this->applicationPolicy();

        if (!$policy->allowsMethod($guard, self::METHOD)) {
            return $this->refuse($context, FailureReason::METHOD_NOT_ALLOWED, ClientCredentialsResult::UNAUTHORIZED_CLIENT, $presented->reportedId());
        }

        /** @var \SineMacula\Laravel\Authentication\Contracts\AttemptLimiter $limiter */
        $limiter = $this->container->make(AttemptLimiter::class);
        $subject = new AttemptSubject($guard, AttemptFlow::CLIENT_CREDENTIALS, $presented->clientId, null, $client->ip);
        $wait    = $limiter->blocked($subject);

        if ($wait !== null) {
            return $this->refuse($context, FailureReason::RATE_LIMITED, ClientCredentialsResult::SLOW_DOWN, $presented->reportedId(), $wait);
        }

        return $this->authenticated($presented, $client, $limiter, $subject, $policy);
    }

    /**
     * Authenticate the presented client as an API key of the guard and grant it
     * an access token, or refuse it, counting the failure.
     *
     * @param  \SineMacula\Laravel\Authentication\ClientCredentials\PresentedClient  $presented
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @param  \SineMacula\Laravel\Authentication\Contracts\AttemptLimiter  $limiter
     * @param  \SineMacula\Laravel\Authentication\RateLimiting\AttemptSubject  $subject
     * @param  \SineMacula\Laravel\Authentication\Contracts\ApplicationPolicy  $policy
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
        ApplicationPolicy $policy,
    ): ClientCredentialsResult {
        $now     = CarbonImmutable::now()->startOfSecond();
        $outcome = (new ApiKeyAuthentication($this->context->name(), self::METHOD, $this->context->provider(), $this->context->resolver(), $policy))
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
        $token   = $tokens->issueClientAccessToken($identity, $admitted->principal, $admitted->tenant, $key->id, $scopes, $key->expires_at, $now);
        $expires = $tokens->parse($token)[Claims::EXPIRES_AT->value] ?? null;

        assert(is_int($expires));

        ApiKeyLookup::recordUse($key, $now);

        $this->context->dispatch(new ClientCredentialsGranted($context));

        return ClientCredentialsResult::granted($token, $expires - $now->getTimestamp(), $scopes);
    }

    /**
     * Refuse a client that failed to authenticate: `unauthorized_client` for a
     * principal `ApplicationAccess` refuses (`principal_ineligible`),
     * `invalid_client` for any other reason, with the context established by
     * then.
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

        $guard = $this->context->name();

        $this->context->dispatch($outcome->failure($refused, $guard, AuthenticationFlow::CLIENT_CREDENTIALS, self::METHOD, $client, $presented->reportedId()));

        return ClientCredentialsResult::failed($refused->reason, $error, null, self::realmOf($error, $guard));
    }

    /**
     * Report a refusal and answer it.
     *
     * @param  \SineMacula\Laravel\Authentication\Events\EventContext  $context
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\FailureReason  $reason
     * @param  string  $error
     * @param  ?string  $clientId
     * @param  ?int  $retryAfter
     * @return \SineMacula\Laravel\Authentication\ClientCredentials\ClientCredentialsResult
     */
    private function refuse(EventContext $context, FailureReason $reason, string $error, ?string $clientId, ?int $retryAfter = null): ClientCredentialsResult
    {
        $failure = new AuthenticationFailed($context, AuthenticationFlow::CLIENT_CREDENTIALS, $reason, $clientId, $retryAfter);

        $this->context->dispatch($failure);

        return ClientCredentialsResult::failed($reason, $error, $retryAfter, self::realmOf($error, $this->context->name()));
    }

    /**
     * The realm of the Basic challenge an error answers with: the guard's for
     * `invalid_client`, which RFC 6749 section 5.2 answers with 401 and a 401
     * always carries a challenge (RFC 7235 section 3.1), whichever way the
     * client authenticated; none for any other error.
     *
     * @param  string  $error
     * @param  string  $guard
     * @return ?string
     */
    private static function realmOf(string $error, string $guard): ?string
    {
        return $error === ClientCredentialsResult::INVALID_CLIENT ? $guard : null;
    }

    /**
     * The application policy.
     *
     * @return \SineMacula\Laravel\Authentication\Contracts\ApplicationPolicy
     */
    private function applicationPolicy(): ApplicationPolicy
    {
        /** @var \SineMacula\Laravel\Authentication\Contracts\ApplicationPolicy */
        return $this->container->make(ApplicationPolicy::class);
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
