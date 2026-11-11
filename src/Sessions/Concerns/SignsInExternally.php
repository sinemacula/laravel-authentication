<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions\Concerns;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Authentication\Admission\Refused;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\External\ExternalResult;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\SessionRecords\SessionLookup;
use SineMacula\Laravel\Authentication\Sessions\AccessTokenResult;
use SineMacula\Laravel\Authentication\Sessions\ExternalReauthentication;
use SineMacula\Laravel\Authentication\Sessions\ExternalSignIn;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;
use SineMacula\Laravel\Authentication\Sessions\SignInMethodManager;
use SineMacula\Laravel\Authentication\Sessions\SignInResult;

/**
 * The session service's external sign-in, reauthentication and standing.
 *
 * Kept in a trait only to hold the service under the per-class method limit.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait SignsInExternally
{
    /** @var \SineMacula\Laravel\Authentication\Sessions\ExternalSignIn Maps external results to their linked identities, on the guard's context. */
    private readonly ExternalSignIn $externalSignIns;

    /** @var \SineMacula\Laravel\Authentication\Sessions\ExternalReauthentication Reauthenticates sessions through the links that established them, on the guard's context. */
    private readonly ExternalReauthentication $externalReauthentications;

    /**
     * Sign in the identity linked to a result an external identity provider
     * verified, under the method `external_provider`.
     *
     * @param  \SineMacula\Laravel\Authentication\External\ExternalResult  $result
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignInContext  $context
     * @return \SineMacula\Laravel\Authentication\Sessions\SignInResult
     *
     * @throws \Throwable
     */
    public function signInExternally(ExternalResult $result, SignInContext $context): SignInResult
    {
        $began     = CarbonImmutable::now()->startOfSecond();
        $method    = SignInMethodManager::EXTERNAL_METHOD;
        $transport = $this->transport();
        $context   = $context->withNotAfter($result->sessionNotAfter);
        $recheck   = $this->recheck($context->client, $began);
        $outcome   = SessionLookup::model()->getConnection()->transaction(function () use ($result, $context, $method, $recheck): mixed {

            $resolved = $this->externalSignIns->resolve($result, $context);

            return $resolved instanceof Refused ? $resolved : $this->startFor($resolved[0], $context->principal, $method, $context, $resolved[1], $recheck);
        });

        $outcome = $recheck->refusal() ?? $outcome;

        return $outcome instanceof Refused ? $this->fail($outcome, $method, $context, null, [], null, $result) : $this->bound($outcome, $transport, $recheck);
    }

    /**
     * Reauthenticate a session, by its identifier, with a result an external
     * identity provider verified, and issue it a new access token only.
     *
     * @param  mixed  $sessionId
     * @param  \SineMacula\Laravel\Authentication\External\ExternalResult  $result
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Authentication\Sessions\AccessTokenResult
     *
     * @throws \Throwable
     */
    public function reauthenticateExternally(mixed $sessionId, ExternalResult $result, ClientContext $client): AccessTokenResult
    {
        return $this->externalReauthentications->reauthenticate($sessionId, $result, $client);
    }

    /**
     * Why a session cannot be reauthenticated externally by the identity
     * through the connection and link; `null` when it can.
     *
     * @param  mixed  $sessionId
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  string  $connectionId
     * @param  ?string  $linkId
     * @return ?\SineMacula\Laravel\Authentication\Events\Enums\FailureReason
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidSessionModelConfigurationException
     */
    public function externalStanding(mixed $sessionId, Identity $identity, string $connectionId, ?string $linkId = null): ?FailureReason
    {
        return $this->externalReauthentications->standing($sessionId, $identity, $connectionId, $linkId);
    }
}
