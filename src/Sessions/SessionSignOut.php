<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions;

use Carbon\CarbonImmutable;
use Illuminate\Auth\Events\Logout;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Container\Container;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Contracts\GuardBinding;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\Enums\AuthenticationFlow;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\Enums\RevocationReason;
use SineMacula\Laravel\Authentication\Events\EventContext;
use SineMacula\Laravel\Authentication\Events\SessionRevoked;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Http\Enums\RefreshTokenSource;
use SineMacula\Laravel\Authentication\Http\PresentedRefreshToken;
use SineMacula\Laravel\Authentication\Http\RefreshTokenTransport;
use SineMacula\Laravel\Authentication\Runtime\GuardContext;
use SineMacula\Laravel\Authentication\Secrets\Secret;
use SineMacula\Laravel\Authentication\SessionRecords\SessionOwnership;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use Symfony\Component\HttpFoundation\Cookie;

/**
 * Signs a session of one guard out by its refresh credential, and clears a
 * cookie application's refresh cookie for a client its own pages sent.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class SessionSignOut
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Runtime\GuardContext  $context
     * @param  \SineMacula\Laravel\Authentication\Contracts\GuardBinding  $binding
     * @param  \SineMacula\Laravel\Authentication\Sessions\RevocationWriter  $writer
     * @param  \SineMacula\Laravel\Authentication\Sessions\RefreshProof  $proof
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** The context of the guard whose sessions are signed out. */
        private GuardContext $context,

        /** The guard's bound state, whose binding to a session signed out is forgotten. */
        private GuardBinding $binding,

        /** Revokes the session the refresh credential proves, and reports it once committed. */
        private RevocationWriter $writer,

        /** Proves the session a refresh token holds. */
        private RefreshProof $proof,

        /** Container the configuration the refresh token transport reads is resolved from. */
        private Container $container,
    ) {}

    /**
     * Sign out by what was presented, judged again with the client, or return
     * `null` when nothing was.
     *
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\FailureReason|\SineMacula\Laravel\Authentication\Http\PresentedRefreshToken|null  $presented
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @param  int|string|null  $expectedSession
     * @return \SineMacula\Laravel\Authentication\Sessions\SignOutResult
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidSessionModelConfigurationException
     */
    public function signOutWith(
        #[\SensitiveParameter] FailureReason|PresentedRefreshToken|null $presented,
        ClientContext $client,
        int|string|null $expectedSession = null,
    ): SignOutResult {
        $transport = $this->transport();
        $refusal   = match (true) {
            $presented instanceof FailureReason         => SessionRefresh::handedIn($presented),
            $presented instanceof PresentedRefreshToken => $transport->judge($presented, $client),
            default                                     => null,
        };
        $forget = $this->forget($transport, $client, $refusal);

        if ($refusal !== null) {

            $this->context->dispatch(new AuthenticationFailed(new EventContext($this->context->name(), $client), AuthenticationFlow::SIGN_OUT, $refusal));

            return SignOutResult::failed($refusal, $presented instanceof PresentedRefreshToken ? $presented->source : null, $forget);
        }

        return $presented instanceof PresentedRefreshToken
            ? $this->signOutProven($presented->token, $presented->source, $forget, $client, $expectedSession)
            : SignOutResult::nothing($forget);
    }

    /**
     * The expired cookie that clears a cookie application's refresh cookie, or
     * `null` for a cross-site client, a conflict or a body application.
     *
     * @param  \SineMacula\Laravel\Authentication\Http\RefreshTokenTransport  $transport
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @param  ?\SineMacula\Laravel\Authentication\Events\Enums\FailureReason  $refusal
     * @return ?\Symfony\Component\HttpFoundation\Cookie
     *
     * @throws \LogicException
     */
    private function forget(RefreshTokenTransport $transport, ClientContext $client, ?FailureReason $refusal): ?Cookie
    {
        $clears = $transport->usesCookie() && $transport->isSameSiteClient($client) && $refusal !== FailureReason::REFRESH_TOKEN_CONFLICT;

        return $clears ? $transport->forgetCookie() : null;
    }

    /**
     * Sign out the session the refresh token proves, or report the refusal and
     * answer it.
     *
     * @param  \SineMacula\Laravel\Authentication\Secrets\Secret  $refreshToken
     * @param  \SineMacula\Laravel\Authentication\Http\Enums\RefreshTokenSource  $source
     * @param  ?\Symfony\Component\HttpFoundation\Cookie  $forget
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @param  int|string|null  $expectedSession
     * @return \SineMacula\Laravel\Authentication\Sessions\SignOutResult
     *
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidSessionModelConfigurationException
     */
    private function signOutProven(
        #[\SensitiveParameter] Secret $refreshToken,
        RefreshTokenSource $source,
        ?Cookie $forget,
        ClientContext $client,
        int|string|null $expectedSession,
    ): SignOutResult {
        $now    = CarbonImmutable::now()->startOfSecond();
        $proven = $this->proof->prove($refreshToken, AuthenticationFlow::SIGN_OUT, $now, $client);

        if ($proven instanceof AuthenticationFailed) {

            $this->context->dispatch($proven);

            return SignOutResult::failed($proven->reason, $source, $forget);
        }

        $session = $proven->session;

        if ($expectedSession !== null && !IdentifierCoercion::matches($session->getSessionIdentifier(), $expectedSession)) {
            return $this->refuseMismatch($session, $source, $client);
        }

        $owner = $this->owner($session);
        $event = new SessionRevoked(
            new EventContext($session->getGuard(), $client, $owner, session: $session, method: $session->getSignInMethod(), fromSession: true),
            RevocationReason::SIGNED_OUT,
        );

        $revoked = $this->writer->revoke($session, RevocationReason::SIGNED_OUT, $now, fn () => $this->context->dispatch($event));

        $this->binding->forgetSession($session);

        if ($revoked && $owner !== null) {
            $this->context->dispatch(new Logout($this->context->name(), $owner));
        }

        return $revoked ? SignOutResult::signedOut($source, $forget) : SignOutResult::nothing($forget);
    }

    /**
     * Report a refresh token that proves a session other than the one expected,
     * and answer it with no expired cookie.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @param  \SineMacula\Laravel\Authentication\Http\Enums\RefreshTokenSource  $source
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Authentication\Sessions\SignOutResult
     */
    private function refuseMismatch(EloquentSession&Model $session, RefreshTokenSource $source, ClientContext $client): SignOutResult
    {
        $this->context->dispatch(new AuthenticationFailed(
            new EventContext($this->context->name(), $client, session: $session, method: $session->getSignInMethod(), fromSession: true),
            AuthenticationFlow::SIGN_OUT,
            FailureReason::SESSION_MISMATCH,
        ));

        return SignOutResult::failed(FailureReason::SESSION_MISMATCH, $source, null);
    }

    /**
     * The session's owner, reloaded through the guard's provider, when it
     * returns that very owner.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Identity
     */
    private function owner(EloquentSession&Model $session): ?Identity
    {
        $key      = SessionOwnership::ownerKey($session);
        $identity = $key === null ? null : $this->context->provider()->retrieveById($key);

        return $identity instanceof Identity && SessionOwnership::isOwner($session, $identity) ? $identity : null;
    }

    /**
     * The application's refresh token transport, from the configuration.
     *
     * @return \SineMacula\Laravel\Authentication\Http\RefreshTokenTransport
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     */
    private function transport(): RefreshTokenTransport
    {
        return RefreshTokenTransport::forGuard($this->context->name(), $this->container->make(ConfigRepository::class));
    }
}
