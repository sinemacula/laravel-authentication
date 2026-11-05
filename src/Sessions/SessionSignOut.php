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
use Symfony\Component\HttpFoundation\Cookie;

/**
 * Signs a session of one guard out by its refresh credential, so a client whose
 * access token has expired, or that holds none, can still sign out, and clears
 * a cookie application's refresh cookie for a request its own pages sent.
 *
 * A request still bound to a stored session through its access token signs that
 * session out as `signOut()` does, and its refresh credential is not read.
 * Otherwise any binding is forgotten first (an access-only token's, with
 * Laravel's `Logout`), and the refresh credential is read through the
 * application's transport and proven by `RefreshProof`: the session it proves
 * is revoked (`signed_out`, reported by `SessionRevoked` once committed),
 * `Logout` fires for its owner when the guard's provider still returns it, and
 * a binding to it is forgotten. A refusal is reported by `AuthenticationFailed`
 * with the flow `sign_out`, and by no `Failed`: a sign-out is not an attempt to
 * authenticate. No attempt limit applies: nothing is issued, a refresh token
 * cannot be guessed, and revoking is the safe direction.
 *
 * A cookie application's result carries the expired cookie only for a request a
 * cross-site page cannot have sent, since a browser keeps a cookie the response
 * to a cross-site navigation sets: a cross-site form must not sign the browser
 * out.
 *
 * A sign-out from plain values (`presented()`) signs out by the refresh
 * credential alone, as one by a token the caller read does: the token, its
 * source and the client are the caller's, judged again by the transport, the
 * guard's binding is not consulted, and only a binding to the session it
 * revokes is forgotten. It reads the guard's request for nothing.
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
     * @param  \SineMacula\Laravel\Authentication\Sessions\SessionRevocations  $revocations
     * @param  \SineMacula\Laravel\Authentication\Sessions\RevocationWriter  $writer
     * @param  \SineMacula\Laravel\Authentication\Sessions\RefreshProof  $proof
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** The context of the guard whose sessions are signed out. */
        private GuardContext $context,

        /** The guard's bound state, forgotten by every sign-out. */
        private GuardBinding $binding,

        /** Signs the bound session out, as `signOut()` does. */
        private SessionRevocations $revocations,

        /** Revokes the session the refresh credential proves, and reports it once committed. */
        private RevocationWriter $writer,

        /** Proves the session a refresh token holds. */
        private RefreshProof $proof,

        /** Container the configuration the refresh token transport reads is resolved from. */
        private Container $container,
    ) {}

    /**
     * Sign the request out: the session its access token is bound to, or,
     * without one, the session its refresh credential proves.
     *
     * @return \SineMacula\Laravel\Authentication\Sessions\SignOutResult
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidSessionModelConfigurationException
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    public function fromRequest(): SignOutResult
    {
        $transport = $this->transport();
        $session   = $this->binding->session();

        if ($session instanceof EloquentSession && $session instanceof Model) {

            $forget = $transport->usesCookie() ? $transport->forgetCookie() : null;

            return $this->revocations->signOut($this->binding) ? SignOutResult::signedOut(null, $forget) : SignOutResult::nothing($forget);
        }

        $loggedOut = $this->binding->user() !== null;

        $this->revocations->signOut($this->binding);

        $presented = $transport->read($this->context->request());

        return $this->signOutPresented($presented, $this->forget($transport, null, $presented), $loggedOut, null);
    }

    /**
     * Sign out by what the caller's code extracted from a request, judged again
     * with the client, for a cookie or a body application, reading nothing from
     * the guard's request: a reason the transport never answers is refused
     * (`InvalidArgumentException`) before anything is dispatched; `null` signs
     * nothing out; the transport's reason, or its refusal of the token on
     * judging it with the client, is reported; otherwise the session the token
     * proves is signed out, as `fromRequest()` signs it out, with the client in
     * place of the request's. Only a binding to that session is forgotten.
     *
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\FailureReason|\SineMacula\Laravel\Authentication\Http\PresentedRefreshToken|null  $presented
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Authentication\Sessions\SignOutResult
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidSessionModelConfigurationException
     */
    public function presented(#[\SensitiveParameter] FailureReason|PresentedRefreshToken|null $presented, ClientContext $client): SignOutResult
    {
        $transport = $this->transport();

        SessionRefresh::assertHandedIn($presented);

        if ($presented instanceof PresentedRefreshToken) {

            $refusal = $transport->judge($presented, $client);

            if ($refusal !== null) {

                $this->context->dispatch(new AuthenticationFailed(new EventContext($this->context->name(), $client), AuthenticationFlow::SIGN_OUT, $refusal));

                return SignOutResult::failed($refusal, $presented->source, $this->forget($transport, $client, $refusal));
            }
        }

        return $this->signOutPresented($presented, $this->forget($transport, $client, $presented), false, $client);
    }

    /**
     * Sign out the session a body application's refresh token, read by the
     * caller, proves. A cookie application's token is read only from its
     * cookie, with the cookie's cross-site checks, so on a cookie application
     * this is a misconfiguration (`LogicException`): `presented()` signs out by
     * one from plain values.
     *
     * @param  \SineMacula\Laravel\Authentication\Secrets\Secret|string  $refreshToken
     * @return \SineMacula\Laravel\Authentication\Sessions\SignOutResult
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidSessionModelConfigurationException
     */
    public function with(#[\SensitiveParameter] Secret|string $refreshToken): SignOutResult
    {
        SessionRefresh::refuseHandedIn($this->transport());

        return $this->signOutProven($refreshToken, null, null, false, null);
    }

    /**
     * The expired cookie a cookie application's sign-out by refresh credential
     * clears the browser's with: only for a client that passes the cookie's
     * same-site checks (the one given, or the guard's request) and whose token
     * the transport did not refuse as a conflict, so neither a cross-site page
     * nor a request whose session stays live clears it; `null` otherwise, and
     * for a body application.
     *
     * @param  \SineMacula\Laravel\Authentication\Http\RefreshTokenTransport  $transport
     * @param  ?\SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\FailureReason|\SineMacula\Laravel\Authentication\Http\PresentedRefreshToken|null  $presented
     * @return ?\Symfony\Component\HttpFoundation\Cookie
     *
     * @throws \LogicException
     */
    private function forget(RefreshTokenTransport $transport, ?ClientContext $client, #[\SensitiveParameter] FailureReason|PresentedRefreshToken|null $presented): ?Cookie
    {
        $clears = $transport->usesCookie()
            && $transport->isSameSiteClient($client ?? ClientContext::sameSiteFactsOf($this->context->request()))
            && $presented !== FailureReason::REFRESH_TOKEN_CONFLICT;

        return $clears ? $transport->forgetCookie() : null;
    }

    /**
     * Sign out with what the transport read: nothing for no refresh token, the
     * transport's refusal, reported, or the session the token proves. The
     * client is the one the caller gave, or, when it gave none, the guard's
     * request's.
     *
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\FailureReason|\SineMacula\Laravel\Authentication\Http\PresentedRefreshToken|null  $presented
     * @param  ?\Symfony\Component\HttpFoundation\Cookie  $forget
     * @param  bool  $loggedOut
     * @param  ?\SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Authentication\Sessions\SignOutResult
     *
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidSessionModelConfigurationException
     */
    private function signOutPresented(
        #[\SensitiveParameter] FailureReason|PresentedRefreshToken|null $presented,
        ?Cookie $forget,
        bool $loggedOut,
        ?ClientContext $client,
    ): SignOutResult {
        if ($presented instanceof PresentedRefreshToken) {
            return $this->signOutProven($presented->token, $presented->source, $forget, $loggedOut, $client);
        }

        if ($presented !== null) {

            $client ??= $this->context->client();

            $this->context->dispatch(new AuthenticationFailed(new EventContext($this->context->name(), $client), AuthenticationFlow::SIGN_OUT, $presented));
        }

        return $presented === null ? SignOutResult::nothing($forget) : SignOutResult::failed($presented, null, $forget);
    }

    /**
     * Sign out the session the refresh token proves: revoke it, fire `Logout`
     * for its owner unless one already fired, and forget a binding to it; or
     * report the refusal and answer it.
     *
     * @param  \SineMacula\Laravel\Authentication\Secrets\Secret|string  $refreshToken
     * @param  ?\SineMacula\Laravel\Authentication\Http\Enums\RefreshTokenSource  $source
     * @param  ?\Symfony\Component\HttpFoundation\Cookie  $forget
     * @param  bool  $loggedOut
     * @param  ?\SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Authentication\Sessions\SignOutResult
     *
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidSessionModelConfigurationException
     */
    private function signOutProven(
        #[\SensitiveParameter] Secret|string $refreshToken,
        ?RefreshTokenSource $source,
        ?Cookie $forget,
        bool $loggedOut,
        ?ClientContext $client,
    ): SignOutResult {
        $now    = CarbonImmutable::now()->startOfSecond();
        $proven = $this->proof->prove($refreshToken, AuthenticationFlow::SIGN_OUT, $now, $client);

        if ($proven instanceof AuthenticationFailed) {

            $this->context->dispatch($proven);

            return SignOutResult::failed($proven->reason, $source, $forget);
        }

        $session = $proven->session;
        $owner   = $this->owner($session);
        $event   = new SessionRevoked(
            new EventContext($session->getGuard(), $client ?? $this->context->client(), $owner, session: $session, method: $session->getSignInMethod(), fromSession: true),
            RevocationReason::SIGNED_OUT,
        );

        $revoked = $this->writer->revoke($session, RevocationReason::SIGNED_OUT, $now, fn () => $this->context->dispatch($event));

        $this->binding->forgetSession($session);

        if ($revoked && $owner !== null && !$loggedOut) {
            $this->context->dispatch(new Logout($this->context->name(), $owner));
        }

        return $revoked ? SignOutResult::signedOut($source, $forget) : SignOutResult::nothing($forget);
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
