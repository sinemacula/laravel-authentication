<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Guards;

use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Http\Request;
use Illuminate\Support\Timebox;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\IdentityProvider;
use SineMacula\Laravel\Authentication\Contracts\PrincipalResolver;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Http\RefreshTokenTransport;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenService;

/**
 * Sessionless JWT bearer-token guard.
 *
 * Reads `Authorization: Bearer <token>` from the active request, decodes via
 * `JwtTokenService`, then rehydrates the live identity, principal, and optional
 * device from the configured provider/resolver/model state before binding them
 * (see `BearerAuthentication`).
 *
 * `logout()` signs the session out through the guard's session revocations,
 * built on its own context. The guard neither builds nor holds a session
 * service: `Auth::sessions()` builds one on the guard's context, with the guard
 * as the binding it signs in, and a refresh goes through it, as a switch of
 * principal does. The guard hands out its refresh token transport, which
 * `Auth::refreshTransport()` returns.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class JwtGuard extends AbstractGuard
{
    /**
     * Constructor.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  string  $name
     * @param  \SineMacula\Laravel\Authentication\Contracts\IdentityProvider  $provider
     * @param  \SineMacula\Laravel\Authentication\Contracts\PrincipalResolver  $resolver
     * @param  \Illuminate\Contracts\Events\Dispatcher  $events
     * @param  \Illuminate\Http\Request  $request
     * @param  \Illuminate\Support\Timebox  $timebox
     * @param  \SineMacula\Laravel\Authentication\Jwt\JwtTokenService  $tokens
     * @param  \Closure(\SineMacula\Laravel\Authentication\Runtime\GuardContext): \SineMacula\Laravel\Authentication\Sessions\SessionRevocations  $revocationsFactory
     * @param  \Closure(): \SineMacula\Laravel\Authentication\Http\RefreshTokenTransport  $transportFactory
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    public function __construct(

        // Guard name from the auth config.
        string $name,

        // Identity provider backing the guard.
        IdentityProvider $provider,

        // Principal resolver for contextual resolution.
        PrincipalResolver $resolver,

        // Event dispatcher for guard lifecycle events.
        Dispatcher $events,

        // Current HTTP request used to extract credentials.
        Request $request,

        // Timebox enforcing uniform elapsed time on the credential path.
        Timebox $timebox,

        /** JWT token service for access and refresh tokens. */
        protected JwtTokenService $tokens,

        /** Builds the session revocations the guard signs out through, given the guard's context, each time it signs out. */
        private readonly \Closure $revocationsFactory,

        /** Builds the guard's refresh token transport from the configuration as it is now. */
        private readonly \Closure $transportFactory,
    ) {
        parent::__construct($name, $provider, $resolver, $events, $request, $timebox);
    }

    /**
     * The guard's token service, which a session service built for the guard
     * issues and parses with, as the guard does.
     *
     * @return \SineMacula\Laravel\Authentication\Jwt\JwtTokenService
     *
     * @internal
     */
    public function tokens(): JwtTokenService
    {
        return $this->tokens;
    }

    /**
     * Sign the request's session out through the guard's session revocations,
     * as the session service's `signOut()` does: the device the guard is bound
     * to is revoked (`signed_out`) and `DeviceRevoked` reported once committed,
     * Laravel's `Logout` fires when an identity was bound, and the guard stays
     * signed out for the rest of the request. A session without a persisted
     * device is only forgotten.
     *
     * @return void
     *
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    #[\Override]
    public function logout(): void
    {
        ($this->revocationsFactory)($this->context)->signOut($this);
    }

    /**
     * The guard's refresh token transport, built from the configuration as it
     * is now; a malformed configuration throws an `InvalidArgumentException`
     * naming the guard and the key.
     *
     * @return \SineMacula\Laravel\Authentication\Http\RefreshTokenTransport
     */
    public function refreshTransport(): RefreshTokenTransport
    {
        return ($this->transportFactory)();
    }

    /**
     * Resolve the identity from the request's bearer token. `user()` calls this
     * at most once per request, so a rejected token is reported once. A request
     * without a token attempts nothing and dispatches nothing.
     *
     * Fail-closed: a token that claims a specific `pid` or `did` but does not
     * resolve to that exact principal/device is rejected rather than silently
     * downgraded.
     *
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Identity
     *
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    #[\Override]
    protected function resolveUserFromRequest(): ?Identity
    {
        $token = $this->context->request()->bearerToken();

        if ($token === null || $token === '') {
            return null;
        }

        return $this->resolveBearerToken($token);
    }

    /**
     * Authenticate a bearer token and bind what it names. A request's token is
     * an authentication, not a sign-in: success binds through
     * `bindVerifiedContext()` without `Validated` or `Login`, so only
     * `Authenticated`, `PrincipalAssigned` and `DeviceAuthenticated` fire, and
     * a rejected token fires only `AuthenticationFailed` with the reason (no
     * `Attempting` or `Failed`).
     *
     * @param  string  $token
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Identity
     *
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    private function resolveBearerToken(#[\SensitiveParameter] string $token): ?Identity
    {
        $outcome = (new BearerAuthentication($this->context->name(), $this->tokens, $this->context->provider(), $this->context->resolver()))
            ->authenticate($token, $this->context->client());

        if ($outcome instanceof AuthenticationFailed) {

            $this->context->dispatch($outcome);

            return null;
        }

        $admitted = $outcome->admitted;

        $this->bindVerifiedContext(
            $admitted->identity,
            $admitted->principal,
            $admitted->device,
            $admitted->tenant,
            $outcome->method(),
            false,
            $outcome->credentialId,
            $outcome->scopes,
        );

        return $admitted->identity;
    }
}
