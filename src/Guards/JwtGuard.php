<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Guards;

use Illuminate\Auth\AuthManager;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Http\Request;
use Illuminate\Support\Timebox;
use SineMacula\Laravel\Authentication\Context\Enums\CredentialKind;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\IdentityProvider;
use SineMacula\Laravel\Authentication\Contracts\PrincipalResolver;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Http\BearerForms;
use SineMacula\Laravel\Authentication\Http\RefreshTokenTransport;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenService;

/**
 * Stateless JWT bearer-token guard.
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
     * Resolve the named or default guard as a JWT guard.
     *
     * @param  \Illuminate\Auth\AuthManager  $auth
     * @param  ?string  $guard
     * @param  string  $service
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function from(AuthManager $auth, ?string $guard, string $service): self
    {
        $resolved = $auth->guard($guard);

        if (!$resolved instanceof self) {
            throw new \InvalidArgumentException(sprintf('Auth guard [%s] is not a jwt guard, so it has no %s.', $guard ?? $auth->getDefaultDriver(), $service));
        }

        return $resolved;
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
     * as the session service's `signOut()` does.
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
     * is now.
     *
     * @return \SineMacula\Laravel\Authentication\Http\RefreshTokenTransport
     */
    public function refreshTransport(): RefreshTokenTransport
    {
        return ($this->transportFactory)();
    }

    /**
     * Resolve the identity from the request's bearer token.
     *
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Identity
     *
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    #[\Override]
    protected function resolveUserFromRequest(): ?Identity
    {
        $request = $this->context->request();
        $token   = $request->bearerToken();

        if ($token === null || $token === '' || BearerForms::defersTo(BearerForms::JWT, $request, $token)) {
            return null;
        }

        return $this->resolveBearerToken($token);
    }

    /**
     * Authenticate a bearer token and bind what it names as an authentication,
     * without `Validated` or `Login`.
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
            $admitted->session,
            $admitted->tenant,
            $outcome->method(),
            false,
            $outcome->credentialId,
            $outcome->scopes,
            $outcome->credentialId === null ? CredentialKind::ACCESS_TOKEN : CredentialKind::CLIENT_CREDENTIALS,
        );

        return $admitted->identity;
    }
}
