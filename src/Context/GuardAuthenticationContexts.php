<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Context;

use Illuminate\Container\Container;
use SineMacula\Laravel\Authentication\Contracts\AuthenticationContexts;
use SineMacula\Laravel\Authentication\Contracts\ContextualGuard;

/**
 * The default authentication contexts: the context the default guard holds, the
 * guard the route's `auth` middleware authenticated with, or `null` on a guard
 * that is not contextual.
 *
 * Holds nothing: the auth manager is resolved from the container serving now on
 * every call (the request's own under Octane), and the context lives on the
 * guard, so nothing outlives the request.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class GuardAuthenticationContexts implements AuthenticationContexts
{
    /**
     * The context the default guard holds.
     *
     * @return ?\SineMacula\Laravel\Authentication\Context\AuthenticationContext
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\TenantUnavailableException
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    #[\Override]
    public function current(): ?AuthenticationContext
    {
        /** @var \Illuminate\Auth\AuthManager $auth */
        $auth  = Container::getInstance()->make('auth');
        $guard = $auth->guard();

        return $guard instanceof ContextualGuard ? $guard->authenticationContext() : null;
    }
}
