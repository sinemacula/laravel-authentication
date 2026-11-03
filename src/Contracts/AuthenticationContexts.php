<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Contracts;

use SineMacula\Laravel\Authentication\Context\AuthenticationContext;

/**
 * Authentication contexts contract.
 *
 * The seam an authorisation package's adapter type-hints to judge a policy
 * condition on what the request is authenticated as. The default,
 * `Context\GuardAuthenticationContexts`, asks the default guard (the one the
 * route's `auth` middleware authenticated with) for the context it holds; a
 * test binds a fake, or builds an `AuthenticationContext` itself.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface AuthenticationContexts
{
    /**
     * The authentication context of the request being served, or `null` for a
     * guest and on a guard that is not contextual. Built at most once per
     * unchanged authentication state, so asking again reads nothing again.
     *
     * @return ?\SineMacula\Laravel\Authentication\Context\AuthenticationContext
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\TenantUnavailableException
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    public function current(): ?AuthenticationContext;
}
