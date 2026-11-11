<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Guards\Concerns;

use SineMacula\Laravel\Authentication\Context\AuthenticationContext;
use SineMacula\Laravel\Authentication\Context\ContextBuilder;
use SineMacula\Laravel\Authentication\Contracts\Session;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;

/**
 * Holds the authentication context of the state a guard bound, built on first
 * ask and forgotten when that state changes.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @phpstan-require-implements \SineMacula\Laravel\Authentication\Contracts\ContextualGuard
 * @phpstan-require-implements \SineMacula\Laravel\Authentication\Contracts\GuardBinding
 *
 * @property \SineMacula\Laravel\Authentication\Runtime\GuardContext $context
 */
trait HoldsAuthenticationContext
{
    /** @var ?\SineMacula\Laravel\Authentication\Context\AuthenticationContext The authentication context of the bound state, once built. */
    protected ?AuthenticationContext $authenticationContext = null;

    /** @var bool Whether the authentication context is being built, so a contributor asking for it is refused. */
    private bool $buildingAuthenticationContext = false;

    /**
     * Return the authentication context of what the guard bound, resolving the
     * request on first access.
     *
     * @return ?\SineMacula\Laravel\Authentication\Context\AuthenticationContext
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\TenantUnavailableException
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    public function authenticationContext(): ?AuthenticationContext
    {
        $identity = $this->user();

        if ($identity === null || $this->principal === null) {
            return null;
        }

        $this->refuseReentry();

        if ($this->authenticationContext !== null) {
            return $this->authenticationContext;
        }

        $this->buildingAuthenticationContext = true;

        try {
            $context = ContextBuilder::build($this->context, $identity, $this->principal, $this->tenant(), $this->session, $this->credentialKind, $this->scopes);
        } finally {
            $this->buildingAuthenticationContext = false;
        }

        return $this->authenticationContext = $context;
    }

    /**
     * Forget the authentication context the guard holds when the bound session
     * is the one given.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @return void
     */
    #[\Override]
    public function forgetAuthenticationContext(Session $session): void
    {
        if ($this->session === null || !IdentifierCoercion::matches($this->session->getSessionIdentifier(), $session->getSessionIdentifier())) {
            return;
        }

        $this->authenticationContext = null;
    }

    /**
     * Refuse an ask for the authentication context made while it is being
     * built: a contributor must not ask for the context it is adding to.
     *
     * @return void
     *
     * @throws \LogicException
     */
    private function refuseReentry(): void
    {
        if ($this->buildingAuthenticationContext) {
            throw new \LogicException(sprintf('Guard [%s] was asked for its authentication context while building it: a contributor must not ask.', $this->context->name()));
        }
    }
}
