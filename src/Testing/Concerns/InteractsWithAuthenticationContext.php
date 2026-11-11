<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Testing\Concerns;

use Illuminate\Container\Container;
use Illuminate\Database\Eloquent\Model;
use PHPUnit\Framework\Assert;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\Session;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Guards\AbstractGuard;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use SineMacula\Laravel\Authentication\Testing\ActingContext;

/**
 * Act as an identity, a principal or a session on a package guard in a Laravel
 * test, and assert what a guard has bound.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
trait InteractsWithAuthenticationContext
{
    /**
     * Act as the identity on the guard, as the given or default principal.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @param  ?list<string>  $scopes
     * @param  ?string  $guard
     * @return static
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    public function actingAsIdentity(Identity $identity, ?Principal $principal = null, ?Session $session = null, ?array $scopes = null, ?string $guard = null): static
    {
        $resolved = ActingContext::guard($guard);

        return $this->actOnGuard($resolved, $identity, $principal ?? ActingContext::defaultPrincipal($resolved, $identity), $session, $scopes);
    }

    /**
     * Act as the principal, for the identity that owns it, on the guard.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @param  ?list<string>  $scopes
     * @param  ?string  $guard
     * @return static
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public function actingAsPrincipal(Principal $principal, ?Session $session = null, ?array $scopes = null, ?string $guard = null): static
    {
        return $this->actOnGuard(ActingContext::guard($guard), $principal->getIdentity(), $principal, $session, $scopes);
    }

    /**
     * Act on the session as the identity and principal it records, on its
     * guard.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @param  ?string  $guard
     * @return static
     *
     * @throws \InvalidArgumentException
     */
    public function actingOnSession(EloquentSession&Model $session, ?string $guard = null): static
    {
        $name = $session->getGuard() ?? $guard;

        if ($guard !== null && $name !== $guard) {
            throw new \InvalidArgumentException(sprintf('Session [%s] belongs to guard [%s], not [%s].', IdentifierCoercion::stringify($session->getKey()), $name, $guard));
        }

        $resolved = ActingContext::guard($name);

        [$identity, $principal] = ActingContext::recordedOn($resolved, $session);

        return $this->actOnGuard($resolved, $identity, $principal, $session);
    }

    /**
     * Act in the tenant with the context the test already acts as on the guard.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Tenant  $tenant
     * @param  ?string  $guard
     * @return static
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public function actingInTenant(Tenant $tenant, ?string $guard = null): static
    {
        ActingContext::current()->actIn(ActingContext::guard($guard), $tenant);

        return $this;
    }

    /**
     * Stop acting on the guard and sign it out for the rest of the request.
     *
     * @param  ?string  $guard
     * @return static
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     */
    public function stopActing(?string $guard = null): static
    {
        $resolved = ActingContext::guard($guard);

        ActingContext::current()->forget($resolved->getName());

        $resolved->forgetUser();

        return $this;
    }

    /**
     * Assert the identity the guard has bound, or none for `null`.
     *
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Identity  $expected
     * @param  ?string  $guard
     * @return static
     *
     * @throws \InvalidArgumentException
     * @throws \PHPUnit\Framework\ExpectationFailedException
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    public function assertBoundIdentity(?Identity $expected, ?string $guard = null): static
    {
        $resolved = ActingContext::guard($guard);
        $actual   = $resolved->identity();

        ActingContext::assertBound('identity', $resolved, $expected, $expected?->getAuthIdentifier(), $actual, $actual?->getAuthIdentifier());

        return $this;
    }

    /**
     * Assert the principal the guard has bound, or none for `null`.
     *
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Principal  $expected
     * @param  ?string  $guard
     * @return static
     *
     * @throws \InvalidArgumentException
     * @throws \PHPUnit\Framework\ExpectationFailedException
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    public function assertBoundPrincipal(?Principal $expected, ?string $guard = null): static
    {
        $resolved = ActingContext::guard($guard);
        $actual   = $resolved->principal();

        ActingContext::assertBound('principal', $resolved, $expected, $expected?->getPrincipalIdentifier(), $actual, $actual?->getPrincipalIdentifier());

        return $this;
    }

    /**
     * Assert the active tenant the guard has bound, or none for `null`.
     *
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Tenant  $expected
     * @param  ?string  $guard
     * @return static
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \PHPUnit\Framework\ExpectationFailedException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\TenantUnavailableException
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    public function assertBoundTenant(?Tenant $expected, ?string $guard = null): static
    {
        $resolved = ActingContext::guard($guard);
        $actual   = $resolved->tenant();

        ActingContext::assertBound('tenant', $resolved, $expected, $expected?->getTenantIdentifier(), $actual, $actual?->getTenantIdentifier());

        return $this;
    }

    /**
     * Assert the session the guard has bound, or none for `null`.
     *
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Session  $expected
     * @param  ?string  $guard
     * @return static
     *
     * @throws \InvalidArgumentException
     * @throws \PHPUnit\Framework\ExpectationFailedException
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    public function assertBoundSession(?Session $expected, ?string $guard = null): static
    {
        $resolved = ActingContext::guard($guard);
        $actual   = $resolved->session();

        ActingContext::assertBound('session', $resolved, $expected, $expected?->getSessionIdentifier(), $actual, $actual?->getSessionIdentifier());

        return $this;
    }

    /**
     * Assert the scopes the guard has bound, exactly and in order.
     *
     * @param  ?list<string>  $expected
     * @param  ?string  $guard
     * @return static
     *
     * @throws \InvalidArgumentException
     * @throws \PHPUnit\Framework\ExpectationFailedException
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    public function assertBoundScopes(?array $expected, ?string $guard = null): static
    {
        $resolved = ActingContext::guard($guard);

        Assert::assertSame($expected, $resolved->scopes(), sprintf('Unexpected scopes bound to guard [%s].', $resolved->getName()));

        return $this;
    }

    /**
     * Act as the context on the guard and make it the default guard.
     *
     * @param  \SineMacula\Laravel\Authentication\Guards\AbstractGuard  $guard
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @param  ?list<string>  $scopes
     * @return static
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    private function actOnGuard(AbstractGuard $guard, Identity $identity, Principal $principal, ?Session $session, ?array $scopes = null): static
    {
        if ($identity instanceof Model) {
            $identity->wasRecentlyCreated = false;
        }

        ActingContext::current()->act($guard, $identity, $principal, $session, $scopes);

        /** @var \Illuminate\Auth\AuthManager $auth */
        $auth = Container::getInstance()->make('auth');

        $auth->shouldUse($guard->getName());

        return $this;
    }
}
