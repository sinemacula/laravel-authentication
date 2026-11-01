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
 * Acting binds the context through the guard's trusted `authenticateAs()` and
 * makes the guard the default, as Laravel's `actingAs()` does, but the context
 * also authenticates every request the test then sends through the HTTP kernel
 * (`$this->actingAsIdentity($user)->getJson('/me')`), which `actingAs()` cannot
 * do for these guards. It ends with `stopActing()`, with a sign-out on the
 * guard (Laravel's `Logout`, as `Auth::logout()` and a sign-out endpoint
 * dispatch), or when the test acts again on the same guard; each guard keeps
 * its own. A queued job a worker runs still starts signed out, as in
 * production. Nothing is checked: the identity, principal and session are bound
 * as given, so a test can act as a revoked session or an inactive principal.
 *
 * The assertions read the guard as application code does, so the first one on a
 * request authenticates it. No method shares a name with Laravel's
 * `actingAs()`, `be()` or `assertAuthenticated*()`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
trait InteractsWithAuthenticationContext
{
    /**
     * Act as the identity on the guard (the default guard when none is named),
     * as the principal given or the resolver's default one, on the session
     * given or none. A machine identity is limited to the scopes given, as if
     * its credential granted them (none, `[]`, when no list is given), so a
     * test of a scope-gated route needs no real API key.
     *
     * Throws an `InvalidArgumentException` when no principal is given and the
     * identity has no default one, when scopes are given for an identity that
     * is not a machine, or when the guard is not a package guard.
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
     * Act as the principal, for the identity that owns it, on the guard (the
     * default guard when none is named), on the session given or none, limited,
     * for a machine identity, to the scopes given (see `actingAsIdentity()`).
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
     * Act on the session: as the identity that owns it and the principal it
     * records, on the guard it records (or the default guard when it records
     * none).
     *
     * Throws an `InvalidArgumentException` when a guard is named that the
     * session does not record, when the guard's provider does not find the
     * session's owner, or when its resolver does not resolve the principal the
     * session records.
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
     * Stop acting on the guard (the default guard when none is named): it is
     * signed out for the rest of the request, and the next request is
     * authenticated by its own credential, if any.
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
     * Assert the identity the guard (the default guard when none is named) has
     * bound: none when `null` is expected, otherwise one of the same class with
     * the same auth identifier.
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
     * Assert the principal the guard (the default guard when none is named) has
     * bound: none when `null` is expected, otherwise one of the same class with
     * the same principal identifier.
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
     * Assert the tenant the principal the guard (the default guard when none is
     * named) has bound acts within: none when `null` is expected, otherwise one
     * of the same class with the same tenant identifier.
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
     * Assert the session the guard (the default guard when none is named) has
     * bound: none when `null` is expected, otherwise one of the same class with
     * the same session identifier.
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
     * Assert the scopes the guard (the default guard when none is named) has
     * bound, exactly and in order: `null` for a context no credential limits,
     * otherwise the list (`[]` for none).
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
