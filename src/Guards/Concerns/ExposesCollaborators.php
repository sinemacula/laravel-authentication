<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Guards\Concerns;

use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Http\Request;
use SineMacula\Laravel\Authentication\Contracts\IdentityProvider;
use SineMacula\Laravel\Authentication\Contracts\PrincipalResolver;

/**
 * Exposes the collaborators a guard holds to the code that signs in through it,
 * such as the session service: each is read when it is needed, so a later
 * `setRequest()`, `setDispatcher()` or `setPrincipalResolver()` reaches that
 * code as it reaches the guard.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @phpstan-require-extends \SineMacula\Laravel\Authentication\Guards\AbstractGuard
 */
trait ExposesCollaborators
{
    /**
     * Return the identity provider the guard looks identities up through.
     *
     * @return \SineMacula\Laravel\Authentication\Contracts\IdentityProvider
     */
    public function getProvider(): IdentityProvider
    {
        return $this->provider;
    }

    /**
     * Return the resolver the guard maps identities to principals with.
     *
     * @return \SineMacula\Laravel\Authentication\Contracts\PrincipalResolver
     */
    public function getPrincipalResolver(): PrincipalResolver
    {
        return $this->resolver;
    }

    /**
     * Return the dispatcher the guard fires its events on.
     *
     * @return \Illuminate\Contracts\Events\Dispatcher
     */
    public function getDispatcher(): Dispatcher
    {
        return $this->events;
    }

    /**
     * Return the request the guard serves.
     *
     * @return \Illuminate\Http\Request
     */
    public function getRequest(): Request
    {
        return $this->request;
    }

    /**
     * Run the callback inside the guard's credential timebox, so a sign-in that
     * fails takes as long as any other, whether or not its identifier exists.
     * The callback calls `returnEarly()` on the timebox it is given for an
     * outcome that may return at once.
     *
     * @template TResult
     *
     * @param  \Closure(\Illuminate\Support\Timebox): TResult  $callback
     * @return TResult
     *
     * @throws \Throwable
     */
    public function callInCredentialTimebox(\Closure $callback): mixed
    {
        return $this->timebox->call($callback, $this->timeboxMicroseconds());
    }
}
