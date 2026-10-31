<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Guards\Concerns;

use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Http\Request;
use SineMacula\Laravel\Authentication\Contracts\PrincipalResolver;

/**
 * Rebinds the collaborators a guard holds when the container swaps them: the
 * request being served, the event dispatcher and the principal resolver. Each
 * is rebound on the guard's context, the one copy every flow of the guard
 * reads. The service provider wires these to the container's rebinding
 * callbacks, so a guard resolved once follows every later request and every
 * swap.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @phpstan-require-extends \SineMacula\Laravel\Authentication\Guards\AbstractGuard
 */
trait RebindsCollaborators
{
    /**
     * Rebind the current HTTP request onto the guard and forget everything
     * resolved for the previous one. Called by the service provider on each
     * container-resolve cycle.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return static
     */
    public function setRequest(Request $request): static
    {
        $this->context->rebindRequest($request);

        $this->lastRetrievedUser = null;
        $this->requestResolved   = false;
        $this->clearContextualState();

        return $this;
    }

    /**
     * Rebind the event dispatcher onto the guard, so test suites that swap it
     * after the guard is resolved (e.g. `Event::fake()`) get a fresh reference.
     *
     * @param  \Illuminate\Contracts\Events\Dispatcher  $events
     * @return static
     */
    public function setDispatcher(Dispatcher $events): static
    {
        $this->context->rebindEvents($events);

        return $this;
    }

    /**
     * Rebind the principal resolver, so consumers that swap it after guard
     * construction (test fakes, runtime tenancy switches) propagate the new
     * resolver into the guard.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\PrincipalResolver  $resolver
     * @return static
     */
    public function setPrincipalResolver(PrincipalResolver $resolver): static
    {
        $this->context->rebindResolver($resolver);

        return $this;
    }
}
