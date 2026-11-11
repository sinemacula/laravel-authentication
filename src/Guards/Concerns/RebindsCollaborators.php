<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Guards\Concerns;

use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Http\Request;
use SineMacula\Laravel\Authentication\Contracts\PrincipalResolver;

/**
 * Rebinds the collaborators a guard holds when the container swaps them.
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
     * resolved for the previous one.
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
     * Rebind the event dispatcher onto the guard.
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
     * Rebind the principal resolver onto the guard.
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
