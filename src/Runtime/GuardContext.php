<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Runtime;

use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Http\Request;
use SineMacula\Laravel\Authentication\Contracts\IdentityProvider;
use SineMacula\Laravel\Authentication\Contracts\PrincipalResolver;
use SineMacula\Laravel\Authentication\Http\ClientContext;

/**
 * The collaborators one guard's flows run with: the guard's name, its identity
 * provider and principal resolver, the dispatcher its events go to, the request
 * it serves, and its credential timebox.
 *
 * Each guard builds one and keeps it for its life, and everything that runs on
 * the guard holds that same instance. It is mutable on purpose: the guard's
 * `setRequest()`, `setDispatcher()` and `setPrincipalResolver()`, which the
 * container's rebinds and `Event::fake()` reach, rebind it, so a flow built
 * before a rebind follows it. A flow reads a collaborator each time it uses
 * one, never keeping a copy; an operation captures what it reports (the client
 * it came from, its events' payload) when it starts, and a callback deferred to
 * a commit dispatches through `dispatch()`, reaching the dispatcher as it is
 * when the callback runs.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class GuardContext
{
    /**
     * Constructor.
     *
     * @param  string  $name
     * @param  \SineMacula\Laravel\Authentication\Contracts\IdentityProvider  $provider
     * @param  \SineMacula\Laravel\Authentication\Contracts\PrincipalResolver  $resolver
     * @param  \Illuminate\Contracts\Events\Dispatcher  $events
     * @param  \Illuminate\Http\Request  $request
     * @param  \SineMacula\Laravel\Authentication\Runtime\CredentialTimebox  $timebox
     */
    public function __construct(

        /** Guard name, as registered under `auth.guards.<name>`. */
        private readonly string $name,

        /** Identity provider used to look up and validate credentials. */
        private readonly IdentityProvider $provider,

        /** Resolver that maps an identity to its acting principal. */
        private PrincipalResolver $resolver,

        /** Event dispatcher for standard and custom auth events. */
        private Dispatcher $events,

        /** The HTTP request the guard serves. */
        private Request $request,

        /** Timebox enforcing uniform elapsed time on the credential path. */
        private readonly CredentialTimebox $timebox,
    ) {}

    /**
     * Return the guard's name, as registered under `auth.guards.<name>`.
     *
     * @return string
     */
    public function name(): string
    {
        return $this->name;
    }

    /**
     * Return the identity provider the guard looks identities up through.
     *
     * @return \SineMacula\Laravel\Authentication\Contracts\IdentityProvider
     */
    public function provider(): IdentityProvider
    {
        return $this->provider;
    }

    /**
     * Return the resolver the guard maps identities to principals with.
     *
     * @return \SineMacula\Laravel\Authentication\Contracts\PrincipalResolver
     */
    public function resolver(): PrincipalResolver
    {
        return $this->resolver;
    }

    /**
     * Return the dispatcher the guard's events go to.
     *
     * @return \Illuminate\Contracts\Events\Dispatcher
     */
    public function events(): Dispatcher
    {
        return $this->events;
    }

    /**
     * Return the request the guard serves.
     *
     * @return \Illuminate\Http\Request
     */
    public function request(): Request
    {
        return $this->request;
    }

    /**
     * Read the client of the request the guard serves now.
     *
     * @return \SineMacula\Laravel\Authentication\Http\ClientContext
     */
    public function client(): ClientContext
    {
        return ClientContext::fromRequest($this->request);
    }

    /**
     * Return the guard's credential timebox.
     *
     * @return \SineMacula\Laravel\Authentication\Runtime\CredentialTimebox
     */
    public function timebox(): CredentialTimebox
    {
        return $this->timebox;
    }

    /**
     * Dispatch the event to the guard's dispatcher as it is now.
     *
     * @param  object  $event
     * @return void
     */
    public function dispatch(object $event): void
    {
        $this->events->dispatch($event);
    }

    /**
     * Rebind the request the guard serves: for the owning guard's
     * `setRequest()` only.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return void
     *
     * @internal
     */
    public function rebindRequest(Request $request): void
    {
        $this->request = $request;
    }

    /**
     * Rebind the dispatcher the guard's events go to: for the owning guard's
     * `setDispatcher()` only.
     *
     * @param  \Illuminate\Contracts\Events\Dispatcher  $events
     * @return void
     *
     * @internal
     */
    public function rebindEvents(Dispatcher $events): void
    {
        $this->events = $events;
    }

    /**
     * Rebind the resolver the guard maps identities to principals with: for the
     * owning guard's `setPrincipalResolver()` only.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\PrincipalResolver  $resolver
     * @return void
     *
     * @internal
     */
    public function rebindResolver(PrincipalResolver $resolver): void
    {
        $this->resolver = $resolver;
    }
}
