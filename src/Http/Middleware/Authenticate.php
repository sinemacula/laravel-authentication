<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Http\Middleware;

use Illuminate\Auth\AuthenticationException;
use Illuminate\Auth\Middleware\Authenticate as IlluminateAuthenticate;
use Illuminate\Contracts\Auth\Factory as AuthFactory;
use SineMacula\Laravel\Authentication\Http\BearerForms;
use SineMacula\Laravel\Authentication\Http\ConsumerMessages;
use SineMacula\Laravel\Authentication\Http\UnauthenticatedResponse;

/**
 * Laravel's `auth` middleware, made aware of the package's guards.
 *
 * Laravel resolves the guest redirect before the exception handler runs, which
 * fails on an API with no `login` route.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @inheritable
 */
class Authenticate extends IlluminateAuthenticate
{
    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Auth\Factory  $auth
     * @param  \SineMacula\Laravel\Authentication\Http\UnauthenticatedResponse  $response
     */
    public function __construct(

        // Stored by the parent middleware, so not promoted.
        AuthFactory $auth,

        /** Guest response deciding whether the route's guards are all package guards. */
        protected readonly UnauthenticatedResponse $response,
    ) {
        parent::__construct($auth);
    }

    /**
     * Record the guards the route lists on the request, then authenticate
     * against them as Laravel does.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  array<array-key, mixed>  $guards
     * @return void
     *
     * @throws \Illuminate\Auth\AuthenticationException
     */
    #[\Override]
    protected function authenticate(mixed $request, array $guards): void
    {
        $request->attributes->set(BearerForms::ROUTE_GUARDS, $guards === [] ? [null] : $guards);

        parent::authenticate($request, $guards);
    }

    /**
     * Raise the exception without a redirect when every guard is a package
     * guard, otherwise defer to Laravel.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  array<array-key, mixed>  $guards
     * @return never
     *
     * @throws \Illuminate\Auth\AuthenticationException
     */
    #[\Override]
    protected function unauthenticated(mixed $request, array $guards)
    {
        /** @var array<int, ?string> $guards */
        if ($this->response->appliesTo($guards)) {
            throw new AuthenticationException(ConsumerMessages::UNAUTHENTICATED, $guards);
        }

        parent::unauthenticated($request, $guards);
    }
}
