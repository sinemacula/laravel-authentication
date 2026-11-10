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
 * Laravel's middleware resolves the guest redirect (by default
 * `route('login')`) for every request that does not expect JSON, before the
 * exception handler runs, so a stateless API without a login route answered
 * such a request with a server error. When every guard the route names is a
 * package guard, this subclass raises the `AuthenticationException` without a
 * redirect, and `UnauthenticatedResponse` renders it as `401`. Routes guarded
 * by any other guard keep Laravel's behaviour unchanged.
 *
 * It also records the guards the route lists on the request, so that on a route
 * listing both a `jwt` and an `api_key` guard a bearer credential is read and
 * reported only by the guard kind its form belongs to (see `BearerForms`).
 *
 * The package binds it in place of `Illuminate\Auth\Middleware\Authenticate`,
 * so the default `auth` alias resolves to it. An application that aliases its
 * own `auth` middleware should extend this class.
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
     * Record the guards the route lists on the request, `null` for the default
     * guard when it lists none, then authenticate against them as Laravel does.
     * A package guard reads the record to leave a bearer credential of the
     * other guard kind's form to the guard it belongs to (see `BearerForms`).
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
     * Handle an unauthenticated user: raise the exception without a redirect
     * when every guard is a package guard, otherwise defer to Laravel.
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
