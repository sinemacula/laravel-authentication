<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Http\Middleware;

use Illuminate\Contracts\Auth\Factory as AuthFactory;
use Illuminate\Http\Request;
use SineMacula\Laravel\Authentication\Callers\DeclaredCredential;
use Symfony\Component\HttpFoundation\Response;

/**
 * `authentication.pending:<action>[,<guard>]`: declare that the route
 * authenticates with the pending credential for the named pending action.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class UsePendingCredential
{
    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Auth\Factory  $auth
     */
    public function __construct(

        /** Auth factory a named guard is made the default on. */
        private AuthFactory $auth,
    ) {}

    /**
     * Declare the pending credential for the action on the request and pass it
     * on.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure(\Illuminate\Http\Request): \Symfony\Component\HttpFoundation\Response  $next
     * @param  string  $action
     * @param  ?string  $guard
     * @return \Symfony\Component\HttpFoundation\Response
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public function handle(Request $request, \Closure $next, string $action, ?string $guard = null): Response
    {
        DeclaredCredential::pending($action, $guard)->declareOn($request);

        if ($guard !== null) {
            $this->auth->shouldUse($guard);
        }

        return $next($request);
    }
}
