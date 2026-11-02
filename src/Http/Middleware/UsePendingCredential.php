<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Http\Middleware;

use Illuminate\Contracts\Auth\Factory as AuthFactory;
use Illuminate\Http\Request;
use SineMacula\Laravel\Authentication\Routing\DeclaredCredential;
use Symfony\Component\HttpFoundation\Response;

/**
 * `authentication.pending:<action>[,<guard>]`: declare that the route reads its
 * caller from the pending credential, of the guard named or the default one,
 * for the pending action named by its stable value (`mfa.verify`,
 * `choose_principal`, ...), for the `me` route binding, and make a named guard
 * the default for the request, as `auth:<guard>` does. The binding then binds
 * only for a pending session that allows that action now; the action the route
 * goes on to take makes its own checks. An action that is not a pending action
 * is a misconfiguration, refused with an `InvalidArgumentException`. The
 * package orders it before `SubstituteBindings`, so the declaration is in place
 * before any parameter is bound.
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
