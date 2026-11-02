<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Http\Middleware;

use Illuminate\Contracts\Auth\Factory as AuthFactory;
use Illuminate\Http\Request;
use SineMacula\Laravel\Authentication\Routing\DeclaredCredential;
use Symfony\Component\HttpFoundation\Response;

/**
 * `authentication.refresh[:<guard>]`: declare that the route reads its caller
 * from the refresh credential, of the guard named or the default one, for the
 * `me` route binding, and make a named guard the default for the request, as
 * `auth:<guard>` does. It reads, proves and refuses nothing itself: the binding
 * does that when a parameter asks for the caller. The package orders it before
 * `SubstituteBindings`, so the declaration is in place before any parameter is
 * bound.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class UseRefreshCredential
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
     * Declare the refresh credential on the request and pass it on.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure(\Illuminate\Http\Request): \Symfony\Component\HttpFoundation\Response  $next
     * @param  ?string  $guard
     * @return \Symfony\Component\HttpFoundation\Response
     *
     * @throws \LogicException
     */
    public function handle(Request $request, \Closure $next, ?string $guard = null): Response
    {
        DeclaredCredential::refresh($guard)->declareOn($request);

        if ($guard !== null) {
            $this->auth->shouldUse($guard);
        }

        return $next($request);
    }
}
