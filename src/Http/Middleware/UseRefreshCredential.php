<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Http\Middleware;

use Illuminate\Contracts\Auth\Factory as AuthFactory;
use Illuminate\Http\Request;
use SineMacula\Laravel\Authentication\Callers\DeclaredCredential;
use Symfony\Component\HttpFoundation\Response;

/**
 * `authentication.refresh[:<guard>]`: declare that the route authenticates with
 * the refresh credential, of the guard named or the default one, which
 * `Auth::caller()` then reads the caller from, and make a named guard the
 * default for the request, as `auth:<guard>` does. It reads, proves and refuses
 * nothing itself: `Auth::caller()` does that when it is asked. The package
 * orders it before `SubstituteBindings`, so the declaration is in place before
 * any route parameter is bound.
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
