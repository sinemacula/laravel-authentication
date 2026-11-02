<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Http\Middleware;

use Illuminate\Http\Request;
use SineMacula\Laravel\Authentication\Secrets\SecretResponse;
use Symfony\Component\HttpFoundation\Response;

/**
 * The `authentication.no-store` middleware: marks every response of the routes
 * it is placed on not to be stored (`Cache-Control: no-store`, `Pragma:
 * no-cache`), whatever the response carries and whoever built it, so a route
 * that hands out a secret of this package or of another one, such as a factor's
 * secret or recovery codes, never leaves a copy in a browser or a shared cache.
 * It does not read the body.
 *
 * The package puts it first in the HTTP kernel's middleware priority, so on a
 * route that lists it, it wraps every other route middleware the kernel sorts:
 * a `401` from `auth`, a refused route binding, a later middleware's early
 * response and an error the controller raised all leave through it, and none of
 * them can drop the header afterwards. Global middleware runs outside it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class NoStore
{
    /**
     * Handle the request and mark its response not to be stored.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure(\Illuminate\Http\Request): \Symfony\Component\HttpFoundation\Response  $next
     * @return \Symfony\Component\HttpFoundation\Response
     */
    public function handle(Request $request, \Closure $next): Response
    {
        return SecretResponse::withoutStoring($next($request));
    }
}
