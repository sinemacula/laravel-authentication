<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Http\Middleware;

use Illuminate\Http\Request;
use SineMacula\Laravel\Authentication\Secrets\SecretResponse;
use Symfony\Component\HttpFoundation\Response;

/**
 * The `authentication.no-store` middleware: marks every response of its routes
 * not to be stored.
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
