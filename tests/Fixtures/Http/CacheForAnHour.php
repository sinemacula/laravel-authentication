<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Http;

use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * An application's caching middleware: it lets every response it passes back be
 * stored, by browsers and shared caches, for an hour.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class CacheForAnHour
{
    /**
     * Pass the request on and mark its response cacheable for an hour.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure(\Illuminate\Http\Request): \Symfony\Component\HttpFoundation\Response  $next
     * @return \Symfony\Component\HttpFoundation\Response
     */
    public function handle(Request $request, \Closure $next): Response
    {
        return $next($request)->setPublic()->setMaxAge(3600)->setSharedMaxAge(3600);
    }
}
