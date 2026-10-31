<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Http;

use Illuminate\Http\Request;

/**
 * An application's locale middleware: it sets the application's locale to the
 * one the request names in its `locale` input.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class SetLocaleFromRequest
{
    /**
     * Set the locale the request names, and pass the request on.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure(\Illuminate\Http\Request): mixed  $next
     * @return mixed
     */
    public function handle(Request $request, \Closure $next): mixed
    {
        app()->setLocale($request->string('locale')->value());

        return $next($request);
    }
}
