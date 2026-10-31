<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Http;

use Illuminate\Http\Request;
use Illuminate\Translation\ArrayLoader;
use Illuminate\Translation\Translator;

/**
 * An application middleware that binds a translator of its own for the request
 * it serves, on the application serving it (under Octane, the request's
 * sandbox): one that words `Unauthenticated.` as the request's
 * `unauthenticated` input.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class BindRequestTranslator
{
    /**
     * Bind the request's translator, and pass the request on.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure(\Illuminate\Http\Request): mixed  $next
     * @return mixed
     */
    public function handle(Request $request, \Closure $next): mixed
    {
        $loader = new ArrayLoader;

        $loader->addMessages('en', '*', ['Unauthenticated.' => $request->string('unauthenticated')->value()], '*');

        app()->instance('translator', new Translator($loader, 'en'));

        return $next($request);
    }
}
