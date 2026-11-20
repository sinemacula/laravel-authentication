<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Http;

use Illuminate\Http\Request;
use SineMacula\Laravel\Authentication\Facades\Auth;

/**
 * A global middleware that reads the default guard's identity before the
 * request is routed, and keeps its identifier in the `identity_before_routing`
 * request attribute.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ReadIdentityBeforeRouting
{
    /**
     * Keep the identity the request is authenticated as, and pass it on.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure(\Illuminate\Http\Request): mixed  $next
     * @return mixed
     */
    public function handle(Request $request, \Closure $next): mixed
    {
        $request->attributes->set('identity_before_routing', Auth::identity()?->getAuthIdentifier());

        return $next($request);
    }
}
