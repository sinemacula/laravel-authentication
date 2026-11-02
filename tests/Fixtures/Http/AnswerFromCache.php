<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Http;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * An application's middleware that answers a request itself, before the route's
 * controller runs, with a response it lets be cached: a secret of another
 * package, say, served from somewhere of its own.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class AnswerFromCache
{
    /**
     * Answer without passing the request on.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure(\Illuminate\Http\Request): \Symfony\Component\HttpFoundation\Response  $next
     * @return \Symfony\Component\HttpFoundation\Response
     */
    public function handle(Request $request, \Closure $next): Response
    {
        return (new JsonResponse(['recovery_codes' => ['early-recovery-code']]))->setPublic()->setMaxAge(600);
    }
}
