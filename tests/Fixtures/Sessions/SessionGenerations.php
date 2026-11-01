<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Sessions;

use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Str;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;

/**
 * Gives a session row a test inserts itself the generation the session writer
 * gives every session it inserts, so the row is the session its own instance
 * holds, as a real sign-in's is. The package test case runs it for every
 * session row created outside the session writer.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class SessionGenerations
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Give every session row created from now on outside the session writer a
     * new random generation, unless it sets one itself. The writer's own insert
     * is left alone, so a writer that wrote none fails as it would in use.
     *
     * @param  \Illuminate\Contracts\Events\Dispatcher  $events
     * @return void
     */
    public static function listen(Dispatcher $events): void
    {
        $events->listen('eloquent.creating: *', static function (string $event, array $payload): void {

            $session = $payload[0] ?? null;

            if (!$session instanceof EloquentSession || !$session instanceof Model || FirstFactorRecorder::isWrittenBySessionWriter()) {
                return;
            }

            if ($session->getAttribute($session->getGenerationName()) !== null) {
                return;
            }

            $session->setAttribute($session->getGenerationName(), Str::uuid7()->toString());
        });
    }
}
