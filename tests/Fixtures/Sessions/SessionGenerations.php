<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Sessions;

use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Str;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;

/**
 * Gives a session row a test inserts itself the generation the session writer
 * gives every session.
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
     * Give every session row created outside the session writer a random
     * generation, unless it sets one.
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
