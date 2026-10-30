<?php

declare(strict_types = 1);

namespace Tests\Integration\Fixtures;

use Illuminate\Contracts\Queue\ShouldQueue;
use SineMacula\Laravel\Authentication\Events\SignedIn;

/**
 * A queued listener on `SignedIn` that records each event as the queue hands it
 * back, so a test can read what survived the round trip.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class RecordSignedInLater implements ShouldQueue
{
    /** @var list<\SineMacula\Laravel\Authentication\Events\SignedIn> The events received, in order. */
    public static array $received = [];

    /**
     * Record the event.
     *
     * @param  \SineMacula\Laravel\Authentication\Events\SignedIn  $event
     * @return void
     */
    public function handle(SignedIn $event): void
    {
        self::$received[] = $event;
    }
}
