<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\RateLimiting;

/**
 * One limit: at most `max` attempts in each window of `decaySeconds`.
 *
 * Windows are aligned to the Unix epoch: a 300-second window runs from 12:00:00
 * to 12:05:00, whoever makes the first attempt in it. Every counter of a limit
 * therefore ends its window at a time known without reading it back, so a
 * reservation knows which window it took a slot from without a query. A counter
 * whose window was started under another `decay_seconds` keeps that window
 * until it ends, and is read back (see `RateLimitStore`).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class AttemptLimit
{
    /** @var int Longest window, in seconds (one day). */
    public const int MAX_DECAY_SECONDS = 86400;

    /**
     * Constructor.
     *
     * @param  int  $max
     * @param  int  $decaySeconds
     *
     * @throws \InvalidArgumentException
     */
    public function __construct(

        /** Attempts allowed in each window, at least 1. */
        public int $max,

        /** Length of each window, in seconds, from 1 to a day. */
        public int $decaySeconds,
    ) {
        if ($max < 1 || $decaySeconds < 1 || $decaySeconds > self::MAX_DECAY_SECONDS) {
            $message = sprintf('A limit needs at least 1 attempt in a window of 1 to %d seconds, %d in %d given.', self::MAX_DECAY_SECONDS, $max, $decaySeconds);

            throw new \InvalidArgumentException($message);
        }
    }

    /**
     * The end, as a Unix timestamp, of the window the given time falls in: the
     * first window boundary after it.
     *
     * @param  int  $now
     * @return int
     */
    public function windowEnd(int $now): int
    {
        return (intdiv($now, $this->decaySeconds) + 1) * $this->decaySeconds;
    }
}
