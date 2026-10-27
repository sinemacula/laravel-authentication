<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\RateLimiting;

/**
 * The outcome of reserving an attempt: granted, with the window of each slot it
 * took so that giving them back never touches a later window, or refused, with
 * the seconds until the attempt may be made again.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class AttemptReservation
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\RateLimiting\AttemptSubject  $subject
     * @param  ?int  $retryAfter
     * @param  array<string, string>  $windows
     */
    public function __construct(

        /** Who reserved the attempt. */
        public AttemptSubject $subject,

        /** Seconds until the attempt may be made again, or `null` when granted. */
        public ?int $retryAfter,

        /** Window end, as stored, of each slot taken, keyed by the limit's key. */
        public array $windows = [],
    ) {}

    /**
     * Whether the attempt may run.
     *
     * @return bool
     */
    public function granted(): bool
    {
        return $this->retryAfter === null;
    }
}
