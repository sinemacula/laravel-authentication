<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Sessions;

use SineMacula\Laravel\Authentication\Contracts\AttemptLimiter;
use SineMacula\Laravel\Authentication\RateLimiting\AttemptReservation;
use SineMacula\Laravel\Authentication\RateLimiting\AttemptSubject;

/**
 * Attempt limiter double that grants every reservation and counts nothing, for
 * guard tests whose guards no configuration describes.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class UnlimitedAttemptLimiter implements AttemptLimiter
{
    /**
     * Grant the reservation.
     *
     * @param  \SineMacula\Laravel\Authentication\RateLimiting\AttemptSubject  $subject
     * @return \SineMacula\Laravel\Authentication\RateLimiting\AttemptReservation
     */
    #[\Override]
    public function acquire(AttemptSubject $subject): AttemptReservation
    {
        return new AttemptReservation($subject, null);
    }

    /**
     * Give nothing back: nothing was taken.
     *
     * @param  \SineMacula\Laravel\Authentication\RateLimiting\AttemptReservation  $reservation
     * @return void
     */
    #[\Override]
    public function release(AttemptReservation $reservation): void
    {
        unset($reservation);
    }

    /**
     * Never blocked.
     *
     * @param  \SineMacula\Laravel\Authentication\RateLimiting\AttemptSubject  $subject
     * @return ?int
     */
    #[\Override]
    public function blocked(AttemptSubject $subject): ?int
    {
        unset($subject);

        return null;
    }

    /**
     * Count nothing.
     *
     * @param  \SineMacula\Laravel\Authentication\RateLimiting\AttemptSubject  $subject
     * @return void
     */
    #[\Override]
    public function recordFailure(AttemptSubject $subject): void
    {
        unset($subject);
    }
}
