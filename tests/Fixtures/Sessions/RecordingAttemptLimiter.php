<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Sessions;

use SineMacula\Laravel\Authentication\Contracts\AttemptLimiter;
use SineMacula\Laravel\Authentication\RateLimiting\AttemptReservation;
use SineMacula\Laravel\Authentication\RateLimiting\AttemptSubject;

/**
 * Attempt limiter double, as an application might build one on a cache, that
 * grants every reservation and records what it is asked to take and give back.
 * It keys each slot by what it counts (the identifier, else the account, else
 * the IP address) and records those keys as the reservation's windows, or
 * records no windows at all, so tests can see that the package gives slots back
 * from the windows alone.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class RecordingAttemptLimiter implements AttemptLimiter
{
    /** @var list<\SineMacula\Laravel\Authentication\RateLimiting\AttemptSubject> Subjects reserved, in order. */
    public array $acquired = [];

    /** @var list<\SineMacula\Laravel\Authentication\RateLimiting\AttemptReservation> Reservations given back, in order. */
    public array $released = [];

    /**
     * Constructor.
     *
     * @param  bool  $recordsWindows
     */
    public function __construct(

        /** Whether a granted reservation records the keys of its slots as windows. */
        private readonly bool $recordsWindows = true,
    ) {}

    /**
     * Grant the reservation, recording its subject.
     *
     * @param  \SineMacula\Laravel\Authentication\RateLimiting\AttemptSubject  $subject
     * @return \SineMacula\Laravel\Authentication\RateLimiting\AttemptReservation
     */
    #[\Override]
    public function acquire(AttemptSubject $subject): AttemptReservation
    {
        $this->acquired[] = $subject;

        $key = $subject->identifier ?? $subject->account ?? $subject->ip ?? 'nothing';

        return new AttemptReservation($subject, null, $this->recordsWindows ? [$key => 'window'] : []);
    }

    /**
     * Record the reservation given back.
     *
     * @param  \SineMacula\Laravel\Authentication\RateLimiting\AttemptReservation  $reservation
     * @return void
     */
    #[\Override]
    public function release(AttemptReservation $reservation): void
    {
        $this->released[] = $reservation;
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
