<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Contracts;

use SineMacula\Laravel\Authentication\RateLimiting\AttemptReservation;
use SineMacula\Laravel\Authentication\RateLimiting\AttemptSubject;

/**
 * Limits how often each identifier, account and IP address may try a flow of a
 * guard.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface AttemptLimiter
{
    /**
     * Reserve one attempt on each limit the subject counts against, all or
     * none, before an attempt that guesses a secret runs.
     *
     * @param  \SineMacula\Laravel\Authentication\RateLimiting\AttemptSubject  $subject
     * @return \SineMacula\Laravel\Authentication\RateLimiting\AttemptReservation
     *
     * @throws \InvalidArgumentException
     */
    public function acquire(AttemptSubject $subject): AttemptReservation;

    /**
     * Give back the slots a granted reservation took, for an attempt that
     * succeeded, working from its `windows` alone.
     *
     * @param  \SineMacula\Laravel\Authentication\RateLimiting\AttemptReservation  $reservation
     * @return void
     */
    public function release(AttemptReservation $reservation): void;

    /**
     * The seconds until the subject may try again, or `null` while every limit
     * it counts against has room.
     *
     * @param  \SineMacula\Laravel\Authentication\RateLimiting\AttemptSubject  $subject
     * @return ?int
     *
     * @throws \InvalidArgumentException
     */
    public function blocked(AttemptSubject $subject): ?int;

    /**
     * Count one failure of the flow against each limit the subject counts
     * against.
     *
     * @param  \SineMacula\Laravel\Authentication\RateLimiting\AttemptSubject  $subject
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public function recordFailure(AttemptSubject $subject): void;
}
