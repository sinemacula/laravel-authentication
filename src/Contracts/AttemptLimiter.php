<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Contracts;

use SineMacula\Laravel\Authentication\RateLimiting\AttemptReservation;
use SineMacula\Laravel\Authentication\RateLimiting\AttemptSubject;

/**
 * Attempt limiter contract.
 *
 * Limits how often each identifier and each IP address may try a flow of a
 * guard, counted in the database so the limits hold across servers and without
 * a cache. A `null` identifier or IP address, or a limit the guard turns off,
 * is not counted.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface AttemptLimiter
{
    /**
     * Reserve one attempt on the identifier's and the IP address's limits
     * before an attempt that guesses a secret runs. The reservation is granted
     * when both had room, and both slots are then taken; otherwise it carries
     * the seconds until the full limit's window ends, and nothing is taken.
     *
     * @param  \SineMacula\Laravel\Authentication\RateLimiting\AttemptSubject  $subject
     * @return \SineMacula\Laravel\Authentication\RateLimiting\AttemptReservation
     *
     * @throws \InvalidArgumentException
     */
    public function acquire(AttemptSubject $subject): AttemptReservation;

    /**
     * Give back the slots a granted reservation took, for an attempt that
     * succeeded. A slot whose window has since ended is not given back, and a
     * reservation that was not granted gives back nothing.
     *
     * @param  \SineMacula\Laravel\Authentication\RateLimiting\AttemptReservation  $reservation
     * @return void
     */
    public function release(AttemptReservation $reservation): void;

    /**
     * For a flow that cannot guess a secret and counts only its failures:
     * `null` while the identifier and the IP address are under their limits,
     * otherwise the seconds, at least 1, until the full limit's window ends.
     *
     * @param  \SineMacula\Laravel\Authentication\RateLimiting\AttemptSubject  $subject
     * @return ?int
     *
     * @throws \InvalidArgumentException
     */
    public function blocked(AttemptSubject $subject): ?int;

    /**
     * Count one failure of the flow against the identifier and the IP address.
     *
     * @param  \SineMacula\Laravel\Authentication\RateLimiting\AttemptSubject  $subject
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public function recordFailure(AttemptSubject $subject): void;
}
