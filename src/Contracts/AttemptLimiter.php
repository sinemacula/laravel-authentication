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
 * a cache. A subject that names an account is also counted against that
 * account, under the guard's identifier limit, however the attempt found it and
 * through whichever guard: an account's count is its own, one counter that
 * every guard counts in and holds to its own identifier limit, not the guard's.
 * A limiter that counts accounts per guard, or not at all, lets each guard, and
 * each spelling of an identifier, guess an account's secret anew. A `null`
 * identifier, IP address or account, or a limit the guard turns off, is not
 * counted.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface AttemptLimiter
{
    /**
     * Reserve one attempt on each limit the subject counts against (its
     * identifier's, its account's and its IP address's, whichever it names)
     * before an attempt that guesses a secret runs, all or none: the
     * reservation is granted when every one had room, and a slot of each is
     * then taken; otherwise it carries the seconds until the full limit's
     * window ends, and nothing is taken.
     *
     * A granted reservation records in its `windows` everything `release()`
     * needs to give its slots back (a key and a value per slot, both strings):
     * a sign-in that waits for a further factor stores the windows of each
     * reservation it holds and, when it completes, gives each back through a
     * reservation rebuilt from its own windows, whose subject keeps only the
     * guard, the flow, the identifier type and the IP address. Two reservations
     * may record the same key (one account checked twice), and each is given
     * back.
     *
     * @param  \SineMacula\Laravel\Authentication\RateLimiting\AttemptSubject  $subject
     * @return \SineMacula\Laravel\Authentication\RateLimiting\AttemptReservation
     *
     * @throws \InvalidArgumentException
     */
    public function acquire(AttemptSubject $subject): AttemptReservation;

    /**
     * Give back the slots a granted reservation took, for an attempt that
     * succeeded, working from its `windows` alone: the reservation may have
     * been rebuilt from stored windows, with no identifier or account on its
     * subject. A slot whose window has since ended is not given back, and a
     * reservation that was not granted gives back nothing.
     *
     * @param  \SineMacula\Laravel\Authentication\RateLimiting\AttemptReservation  $reservation
     * @return void
     */
    public function release(AttemptReservation $reservation): void;

    /**
     * For a flow that cannot guess a secret and counts only its failures:
     * `null` while every limit the subject counts against is under its maximum,
     * otherwise the seconds, at least 1, until the full limit's window ends.
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
