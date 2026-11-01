<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\SessionRecords;

use Carbon\CarbonInterface;
use SineMacula\Laravel\Authentication\Contracts\Session;

/**
 * The deadline rule every session follows: the session has ended from the
 * second its idle or absolute deadline names, and when it lacks either. The
 * guard's `TokenLifetimes` set the deadlines; this only reads them.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class SessionDeadlines
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Whether a session has ended at the given time: either deadline is missing
     * (the session has no deadlines) or has been reached.
     *
     * The one deadline rule, shared by bearer requests, sign-in pins, refresh,
     * and token issuance.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @param  \Carbon\CarbonInterface  $now
     * @return bool
     *
     * @throws \LogicException
     */
    public static function hasEnded(Session $session, CarbonInterface $now): bool
    {
        return self::liveDeadlines($session, $now) === null;
    }

    /**
     * Return a session's idle and absolute deadlines while its session is live
     * at the given time, or `null` once it has ended (see `hasEnded()`). Each
     * deadline is read once.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @param  \Carbon\CarbonInterface  $now
     * @return array{0: \Carbon\CarbonInterface, 1: \Carbon\CarbonInterface}|null
     *
     * @throws \LogicException
     */
    public static function liveDeadlines(Session $session, CarbonInterface $now): ?array
    {
        $idle     = $session->getIdleExpiresAt();
        $absolute = $session->getAbsoluteExpiresAt();

        if ($idle === null || $absolute === null || $now->getTimestamp() >= min($idle->getTimestamp(), $absolute->getTimestamp())) {
            return null;
        }

        return [$idle, $absolute];
    }
}
