<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\SessionRecords;

use Carbon\CarbonImmutable;
use Carbon\CarbonInterface;
use SineMacula\Laravel\Authentication\Contracts\Session;

/**
 * The deadline rule every session follows: it ends at the earlier of its idle
 * and absolute deadlines, or at once without an idle one.
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
     * Whether a session has ended at the given time.
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
     * A session's idle and absolute deadlines while it is live at the given
     * time, or `null` once it has ended.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @param  \Carbon\CarbonInterface  $now
     * @return array{0: \Carbon\CarbonInterface, 1: ?\Carbon\CarbonInterface}|null
     *
     * @throws \LogicException
     */
    public static function liveDeadlines(Session $session, CarbonInterface $now): ?array
    {
        $idle     = $session->getIdleExpiresAt();
        $absolute = $session->getAbsoluteExpiresAt();

        if ($idle === null || $now->getTimestamp() >= min($idle->getTimestamp(), ($absolute ?? $idle)->getTimestamp())) {
            return null;
        }

        return [$idle, $absolute];
    }

    /**
     * When a session that is live at the given time ends, or `null` once it has
     * ended.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @param  \Carbon\CarbonInterface  $now
     * @return ?\Carbon\CarbonImmutable
     *
     * @throws \LogicException
     */
    public static function liveEnd(Session $session, CarbonInterface $now): ?CarbonImmutable
    {
        $deadlines = self::liveDeadlines($session, $now);

        if ($deadlines === null) {
            return null;
        }

        [$idle, $absolute] = $deadlines;

        return CarbonImmutable::createFromTimestamp(min($idle->getTimestamp(), ($absolute ?? $idle)->getTimestamp()));
    }
}
