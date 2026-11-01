<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Jwt;

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Contracts\Session;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Jwt\Enums\RotationMatch;
use SineMacula\Laravel\Authentication\SessionRecords\SessionDeadlines;

/**
 * Judges a presented refresh rotation id against the session it names, the way
 * both a refresh and a switch of principal do: whether the session is still
 * live, and whether the id is its current one, the one the current one replaced
 * inside the grace window, or a replay.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class RefreshJudgment
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Judge the presented rotation id against the session at `$now`.
     *
     * In order: a revoked session fails as `session_revoked`; a session past
     * either deadline, or without an idle one, as `session_expired` (an ended
     * session is not revoked: it simply cannot be refreshed); a session holding
     * no refresh credential as `refresh_key_missing`. Only then is the rotation
     * id compared, in constant time: the current one, with the absolute
     * deadline the rotation keeps (`null` for none); the previous one inside
     * the grace window; or anything else, which is a replay (`rotation_reuse`).
     * Nothing is compared before the session is known to be live, so such a row
     * cannot be used to time-probe the valid rotation-id space.
     *
     * The session's state is read inside `WriteConnection::during()` for the
     * session, so a session that derives any of it from a relation or another
     * table reads it from the writer as well.
     *
     * @formatter:off
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @param  string  $rotationId
     * @param  \Carbon\CarbonImmutable  $now
     * @param  \SineMacula\Laravel\Authentication\Jwt\TokenLifetimes  $lifetimes
     * @return array{0: \SineMacula\Laravel\Authentication\Jwt\Enums\RotationMatch, 1: ?\Carbon\CarbonInterface}|\SineMacula\Laravel\Authentication\Events\Enums\FailureReason
     *
     * @formatter:on
     *
     * @throws \LogicException
     */
    public static function classify(EloquentSession&Model $session, #[\SensitiveParameter] string $rotationId, CarbonImmutable $now, TokenLifetimes $lifetimes): array|FailureReason
    {
        return WriteConnection::during($session, static function () use ($session, $rotationId, $now, $lifetimes): array|FailureReason {

            if ($session->getRevokedAt() !== null) {
                return FailureReason::SESSION_REVOKED;
            }

            $deadlines = SessionDeadlines::liveDeadlines($session, $now);
            $current   = $session->getRefreshKey();

            if ($deadlines === null || $current === null) {
                return $deadlines === null ? FailureReason::SESSION_EXPIRED : FailureReason::REFRESH_KEY_MISSING;
            }

            $match = match (true) {
                RefreshTokenHasher::verify($rotationId, $current)                     => RotationMatch::CURRENT,
                self::isGraceRetry($session, $rotationId, $current, $lifetimes, $now) => RotationMatch::PREVIOUS,
                default                                                               => null,
            };

            return $match === null ? FailureReason::ROTATION_REUSE : [$match, $deadlines[1]];
        });
    }

    /**
     * Whether the rotation id is the one the session's current id replaced,
     * presented inside the grace window. The current id must also be its
     * successor: a row whose digests were changed outside a rotation does not
     * honour the previous id.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @param  string  $rotationId
     * @param  string  $current
     * @param  \SineMacula\Laravel\Authentication\Jwt\TokenLifetimes  $lifetimes
     * @param  \Carbon\CarbonImmutable  $now
     * @return bool
     *
     * @throws \LogicException
     */
    private static function isGraceRetry(Session $session, #[\SensitiveParameter] string $rotationId, string $current, TokenLifetimes $lifetimes, CarbonImmutable $now): bool
    {
        $previous  = $session->getPreviousRefreshKey();
        $rotatedAt = $session->getRefreshRotatedAt();

        if ($previous === null || $rotatedAt === null || !$lifetimes->isWithinGrace($rotatedAt, $now)) {
            return false;
        }

        return RefreshTokenHasher::verify($rotationId, $previous)
            && RefreshTokenHasher::verify(RefreshTokenHasher::successor($rotationId), $current);
    }
}
