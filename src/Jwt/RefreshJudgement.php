<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Jwt;

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Contracts\Device;
use SineMacula\Laravel\Authentication\Contracts\EloquentDevice;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Jwt\Enums\RotationMatch;

/**
 * Judges a presented refresh rotation id against the device it names, the way
 * both a refresh and a switch of principal do: whether the device still holds a
 * live session, and whether the id is its current one, the one the current one
 * replaced inside the grace window, or a replay.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class RefreshJudgement
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Judge the presented rotation id against the device at `$now`.
     *
     * In order: a revoked device fails as `device_revoked`; a session past
     * either deadline, or without one, as `session_expired` (an ended session
     * is not revoked: it simply cannot be refreshed); a device holding no
     * refresh credential as `refresh_key_missing`. Only then is the rotation id
     * compared, in constant time: the current one, with the absolute deadline
     * the rotation keeps; the previous one inside the grace window; or anything
     * else, which is a replay (`rotation_reuse`). Nothing is compared before
     * the device is known to be live, so such a row cannot be used to
     * time-probe the valid rotation-id space.
     *
     * The device's state is read inside `WriteConnection::during()` for the
     * device, so a device that derives any of it from a relation or another
     * table reads it from the writer as well.
     *
     * @formatter:off
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentDevice  $device
     * @param  string  $rotationId
     * @param  \Carbon\CarbonImmutable  $now
     * @param  \SineMacula\Laravel\Authentication\Jwt\TokenLifetimes  $lifetimes
     * @return array{0: \SineMacula\Laravel\Authentication\Jwt\Enums\RotationMatch, 1: \Carbon\CarbonInterface}|\SineMacula\Laravel\Authentication\Events\Enums\FailureReason
     *
     * @formatter:on
     *
     * @throws \LogicException
     */
    public static function classify(EloquentDevice&Model $device, #[\SensitiveParameter] string $rotationId, CarbonImmutable $now, TokenLifetimes $lifetimes): array|FailureReason
    {
        return WriteConnection::during($device, static function () use ($device, $rotationId, $now, $lifetimes): array|FailureReason {

            if ($device->getRevokedAt() !== null) {
                return FailureReason::DEVICE_REVOKED;
            }

            $deadlines = TokenLifetimes::liveDeadlines($device, $now);
            $current   = $device->getRefreshKey();

            if ($deadlines === null || $current === null) {
                return $deadlines === null ? FailureReason::SESSION_EXPIRED : FailureReason::REFRESH_KEY_MISSING;
            }

            $match = match (true) {
                RefreshTokenHasher::verify($rotationId, $current)                    => RotationMatch::CURRENT,
                self::isGraceRetry($device, $rotationId, $current, $lifetimes, $now) => RotationMatch::PREVIOUS,
                default                                                              => null,
            };

            return $match === null ? FailureReason::ROTATION_REUSE : [$match, $deadlines[1]];
        });
    }

    /**
     * Whether the rotation id is the one the device's current id replaced,
     * presented inside the grace window. The current id must also be its
     * successor: a row whose digests were changed outside a rotation does not
     * honour the previous id.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Device  $device
     * @param  string  $rotationId
     * @param  string  $current
     * @param  \SineMacula\Laravel\Authentication\Jwt\TokenLifetimes  $lifetimes
     * @param  \Carbon\CarbonImmutable  $now
     * @return bool
     *
     * @throws \LogicException
     */
    private static function isGraceRetry(Device $device, #[\SensitiveParameter] string $rotationId, string $current, TokenLifetimes $lifetimes, CarbonImmutable $now): bool
    {
        $previous  = $device->getPreviousRefreshKey();
        $rotatedAt = $device->getRefreshRotatedAt();

        if ($previous === null || $rotatedAt === null || !$lifetimes->isWithinGrace($rotatedAt, $now)) {
            return false;
        }

        return RefreshTokenHasher::verify($rotationId, $previous)
            && RefreshTokenHasher::verify(RefreshTokenHasher::successor($rotationId), $current);
    }
}
