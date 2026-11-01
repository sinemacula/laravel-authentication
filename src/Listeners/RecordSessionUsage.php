<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Listeners;

use Carbon\CarbonInterface;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Config;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Events\SessionAuthenticated;

/**
 * Records when, from which IP address, and with which user agent a session was
 * last used, on every authentication that binds it, debounced by a configurable
 * throttle. Only persisted `EloquentSession` models participate.
 *
 * The client is the one the event carries: the request being served when the
 * session was bound, so a long-running worker records that request, not one the
 * listener saw before.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class RecordSessionUsage
{
    /** @var int Fallback throttle window (seconds). */
    private const int DEFAULT_THROTTLE_SECONDS = 60;

    /**
     * Handle the SessionAuthenticated event.
     *
     * @param  \SineMacula\Laravel\Authentication\Events\SessionAuthenticated  $event
     * @return void
     */
    public function __invoke(SessionAuthenticated $event): void
    {
        $session = $event->context->session;

        if (!$session instanceof EloquentSession || !$session instanceof Model || !$session->exists) {
            return;
        }

        $now = Carbon::now();

        if (!$this->shouldRecord($session->getLastUsedAt(), $now)) {
            return;
        }

        $client = $event->context->client;

        $usage = [
            $session->getLastUsedAtName()        => $session->fromDateTime($now),
            $session->getLastUsedIpName()        => $client->ip,
            $session->getLastUsedUserAgentName() => $client->userAgent,
        ];

        $session->newQuery()
            ->whereKey($session->getKey())
            ->update($usage);

        $session->forceFill($usage)->syncOriginalAttributes(array_keys($usage));
    }

    /**
     * Whether the use should be recorded now: on first use, or once the
     * configured throttle window has elapsed since the last recorded use. A
     * window of zero or less records every use, and a last use recorded in the
     * future (a clock that ran ahead) counts by its distance from now, so it is
     * corrected rather than blocking every write until it is reached.
     *
     * @param  ?\Carbon\CarbonInterface  $lastUsedAt
     * @param  \Carbon\CarbonInterface  $now
     * @return bool
     */
    private function shouldRecord(?CarbonInterface $lastUsedAt, CarbonInterface $now): bool
    {
        if ($lastUsedAt === null) {
            return true;
        }

        $windowSeconds = Config::integer(
            'authentication.session.last_used_throttle_seconds',
            self::DEFAULT_THROTTLE_SECONDS,
        );

        return $lastUsedAt->diffInSeconds($now, true) >= $windowSeconds;
    }
}
