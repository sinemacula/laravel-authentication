<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Listeners;

use Carbon\CarbonInterface;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Config;
use SineMacula\Laravel\Authentication\Contracts\EloquentDevice;
use SineMacula\Laravel\Authentication\Events\DeviceAuthenticated;

/**
 * Records when, from which IP address, and with which user agent a device was
 * last used, on every authentication that binds it, debounced by a configurable
 * throttle. Only persisted `EloquentDevice` models participate.
 *
 * The client is the one the event carries: the request being served when the
 * device was bound, so a long-running worker records that request, not one the
 * listener saw before.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class RecordDeviceUsage
{
    /** @var int Fallback throttle window (seconds). */
    private const int DEFAULT_THROTTLE_SECONDS = 60;

    /**
     * Handle the DeviceAuthenticated event.
     *
     * @param  \SineMacula\Laravel\Authentication\Events\DeviceAuthenticated  $event
     * @return void
     */
    public function __invoke(DeviceAuthenticated $event): void
    {
        $device = $event->context->device;

        if (!$device instanceof EloquentDevice || !$device instanceof Model || !$device->exists) {
            return;
        }

        $now = Carbon::now();

        if (!$this->shouldRecord($device->getLastUsedAt(), $now)) {
            return;
        }

        $client = $event->context->client;

        $usage = [
            $device->getLastUsedAtName()        => $device->fromDateTime($now),
            $device->getLastUsedIpName()        => $client->ip,
            $device->getLastUsedUserAgentName() => $client->userAgent,
        ];

        $device->newQuery()
            ->whereKey($device->getKey())
            ->update($usage);

        $device->forceFill($usage)->syncOriginalAttributes(array_keys($usage));
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
            'authentication.device.last_used_throttle_seconds',
            self::DEFAULT_THROTTLE_SECONDS,
        );

        return $lastUsedAt->diffInSeconds($now, true) >= $windowSeconds;
    }
}
