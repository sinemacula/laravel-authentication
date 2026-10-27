<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Concerns;

use Carbon\CarbonInterface;

/**
 * Attribute readers behind the `ActsAsDevice` accessors: state that must be
 * loaded, informational values that may be absent, and conversion of stored
 * timestamps and strings.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait ReadsDeviceAttributes
{
    /**
     * Read a device state attribute that must be loaded.
     *
     * @param  string  $name
     * @param  string  $accessor
     * @return mixed
     *
     * @throws \LogicException
     */
    private function loadedDeviceAttribute(string $name, string $accessor): mixed
    {
        if (!array_key_exists($name, $this->getAttributes())) {

            $message = sprintf(
                'Cannot read the device state of %s: its `%s` attribute is not loaded.'
                . ' Select the column or override %s().',
                static::class,
                $name,
                $accessor,
            );

            throw new \LogicException($message);
        }

        return $this->getAttribute($name);
    }

    /**
     * Read an informational attribute, which reads as `null` when it is not
     * loaded.
     *
     * @param  string  $name
     * @return mixed
     */
    private function optionalDeviceAttribute(string $name): mixed
    {
        return array_key_exists($name, $this->getAttributes()) ? $this->getAttribute($name) : null;
    }

    /**
     * Convert a stored timestamp, cast or raw, to a Carbon instance, read as
     * the earliest instant its wall-clock time could be.
     *
     * @param  mixed  $value
     * @return ?\Carbon\CarbonInterface
     */
    private function toDeviceTimestamp(mixed $value): ?CarbonInterface
    {
        if ($value === null) {
            return null;
        }

        return self::earliestInstantOf($value instanceof CarbonInterface ? $value : $this->asDateTime($value));
    }

    /**
     * The earliest instant showing the same wall-clock time as the given time
     * in its timezone.
     *
     * Times are stored without an offset, so one in the hour that repeats when
     * the clocks go back could be either pass through it, and PHP resolves it
     * to the first pass in some timezones and to the second in others. Taking
     * the first pass means the ambiguity can only end a session or a grace
     * window early, never late. The first pass is found from the offset a day
     * earlier, before any change of the clocks that could have made the time
     * ambiguous.
     *
     * @param  \Carbon\CarbonInterface  $time
     * @return \Carbon\CarbonInterface
     */
    private static function earliestInstantOf(CarbonInterface $time): CarbonInterface
    {
        $zone   = $time->getTimezone();
        $offset = $time->getOffset();
        $before = $zone->getOffset((new \DateTimeImmutable('@' . $time->getTimestamp()))->modify('-1 day'));

        if ($before <= $offset) {
            return $time;
        }

        $earlier = $time->getTimestamp() - ($before - $offset);

        return $zone->getOffset(new \DateTimeImmutable('@' . $earlier)) === $before ? $time::createFromTimestamp($earlier, $zone) : $time;
    }

    /**
     * Convert a stored string column to a string, keeping `null`.
     *
     * @param  mixed  $value
     * @return ?string
     */
    private function toDeviceString(mixed $value): ?string
    {
        return $value === null ? null : (string) $value;
    }
}
