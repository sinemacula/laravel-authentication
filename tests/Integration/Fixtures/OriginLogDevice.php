<?php

declare(strict_types = 1);

namespace Tests\Integration\Fixtures;

use SineMacula\Laravel\Authentication\Models\Device;

/**
 * Device model that derives the guard and the sign-in method of its session
 * from a `device_origins` row naming it, falling back to its own columns, as an
 * application might record either outside the device row.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class OriginLogDevice extends Device
{
    /**
     * Return the guard a `device_origins` row records, falling back to the
     * device's own column.
     *
     * @return ?string
     */
    #[\Override]
    public function getGuard(): ?string
    {
        return $this->origin('guard') ?? parent::getGuard();
    }

    /**
     * Return the sign-in method a `device_origins` row records, falling back to
     * the device's own column.
     *
     * @return ?string
     */
    #[\Override]
    public function getSignInMethod(): ?string
    {
        return $this->origin('sign_in_method') ?? parent::getSignInMethod();
    }

    /**
     * Read a column of the device's `device_origins` row, if it has one.
     *
     * @param  string  $column
     * @return ?string
     */
    private function origin(string $column): ?string
    {
        $value = $this->getConnection()
            ->table('device_origins')
            ->where('device_id', $this->getKey())
            ->value($column);

        return is_string($value) ? $value : null;
    }
}
