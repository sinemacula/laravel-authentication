<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Exceptions;

use SineMacula\Laravel\Authentication\Contracts\EloquentDevice;

/**
 * Thrown when the configured device model does not satisfy the explicit
 * Eloquent-backed persistence boundary required by refresh and last-seen flows.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Ltd
 */
final class InvalidDeviceModelConfiguration extends \RuntimeException
{
    /**
     * Build an exception describing an unsupported configured device model.
     *
     * @param  string  $configured
     * @return static
     */
    public static function unsupported(string $configured): static
    {
        $display = $configured === '' ? '(empty string)' : $configured;

        return new self(sprintf(
            'authentication.device.model must be a non-empty class-string of an Eloquent model implementing [%s]; got [%s].',
            EloquentDevice::class,
            $display,
        ));
    }
}
