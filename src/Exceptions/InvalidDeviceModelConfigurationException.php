<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Exceptions;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Contracts\EloquentDevice;

/**
 * Thrown when the configured device model does not satisfy the explicit
 * Eloquent-backed persistence boundary required by refresh and last-seen flows.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class InvalidDeviceModelConfigurationException extends \RuntimeException
{
    /**
     * Validate that the class satisfies the Eloquent device boundary.
     *
     * @param  string  $class
     * @return void
     *
     * @throws static
     */
    public static function validate(string $class): void
    {
        if (
            $class === ''
            || !class_exists($class)
            || !is_subclass_of($class, Model::class)
            || !is_subclass_of($class, EloquentDevice::class)
        ) {

            throw self::unsupported($class);
        }
    }

    /**
     * Build an exception for an unsupported device model.
     *
     * @param  string  $configured
     * @return static
     */
    public static function unsupported(string $configured): static
    {
        $display = $configured === '' ? '(empty string)' : $configured;

        return new self(
            sprintf(
                'authentication.device.model must be a non-empty class-string of an Eloquent model implementing [%s]; got [%s].',
                EloquentDevice::class,
                $display,
            ),
        );
    }
}
