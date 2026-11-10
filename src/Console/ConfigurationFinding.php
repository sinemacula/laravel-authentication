<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Console;

use SineMacula\Laravel\Authentication\Console\Enums\FindingSeverity;

/**
 * What a configuration check found: a severity, the guard it is about (`null`
 * for a package-wide setting), and a message.
 *
 * The message names the settings at fault, never their values: the command
 * prints it as it is given (less control characters), and its output reaches
 * deploy logs.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class ConfigurationFinding
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Console\Enums\FindingSeverity  $severity
     * @param  string  $message
     * @param  ?string  $guard
     */
    public function __construct(

        /** Whether the finding fails the command or is only shown. */
        public FindingSeverity $severity,

        /** What was found, naming the settings and never their values. */
        public string $message,

        /** The guard the finding is about, `null` for a package-wide setting. */
        public ?string $guard = null,
    ) {}

    /**
     * A finding that fails the command.
     *
     * @param  string  $message
     * @param  ?string  $guard
     * @return self
     */
    public static function error(string $message, ?string $guard = null): self
    {
        return new self(FindingSeverity::ERROR, $message, $guard);
    }

    /**
     * A finding that is shown and leaves the exit code alone.
     *
     * @param  string  $message
     * @param  ?string  $guard
     * @return self
     */
    public static function warning(string $message, ?string $guard = null): self
    {
        return new self(FindingSeverity::WARNING, $message, $guard);
    }
}
