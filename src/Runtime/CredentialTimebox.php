<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Runtime;

use Illuminate\Support\Facades\Config;
use Illuminate\Support\Timebox;

/**
 * The credential timebox of one guard: every check of a secret its flows make
 * (`attempt()`, `validate()`, a sign-in, a password reset, a reauthentication)
 * runs in it, so the check takes as long whatever it found.
 *
 * One guard serves a whole request, console command or queue worker, and
 * Laravel's `Timebox` keeps an early return for every later call, so the box is
 * told before each call that it may not return early: a check that fails after
 * one that succeeded on the same guard is padded as well. The budget is read
 * from `authentication.timebox.credentials_microseconds` on each call.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class CredentialTimebox
{
    /** @var int The budget, in microseconds, when none is configured. */
    private const int DEFAULT_MICROSECONDS = 400000;

    /**
     * Constructor.
     *
     * @param  \Illuminate\Support\Timebox  $timebox
     */
    public function __construct(

        /** Laravel's timebox, which pads each call to the budget. */
        private Timebox $timebox,
    ) {}

    /**
     * Run the callback in the credential budget, which it waits out unless the
     * callback ends it early through the `Timebox` it is given.
     *
     * @template TResult
     *
     * @param  \Closure(\Illuminate\Support\Timebox): TResult  $callback
     * @return TResult
     *
     * @throws \Throwable
     */
    public function run(\Closure $callback): mixed
    {
        $this->timebox->dontReturnEarly();

        return $this->timebox->call($callback, $this->microseconds());
    }

    /**
     * The budget a call waits out now, in microseconds. Falls back to the
     * default when the config key is missing, non-positive, or the Config
     * facade is not bootstrapped.
     *
     * @return int
     */
    public function microseconds(): int
    {
        try {
            $configured = Config::integer('authentication.timebox.credentials_microseconds', self::DEFAULT_MICROSECONDS);
        } catch (\Throwable) {
            return self::DEFAULT_MICROSECONDS;
        }

        return $configured > 0 ? $configured : self::DEFAULT_MICROSECONDS;
    }
}
