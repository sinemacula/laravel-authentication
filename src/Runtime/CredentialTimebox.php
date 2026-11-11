<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Runtime;

use Illuminate\Support\Facades\Config;
use Illuminate\Support\Timebox;

/**
 * The credential timebox of one guard, in which every check of a secret its
 * flows make runs.
 *
 * Laravel's `Timebox` keeps an early return for every later call, so each call
 * resets it.
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
     * Run the callback in the credential budget.
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
     * The budget a call waits out now, in microseconds.
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
