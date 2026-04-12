<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Guards\Concerns;

use Illuminate\Auth\Events\Attempting;
use Illuminate\Auth\Events\Failed;
use Illuminate\Auth\Events\Validated;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\Config;

/**
 * Credential-validation primitive plus the standard Laravel
 * `Attempting` / `Validated` / `Failed` event-firing helpers.
 *
 * Timing safety is the caller's responsibility: the enclosing guard flow
 * wraps the retrieve -> validate -> dispatch pipeline in a single
 * top-level timebox. Do not nest another timebox here.
 *
 * Expects the using class to declare:
 * - `protected string $name`
 * - `protected \Illuminate\Contracts\Events\Dispatcher $events`
 * - `protected \Illuminate\Support\Timebox $timebox`
 * - `protected \SineMacula\Laravel\Authentication\Contracts\IdentityProvider $provider`
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @property string $name
 * @property \Illuminate\Contracts\Events\Dispatcher $events
 * @property \Illuminate\Support\Timebox $timebox
 * @property \SineMacula\Laravel\Authentication\Contracts\IdentityProvider $provider
 */
trait ValidatesGuardCredentials
{
    /** @var int Default timebox budget in microseconds. */
    protected const int DEFAULT_TIMEBOX_MICROSECONDS = 400000;

    /**
     * Credential validation; fires `Validated` on success.
     *
     * Accepts a nullable user so callers can pass the `retrieveByCredentials`
     * result straight in without short-circuiting on `null`. The uniform call
     * path is what gives the enclosing timebox its timing-safety guarantee.
     *
     * @param  ?\Illuminate\Contracts\Auth\Authenticatable  $user
     * @param  array<string, mixed>  $credentials
     * @return bool
     */
    protected function hasValidCredentials(?Authenticatable $user, #[\SensitiveParameter] array $credentials): bool
    {
        $valid = $user !== null && $this->provider->validateCredentials($user, $credentials);

        if ($valid) {
            $this->fireValidatedEvent($user);
        }

        return $valid;
    }

    /**
     * Fire the standard Laravel `Validated` event.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $user
     * @return void
     */
    protected function fireValidatedEvent(Authenticatable $user): void
    {
        $this->events->dispatch(new Validated($this->name, $user));
    }

    /**
     * Resolve the configured timebox budget in microseconds. Falls back to the
     * default when the config key is missing, non-positive, or the Config
     * facade is not bootstrapped.
     *
     * @return int
     */
    protected function timeboxMicroseconds(): int
    {
        try {
            $configured = Config::integer(
                'authentication.timebox.credentials_microseconds',
                self::DEFAULT_TIMEBOX_MICROSECONDS,
            );
        } catch (\Throwable) {
            return self::DEFAULT_TIMEBOX_MICROSECONDS;
        }

        return $configured > 0 ? $configured : self::DEFAULT_TIMEBOX_MICROSECONDS;
    }

    /**
     * Fire the standard Laravel `Attempting` event.
     *
     * @param  array<string, mixed>  $credentials
     * @return void
     */
    protected function fireAttemptingEvent(#[\SensitiveParameter] array $credentials): void
    {
        $this->events->dispatch(new Attempting($this->name, $credentials, false));
    }

    /**
     * Fire the standard Laravel `Failed` event.
     *
     * @param  ?\Illuminate\Contracts\Auth\Authenticatable  $user
     * @param  array<string, mixed>  $credentials
     * @return void
     */
    protected function fireFailedEvent(?Authenticatable $user, #[\SensitiveParameter] array $credentials): void
    {
        $this->events->dispatch(new Failed($this->name, $user, $credentials));
    }
}
