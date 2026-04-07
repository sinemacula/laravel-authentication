<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Guards\Concerns;

use Illuminate\Auth\Events\Attempting;
use Illuminate\Auth\Events\Failed;
use Illuminate\Auth\Events\Validated;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Timebox;

/**
 * Provides the timing-safe credential-validation primitive plus the
 * standard Laravel `Attempting` / `Validated` / `Failed` event-firing
 * helpers.
 *
 * Used by `AbstractGuard` so the credential-validation surface is
 * decomposed away from the contextual binding surface.
 *
 * Expects the using class to declare:
 * - `protected string $name`
 * - `protected \Illuminate\Contracts\Events\Dispatcher $events`
 * - `protected \Illuminate\Support\Timebox $timebox`
 * - `protected \SineMacula\Laravel\Authentication\Contracts\IdentityProvider $provider`
 *
 * @author    Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright 2026 Sine Macula Limited.
 *
 * @property string $name
 * @property \Illuminate\Contracts\Events\Dispatcher $events
 * @property \Illuminate\Support\Timebox $timebox
 * @property \SineMacula\Laravel\Authentication\Contracts\IdentityProvider $provider
 */
trait ValidatesGuardCredentials
{
    /** @var int Default timebox budget (microseconds) when no project override is set. */
    protected const int DEFAULT_TIMEBOX_MICROSECONDS = 400000;

    /**
     * Timing-safe credential validation.
     *
     * Wraps the hasher check inside `Timebox::call()` so the call site
     * takes the same elapsed time regardless of whether the supplied
     * identifier resolved to a persisted user (NFR-04). The `Validated`
     * standard event is fired from inside the timebox so subscribers
     * still observe a successful hasher check.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable|null  $user
     * @param  array<string, mixed>  $credentials
     * @return bool
     */
    protected function hasValidCredentials(
        ?Authenticatable $user,
        #[\SensitiveParameter] array $credentials,
    ): bool {

        return $this->timebox->call(function () use ($user, $credentials): bool {

            $valid = $user !== null && $this->provider->validateCredentials($user, $credentials);

            if ($valid) {
                $this->fireValidatedEvent($user);
            }

            return $valid;
        }, $this->timeboxMicroseconds());
    }

    /**
     * Resolve the configured timebox budget (microseconds). Falls back
     * to the trait default when the config key is missing,
     * non-positive, or the Config facade is not bootstrapped (the
     * latter matters only to plain-`TestCase` unit tests).
     *
     * @return int
     */
    protected function timeboxMicroseconds(): int
    {
        try {
            $configured = Config::integer(
                'laravel-authentication.timebox.credentials_microseconds',
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
     * Fire the standard Laravel `Failed` event.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable|null  $user
     * @param  array<string, mixed>  $credentials
     * @return void
     */
    protected function fireFailedEvent(
        ?Authenticatable $user,
        #[\SensitiveParameter] array $credentials,
    ): void {
        $this->events->dispatch(new Failed($this->name, $user, $credentials));
    }
}
