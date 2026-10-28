<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Listeners;

use Illuminate\Auth\Events\Attempting;
use Illuminate\Auth\Events\Authenticated;
use Illuminate\Auth\Events\Failed;
use Illuminate\Auth\Events\Login;
use Illuminate\Auth\Events\OtherDeviceLogout;
use Illuminate\Auth\Events\Validated;
use Illuminate\Container\Container;
use SineMacula\Laravel\Authentication\Sessions\Methods\Rehashing;

/**
 * Follows every guard's credential attempts through Laravel's auth events, so
 * the automatic rehash a guard runs between validating an attempt's credentials
 * and ending the attempt is marked as one (see `Rehashing`): a password-change
 * listener then does not take Laravel's own rehash on login for a change of
 * password. `OtherDeviceLogout` sets apart the forced rehash of
 * `logoutOtherDevices()`, which is a change.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class TrackCredentialAttempts
{
    /**
     * Handle one of the attempt's events.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  \Illuminate\Auth\Events\Attempting|\Illuminate\Auth\Events\Authenticated|\Illuminate\Auth\Events\Failed|\Illuminate\Auth\Events\Login|\Illuminate\Auth\Events\OtherDeviceLogout|\Illuminate\Auth\Events\Validated  $event
     * @return void
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function __invoke(Attempting|Authenticated|Failed|Login|OtherDeviceLogout|Validated $event): void
    {
        $rehashing = Container::getInstance()->make(Rehashing::class);

        if ($event instanceof Attempting) {
            $rehashing->attempting($event->guard, $event->credentials);
        } elseif ($event instanceof Validated) {
            $rehashing->validated($event->guard, $event->user);
        } elseif ($event instanceof OtherDeviceLogout) {
            $rehashing->forced($event->user);
        } else {
            $rehashing->ended($event->guard);
        }
    }
}
