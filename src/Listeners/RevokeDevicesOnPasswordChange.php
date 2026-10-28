<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Listeners;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Listeners\Concerns\RevokesOnceCommitted;
use SineMacula\Laravel\Authentication\Sessions\Methods\Rehashing;
use SineMacula\Laravel\Authentication\Sessions\SessionService;

/**
 * Optional Eloquent observer for identity models: ends every session of an
 * identity whose password column changed, with reason `password_changed`, once
 * the change is committed. Registering it is the opt-in:
 *
 * `User::observe(RevokeDevicesOnPasswordChange::class);`
 *
 * The automatic rehash of a password on sign-in is not a change of password and
 * revokes nothing: the package's own, and the one Laravel's guards run in
 * `attempt()`, `attemptWhen()` and `once()`, which re-encodes the password the
 * attempt was made with (see `Rehashing`); another password saved before the
 * attempt ends, by an `attemptWhen()` callback say, is a change, and so is
 * every save of the identity after it, a change back to the attempt's password
 * included. The forced rehash of `logoutOtherDevices()` is a sign-out of the
 * other sessions and is answered as a change, even while an attempt for the
 * user is open or was abandoned by an exception. Every device is revoked, the
 * one the change was made from included; an application that keeps that device
 * signed in calls `Auth::sessions()->passwordChanged($identity,
 * Auth::device())` itself instead of registering the observer. Only changes
 * saved through Eloquent are seen: a query-builder update fires no model event.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class RevokeDevicesOnPasswordChange
{
    use RevokesOnceCommitted;

    /**
     * Handle the identity's update.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $model
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function updated(Model $model): void
    {
        if (!$model instanceof Identity || !$model->wasChanged($model->getAuthPasswordName())) {
            return;
        }

        $this->container->make(Rehashing::class)->unlessRehash($model, $model->getOriginal($model->getAuthPasswordName()), function () use ($model): void {
            $this->revokeOnceCommitted($model, static fn (SessionService $sessions): int => $sessions->passwordChanged($model));
        });
    }
}
