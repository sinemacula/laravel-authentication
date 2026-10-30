<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Listeners;

use Illuminate\Container\Container;
use SineMacula\Laravel\Authentication\Events\PasskeyRemoved;

/**
 * Optional listener: ends every session of an identity that removed a passkey,
 * with reason `factor_removed`, through the session service of the guard the
 * passkey was removed through. `PasskeyRemoved` is dispatched only once the
 * removal is committed, so a removal that is rolled back revokes nothing.
 * Registering it is the opt-in:
 *
 * `Event::listen(PasskeyRemoved::class, RevokeDevicesOnPasskeyRemoval::class);`
 *
 * Every device is revoked, the one the passkey was removed from included; an
 * application that keeps that device signed in calls
 * `Auth::sessions()->factorRemoved($identity, Auth::device())` itself instead
 * of registering the listener.
 *
 * The session service comes from the application now serving, not from the
 * container that built the listener, which under Octane is the application the
 * worker booted rather than the request's sandbox.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class RevokeDevicesOnPasskeyRemoval
{
    /**
     * End the sessions of the identity that removed the passkey.
     *
     * @param  \SineMacula\Laravel\Authentication\Events\PasskeyRemoved  $event
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Throwable
     */
    public function handle(PasskeyRemoved $event): void
    {
        $identity = $event->context->identity;

        if ($identity === null) {
            return;
        }

        /** @var \SineMacula\Laravel\Authentication\AuthManager $auth */
        $auth = Container::getInstance()->make('auth');

        $auth->sessions($event->context->guard)->factorRemoved($identity);
    }
}
