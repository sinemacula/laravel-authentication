<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Listeners;

use Illuminate\Container\Container;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Events\PasskeyRemoved;
use SineMacula\Laravel\Authentication\Support\MorphClass;

/**
 * Optional listener: ends every session of an identity that removed a passkey,
 * with reason `factor_removed`, through the session service of the guard the
 * passkey was removed through. `PasskeyRemoved` is dispatched only once the
 * removal is committed, so a removal that is rolled back revokes nothing.
 * Registering it is the opt-in:
 *
 * `Event::listen(PasskeyRemoved::class, RevokeSessionsOnPasskeyRemoval::class);`
 *
 * Every session is revoked, the one the passkey was removed from included; an
 * application that keeps that session signed in calls
 * `Auth::sessions()->credentialRemoved($identity, Auth::session())` itself
 * instead of registering the listener. A passkey the factor package associated
 * as a factor has its removal judged by the factor package, which calls
 * `factorRemoved()` itself; registered alongside it, the listener still ends
 * every session on any passkey's removal.
 *
 * The event names the identity by its type and identifier only, so the identity
 * is loaded again through the guard's identity provider, on the write
 * connection, and its sessions are ended only when it is still there and of the
 * type the event names; an event that names none, or an identity that is gone,
 * ends nothing. The session service comes from the application now serving, not
 * from the container that built the listener, which under Octane is the
 * application the worker booted rather than the request's sandbox.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class RevokeSessionsOnPasskeyRemoval
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
        $context = $event->context;

        if ($context->identityId === null) {
            return;
        }

        /** @var \SineMacula\Laravel\Authentication\AuthManager $auth */
        $auth     = Container::getInstance()->make('auth');
        $sessions = $auth->sessions($context->guard);

        /** @var \Illuminate\Contracts\Auth\Guard&\SineMacula\Laravel\Authentication\Contracts\HasGuardContext $guard */
        $guard    = $auth->guard($context->guard);
        $identity = $guard->context()->provider()->retrieveById($context->identityId);

        if (!$identity instanceof Identity || MorphClass::of($identity) !== $context->identityType) {
            return;
        }

        $sessions->credentialRemoved($identity);
    }
}
