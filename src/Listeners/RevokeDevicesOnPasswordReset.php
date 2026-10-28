<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Listeners;

use Illuminate\Auth\Events\PasswordReset;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Listeners\Concerns\RevokesOnceCommitted;
use SineMacula\Laravel\Authentication\Sessions\SessionService;

/**
 * Optional listener: ends every session of an identity whose password was reset
 * through Laravel's password broker (`PasswordReset`), with reason
 * `password_reset`, once the reset is committed. Registering it is the opt-in:
 *
 * `Event::listen(PasswordReset::class, RevokeDevicesOnPasswordReset::class);`
 *
 * Revocation covers every guard; the acting guard is the one given to the
 * listener, else the default guard when it is a jwt guard, else the first jwt
 * guard configured. A user that is not an `Identity` is left alone.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class RevokeDevicesOnPasswordReset
{
    use RevokesOnceCommitted;

    /**
     * Handle the password reset.
     *
     * @param  \Illuminate\Auth\Events\PasswordReset  $event
     * @return void
     */
    public function __invoke(PasswordReset $event): void
    {
        $user = $event->user;

        if (!$user instanceof Identity) {
            return;
        }

        $this->revokeOnceCommitted($user, static fn (SessionService $sessions): int => $sessions->passwordReset($user));
    }
}
