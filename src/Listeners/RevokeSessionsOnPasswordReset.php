<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Listeners;

use Illuminate\Auth\Events\PasswordReset;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Listeners\Concerns\RevokesOnceCommitted;
use SineMacula\Laravel\Authentication\Sessions\SessionService;

/**
 * Optional listener that ends every session of an identity whose password was
 * reset through Laravel's password broker.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class RevokeSessionsOnPasswordReset
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
