<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Passwords;

use Illuminate\Contracts\Auth\CanResetPassword;
use SineMacula\Laravel\Authentication\Contracts\PasswordResetLinkSender;

/**
 * The default password reset link sender: Laravel's own, through
 * `CanResetPassword::sendPasswordResetNotification($token)`, so its
 * `ResetPassword` notification and that notification's `createUrlUsing()` and
 * `toMailUsing()` hooks keep working.
 *
 * Laravel's notification builds the link from the identity's
 * `getEmailForPasswordReset()` and no guard, and states the expiry of
 * `auth.passwords.*.expire`, so it suits only a guard whose password identifier
 * is `email`, with one reset route per guard and that expiry kept in step with
 * `authentication.passwords.reset.link_ttl_seconds`; a reset link is refused
 * before anything is counted for any other identifier while this sender is
 * bound. An identity that does not implement `CanResetPassword` fails the job
 * with a `LogicException`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class NotifyingResetLinkSender implements PasswordResetLinkSender
{
    /** @var string The only identifier type Laravel's notification can carry. */
    public const string IDENTIFIER_TYPE = 'email';

    /**
     * Send the identity Laravel's password reset notification with the token.
     *
     * @param  \SineMacula\Laravel\Authentication\Passwords\PasswordResetLink  $message
     * @return void
     *
     * @throws \LogicException
     */
    #[\Override]
    public function send(PasswordResetLink $message): void
    {
        $identity = $message->identity;

        if (!$identity instanceof CanResetPassword) {
            $message = sprintf(
                '%s cannot be sent a password reset link: it does not implement %s; bind a %s of your own.',
                $identity::class,
                CanResetPassword::class,
                PasswordResetLinkSender::class,
            );

            throw new \LogicException($message);
        }

        $identity->sendPasswordResetNotification($message->token());
    }
}
