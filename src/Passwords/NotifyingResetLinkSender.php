<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Passwords;

use Illuminate\Contracts\Auth\CanResetPassword;
use SineMacula\Laravel\Authentication\Contracts\PasswordResetLinkSender;

/**
 * The default password reset link sender, through Laravel's
 * `CanResetPassword::sendPasswordResetNotification()`.
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

        $identity->sendPasswordResetNotification($message->token()->reveal());
    }
}
