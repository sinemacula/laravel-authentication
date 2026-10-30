<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Contracts;

use SineMacula\Laravel\Authentication\Passwords\PasswordResetLink;

/**
 * Password reset link sender contract.
 *
 * Delivers a password reset link's token to the identity it was requested for,
 * as a link to the application's own reset route. The default binding,
 * `NotifyingResetLinkSender`, sends Laravel's `ResetPassword` notification;
 * bind another to word the message, carry the guard, or reach an identifier
 * other than an email address.
 *
 * It is called only from the queued delivery job, never during the request that
 * asked for the link, and only once the job has checked that the token is still
 * the live one and that the identity may reset its password. An exception it
 * throws fails the job, so the application's queue retry policy applies; a
 * retry checks the token again first. The message carries the token in clear:
 * do not log it.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface PasswordResetLinkSender
{
    /**
     * Deliver the link's token to its identity.
     *
     * @param  \SineMacula\Laravel\Authentication\Passwords\PasswordResetLink  $message
     * @return void
     */
    public function send(PasswordResetLink $message): void;
}
