<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Contracts;

use SineMacula\Laravel\Authentication\Passwords\PasswordResetLink;

/**
 * Delivers a password reset link's token to the identity it was requested for.
 * The message carries the token in clear: do not log it.
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
