<?php

declare(strict_types = 1);

namespace Tests\Performance\Fixtures;

use SineMacula\Laravel\Authentication\Contracts\PasswordResetLinkSender;
use SineMacula\Laravel\Authentication\Passwords\PasswordResetLink;

/**
 * A password reset link sender that takes as long as a mail gateway, so a test
 * can tell a delivery made inside the request from one made after it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class SlowPasswordResetLinkSender implements PasswordResetLinkSender
{
    /** @var int How long a delivery takes, in microseconds. */
    public const int MICROSECONDS = 250000;

    /** @var int Links sent. */
    private int $sent = 0;

    /**
     * Take as long as a gateway, then count the link.
     *
     * @param  \SineMacula\Laravel\Authentication\Passwords\PasswordResetLink  $message
     * @return void
     */
    #[\Override]
    public function send(PasswordResetLink $message): void
    {
        usleep(self::MICROSECONDS);

        $this->sent++;
    }

    /**
     * How many links were sent.
     *
     * @return int
     */
    public function count(): int
    {
        return $this->sent;
    }
}
