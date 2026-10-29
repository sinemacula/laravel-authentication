<?php

declare(strict_types = 1);

namespace Tests\Performance\Fixtures;

use SineMacula\Laravel\Authentication\Codes\OneTimeCodeMessage;
use SineMacula\Laravel\Authentication\Contracts\OneTimeCodeSender;

/**
 * A sender as slow as a remote SMS or mail gateway, counting what it sends.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class SlowOneTimeCodeSender implements OneTimeCodeSender
{
    /** @var int How long a delivery takes, in microseconds. */
    public const int MICROSECONDS = 250000;

    /** @var int Messages sent. */
    private int $sent = 0;

    /**
     * Take as long as a gateway, then count the message.
     *
     * @param  \SineMacula\Laravel\Authentication\Codes\OneTimeCodeMessage  $message
     * @return void
     */
    #[\Override]
    public function send(OneTimeCodeMessage $message): void
    {
        usleep(self::MICROSECONDS);

        $this->sent++;
    }

    /**
     * How many messages were sent.
     *
     * @return int
     */
    public function count(): int
    {
        return $this->sent;
    }
}
