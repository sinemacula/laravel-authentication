<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Contracts;

use SineMacula\Laravel\Authentication\Codes\OneTimeCodeMessage;

/**
 * Delivers a one-time code to the identifier it was issued for. The message
 * carries the code in clear: do not log it.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface OneTimeCodeSender
{
    /**
     * Deliver the message's code to its identifier.
     *
     * @param  \SineMacula\Laravel\Authentication\Codes\OneTimeCodeMessage  $message
     * @return void
     */
    public function send(OneTimeCodeMessage $message): void;
}
