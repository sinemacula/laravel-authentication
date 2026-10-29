<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Contracts;

use SineMacula\Laravel\Authentication\Codes\OneTimeCodeMessage;

/**
 * One-time code sender contract.
 *
 * Delivers a one-time code to the phone number or email address it was issued
 * for, through the application's own SMS or mail gateway: the package ships no
 * provider, and the application binds its implementation in the container.
 *
 * It is called only from the queued delivery job, never during the request that
 * asked for the code, and only once the job has checked that the code is still
 * the current one for its identifier and that the recipient may receive it. An
 * exception it throws fails the job, so the application's queue retry policy
 * applies; a retry checks the code again first, so a code that expired or was
 * replaced meanwhile is never sent. The message carries the code in clear: do
 * not log it.
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
