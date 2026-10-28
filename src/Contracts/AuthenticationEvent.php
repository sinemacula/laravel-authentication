<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Contracts;

use SineMacula\Laravel\Authentication\Events\EventContext;

/**
 * Implemented by every event the package dispatches, so one listener can take
 * them all (`Event::listen(AuthenticationEvent::class, ...)`) and attribute
 * each through the same context. Laravel's own auth events (`Attempting`,
 * `Validated`, `Login`, `Authenticated`, `Failed`, `Logout`) do not implement
 * it.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface AuthenticationEvent
{
    /**
     * Return who and what the event is about.
     *
     * @return \SineMacula\Laravel\Authentication\Events\EventContext
     */
    public function context(): EventContext;
}
