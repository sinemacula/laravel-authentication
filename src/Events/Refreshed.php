<?php

declare(strict_types=1);

namespace SineMacula\Laravel\Authentication\Events;

use Illuminate\Queue\SerializesModels;
use SineMacula\Laravel\Authentication\Contracts\Identity;

/**
 * Dispatched after a successful refresh-token exchange.
 *
 * @author    Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright 2026 Sine Macula Limited.
 */
final class Refreshed
{
    use SerializesModels;

    public function __construct(

        /** Name of the guard that performed the refresh. */
        public string $guard,

        /** Identity whose session was refreshed. */
        public Identity $identity,

    ) {}
}
