<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Events;

use Illuminate\Contracts\Events\ShouldDispatchAfterCommit;
use Illuminate\Queue\SerializesModels;
use SineMacula\Laravel\Authentication\Contracts\Device;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;

/**
 * Dispatched after a successful refresh-token exchange. Carries the full
 * contextual surface so activity-log consumers can attribute the refresh
 * without a second round-trip through the guard.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 */
final class Refreshed implements ShouldDispatchAfterCommit
{
    use SerializesModels;

    /**
     * Constructor.
     *
     * @param  string  $guard
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  \SineMacula\Laravel\Authentication\Contracts\Device  $device
     */
    public function __construct(

        /** Name of the guard that performed the refresh. */
        public string $guard,

        /** Identity whose session was refreshed. */
        public Identity $identity,

        /** Principal bound on the refreshed guard. */
        public Principal $principal,

        /** Device whose rotation-id was rotated during the exchange. */
        public Device $device,

    ) {}
}
