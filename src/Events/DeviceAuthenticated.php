<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Events;

use Illuminate\Queue\SerializesModels;
use SineMacula\Laravel\Authentication\Contracts\Device;

/**
 * Dispatched when a device is bound to a guard during authentication.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class DeviceAuthenticated
{
    use SerializesModels;

    /**
     * Constructor.
     *
     * @param  string  $guard
     * @param  \SineMacula\Laravel\Authentication\Contracts\Device  $device
     */
    public function __construct(

        /** Name of the guard that bound the device. */
        public string $guard,

        /** Device that was bound to the guard. */
        public Device $device,

    ) {}
}
