<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Events;

use SineMacula\Laravel\Authentication\Events\Enums\RefreshFailureReason;

/**
 * Dispatched when a refresh-token exchange fails. Carries a machine-readable
 * `reason` code for attribution.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class RefreshFailed
{
    /**
     * Constructor.
     *
     * @param  string  $guard
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\RefreshFailureReason  $reason
     * @param  ?string  $deviceId
     */
    public function __construct(

        /** Name of the guard that attempted the refresh. */
        public string $guard,

        /** Machine-readable failure reason. */
        public RefreshFailureReason $reason,

        /** Device identifier from the token, when parseable. */
        public ?string $deviceId = null,

    ) {}
}
