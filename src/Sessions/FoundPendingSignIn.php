<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Contracts\EloquentDevice;
use SineMacula\Laravel\Authentication\Models\PendingSignIn;

/**
 * A live pending sign-in a token named, as found: the row, the secret that
 * proved the token, what it is for, and its proven device when that still
 * holds.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class FoundPendingSignIn
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Models\PendingSignIn  $pending
     * @param  string  $secret
     * @param  \SineMacula\Laravel\Authentication\Sessions\PendingFactor  $factor
     * @param  (\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentDevice)|null  $device
     */
    public function __construct(

        /** The pending sign-in's row. */
        public PendingSignIn $pending,

        /** The secret the token carried. */
        #[\SensitiveParameter] public string $secret,

        /** What the pending sign-in is for. */
        public PendingFactor $factor,

        /** The proven device, when it still holds. */
        public (EloquentDevice&Model)|null $device,
    ) {}
}
