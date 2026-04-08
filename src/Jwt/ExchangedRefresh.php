<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Jwt;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Contracts\Device;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;

/**
 * Immutable DTO returned by `RefreshTokenExchange::exchange()` on a
 * successful refresh-token round trip.
 *
 * Carries the resolved contextual triple (identity, principal,
 * device) the `JwtGuard` should bind on its lifecycle, plus the
 * newly issued access + refresh token pair.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 */
final class ExchangedRefresh
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\Device  $device
     * @param  \SineMacula\Laravel\Authentication\Jwt\RefreshResult  $tokens
     */
    public function __construct(

        /** Identity hydrated from the device's `authenticatable` relation. */
        public Identity $identity,

        /** Principal resolved for the identity. */
        public Principal $principal,

        /** Device row whose rotation digest was rotated server-side. */
        public Device&Model $device,

        /** Newly issued access + refresh token pair. */
        public RefreshResult $tokens,

    ) {}
}
