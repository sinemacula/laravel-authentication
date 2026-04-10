<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Jwt;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Contracts\Device;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;

/**
 * Immutable result of a successful refresh-token exchange.
 *
 * Carries the resolved contextual triple plus the newly issued access + refresh
 * token pair.
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

        /** Authenticated identity resolved from the refreshed device. */
        public Identity $identity,

        /** Principal bound to the refreshed session. */
        public Principal $principal,

        /** Device whose refresh credential was rotated. */
        public Device&Model $device,

        /** Newly issued access + refresh token pair. */
        public RefreshResult $tokens,

    ) {}
}
