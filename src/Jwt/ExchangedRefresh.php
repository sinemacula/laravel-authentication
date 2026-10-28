<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Jwt;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Contracts\EloquentDevice;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\Tenant;

/**
 * Immutable result of a successful refresh-token exchange.
 *
 * Carries the resolved contextual triple, the tenant the principal's activity
 * check loaded, the sign-in method the device's session records, and the newly
 * issued access + refresh token pair.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class ExchangedRefresh
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentDevice  $device
     * @param  \SineMacula\Laravel\Authentication\Jwt\RefreshResult  $tokens
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Tenant  $tenant
     * @param  ?string  $method
     */
    public function __construct(

        /** Authenticated identity resolved from the refreshed device. */
        public Identity $identity,

        /** Principal bound to the refreshed session. */
        public Principal $principal,

        /** Device whose refresh credential was rotated. */
        public EloquentDevice&Model $device,

        /** Newly issued access + refresh token pair. */
        public RefreshResult $tokens,

        /** Tenant the principal acts within, as its activity check loaded it, if any. */
        public ?Tenant $tenant = null,

        /** Name of the sign-in method the device's session records. */
        public ?string $method = null,
    ) {}
}
