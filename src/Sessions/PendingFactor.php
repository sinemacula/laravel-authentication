<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Authentication\Contracts\Device;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\Tenant;

/**
 * A sign-in that needs a further factor before its session may start: the
 * pending credential that completes it, and who it is for.
 *
 * The token is opaque and is not a JWT, so no guard authenticates a request
 * with it. It works once, for the guard that issued it, until `$expiresAt`.
 * Possessing it proves nothing about the factor: the code that verifies the
 * factor looks the sign-in up with `pending()`, verifies the factor for its
 * identity and principal, and only then calls `complete()`.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class PendingFactor
{
    /**
     * Constructor.
     *
     * @param  string  $token
     * @param  string  $guard
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Tenant  $tenant
     * @param  string  $method
     * @param  \Carbon\CarbonImmutable  $expiresAt
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Device  $provenDevice
     */
    public function __construct(

        /** The pending credential that completes the sign-in. */
        #[\SensitiveParameter] public string $token,

        /** Guard the sign-in is for. */
        public string $guard,

        /** Identity the primary method verified. */
        public Identity $identity,

        /** Principal the session will act as. */
        public Principal $principal,

        /** Tenant the principal acts within, when it has one that may authenticate. */
        public ?Tenant $tenant,

        /** Name of the sign-in method that verified the identity. */
        public string $method,

        /** When the pending credential stops working. */
        public CarbonImmutable $expiresAt,

        /** Existing device the client proved it holds, which the session will continue on, if any. */
        public ?Device $provenDevice,
    ) {}
}
