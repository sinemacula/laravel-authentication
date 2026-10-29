<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Factors;

use SineMacula\Laravel\Authentication\Contracts\Device;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Http\ClientContext;

/**
 * Everything an additional-factor policy decides on: the guard, who is signing
 * in and as which principal, how, and from which client.
 *
 * `$provenDevice` is set only when the client proved, with its current refresh
 * token, that it holds an existing session of this guard on the same identity
 * and principal, which the sign-in will then continue on. A policy that trusts
 * a device it has seen a factor on (keyed by the device identifier) can rely on
 * it. A device merely named by the caller never appears here.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class AdditionalFactorContext
{
    /**
     * Constructor.
     *
     * @param  string  $guard
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Tenant  $tenant
     * @param  string  $method
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @param  ?string  $clientName
     * @param  ?string  $platform
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Device  $provenDevice
     */
    public function __construct(

        /** Guard the sign-in is for. */
        public string $guard,

        /** Identity the primary method verified. */
        public Identity $identity,

        /** Principal the session would act as. */
        public Principal $principal,

        /** Tenant the principal acts within, if any. */
        public ?Tenant $tenant,

        /** Name of the sign-in method that verified the identity. */
        public string $method,

        /** Client the sign-in came from. */
        public ClientContext $client,

        /** Name the client gave itself, if any. */
        public ?string $clientName,

        /** Platform the client reported, if any. */
        public ?string $platform,

        /** Existing device of this guard, identity and principal the client proved it holds, if any. */
        public ?Device $provenDevice,
    ) {}
}
