<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions\Admission;

use SineMacula\Laravel\Authentication\Contracts\Device;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\Tenant;

/**
 * A sign-in the guard admitted: the active identity, the active principal it
 * acts as, the active tenant that principal acts within, if any, and the device
 * the sign-in continues on, once one is known.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class AdmittedSignIn
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Tenant  $tenant
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Device  $device
     */
    public function __construct(

        /** The identity signing in. */
        public Identity $identity,

        /** The principal it acts as. */
        public Principal $principal,

        /** The tenant the principal acts within, if any. */
        public ?Tenant $tenant,

        /** The device the sign-in continues on, if any. */
        public ?Device $device = null,
    ) {}

    /**
     * The same sign-in, continuing on the given device.
     *
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Device  $device
     * @return self
     */
    public function on(?Device $device): self
    {
        return new self($this->identity, $this->principal, $this->tenant, $device);
    }
}
