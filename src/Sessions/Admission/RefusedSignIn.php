<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions\Admission;

use SineMacula\Laravel\Authentication\Contracts\Device;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;

/**
 * A sign-in that failed: why, and the context it had established by then, which
 * the failure events carry.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class RefusedSignIn
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\FailureReason  $reason
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Tenant  $tenant
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Device  $device
     * @param  ?int  $retryAfter
     */
    public function __construct(

        /** Why the sign-in failed. */
        public FailureReason $reason,

        /** The verified identity, if the sign-in got that far. */
        public ?Identity $identity = null,

        /** The resolved principal, if the sign-in got that far. */
        public ?Principal $principal = null,

        /** The tenant the principal acts within, if the sign-in got that far. */
        public ?Tenant $tenant = null,

        /** The device the sign-in concerned, if any. */
        public ?Device $device = null,

        /** Seconds until another attempt may be made, for `rate_limited` and `account_rate_limited` only. */
        public ?int $retryAfter = null,
    ) {}

    /**
     * Refuse an admitted sign-in that a later check failed, keeping its
     * context.
     *
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\FailureReason  $reason
     * @param  \SineMacula\Laravel\Authentication\Sessions\Admission\AdmittedSignIn  $admitted
     * @return self
     */
    public static function after(FailureReason $reason, AdmittedSignIn $admitted): self
    {
        return new self($reason, $admitted->identity, $admitted->principal, $admitted->tenant, $admitted->device);
    }
}
