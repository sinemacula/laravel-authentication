<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Passkeys;

use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;

/**
 * How verifying one of an identity's passkeys as a further factor ended:
 * verified, with the summary of the passkey as its use left it, or refused,
 * with why.
 *
 * The reason is not concealed, since the caller already holds the identity, and
 * nothing reports or counts a refusal: the factor's outcome is the
 * further-factor package's to report and limit.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class PasskeyFactorResult
{
    /**
     * Constructor.
     *
     * @param  ?\SineMacula\Laravel\Authentication\Passkeys\PasskeySummary  $passkey
     * @param  ?\SineMacula\Laravel\Authentication\Events\Enums\FailureReason  $reason
     */
    private function __construct(

        /** The passkey that verified, when one did. */
        public ?PasskeySummary $passkey = null,

        /** Why the passkey did not verify, when it did not. */
        public ?FailureReason $reason = null,
    ) {}

    /**
     * The identity's passkey verified.
     *
     * @param  \SineMacula\Laravel\Authentication\Passkeys\PasskeySummary  $passkey
     * @return self
     */
    public static function verified(PasskeySummary $passkey): self
    {
        return new self(passkey: $passkey);
    }

    /**
     * No passkey of the identity verified.
     *
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\FailureReason  $reason
     * @return self
     */
    public static function failed(FailureReason $reason): self
    {
        return new self(reason: $reason);
    }

    /**
     * Whether the identity's passkey verified.
     *
     * @return bool
     */
    public function isVerified(): bool
    {
        return $this->passkey !== null;
    }

    /**
     * Whether the verification was refused.
     *
     * @return bool
     */
    public function isFailed(): bool
    {
        return $this->passkey === null;
    }
}
