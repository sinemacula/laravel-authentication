<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Passkeys;

use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;

/**
 * How verifying one of an identity's passkeys as a further factor ended.
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
     * @param  ?\SineMacula\Laravel\Authentication\Passkeys\PasskeyFactorAssertion  $assertion
     * @param  ?\SineMacula\Laravel\Authentication\Events\Enums\FailureReason  $reason
     */
    private function __construct(

        /** What the verified assertion showed, when one verified. */
        public ?PasskeyFactorAssertion $assertion = null,

        /** Why the passkey did not verify, when it did not. */
        public ?FailureReason $reason = null,
    ) {}

    /**
     * The identity's passkey verified.
     *
     * @param  \SineMacula\Laravel\Authentication\Passkeys\PasskeyFactorAssertion  $assertion
     * @return self
     */
    public static function verified(PasskeyFactorAssertion $assertion): self
    {
        return new self(assertion: $assertion);
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
        return $this->assertion !== null;
    }

    /**
     * Whether the verification was refused.
     *
     * @return bool
     */
    public function isFailed(): bool
    {
        return $this->assertion === null;
    }
}
