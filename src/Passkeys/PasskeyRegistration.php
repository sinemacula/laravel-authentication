<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Passkeys;

use SineMacula\Laravel\Authentication\Passkeys\Enums\PasskeyRegistrationStatus;

/**
 * How registering a passkey ended: registered, with the summary of the passkey
 * stored, or refused, with why.
 *
 * A refused registration stores and dispatches nothing. The status names every
 * outcome; `passkey` is set only for `registered`.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class PasskeyRegistration
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Passkeys\Enums\PasskeyRegistrationStatus  $status
     * @param  ?\SineMacula\Laravel\Authentication\Passkeys\PasskeySummary  $passkey
     */
    private function __construct(

        /** How the registration ended. */
        public PasskeyRegistrationStatus $status,

        /** The passkey stored, for `registered` only. */
        public ?PasskeySummary $passkey = null,
    ) {}

    /**
     * The passkey was stored for the identity.
     *
     * @param  \SineMacula\Laravel\Authentication\Passkeys\PasskeySummary  $passkey
     * @return self
     */
    public static function registered(PasskeySummary $passkey): self
    {
        return new self(PasskeyRegistrationStatus::REGISTERED, $passkey);
    }

    /**
     * The challenge is not a live registration challenge of the guard for the
     * identity.
     *
     * @return self
     */
    public static function challengeInvalid(): self
    {
        return new self(PasskeyRegistrationStatus::CHALLENGE_INVALID);
    }

    /**
     * The response is malformed, or does not verify.
     *
     * @return self
     */
    public static function responseInvalid(): self
    {
        return new self(PasskeyRegistrationStatus::RESPONSE_INVALID);
    }

    /**
     * The credential is registered already.
     *
     * @return self
     */
    public static function alreadyRegistered(): self
    {
        return new self(PasskeyRegistrationStatus::ALREADY_REGISTERED);
    }

    /**
     * Whether the passkey was stored.
     *
     * @return bool
     */
    public function isRegistered(): bool
    {
        return $this->status === PasskeyRegistrationStatus::REGISTERED;
    }
}
