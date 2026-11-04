<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Passkeys;

use SineMacula\Laravel\Authentication\Passkeys\Enums\PasskeyRegistrationStatus;

/**
 * How registering a passkey ended: registered, with the summary of the passkey
 * stored and the factor package's association of it as a factor, if its gate
 * made one, or refused, with why.
 *
 * A refused registration stores and dispatches nothing. The status names every
 * outcome; `passkey` is set only for `registered`, and `factor` only for a
 * registered passkey the factor gate associated, its `completion` carrying the
 * factor package's completion of the registration, if any, uninterpreted (the
 * current session's new pending credential, for one, when the registration
 * returned it to pending).
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
     * @param  ?\SineMacula\Laravel\Authentication\Passkeys\PasskeyFactorAssociation  $factor
     */
    private function __construct(

        /** How the registration ended. */
        public PasskeyRegistrationStatus $status,

        /** The passkey stored, for `registered` only. */
        public ?PasskeySummary $passkey = null,

        /** The factor the gate associated the passkey as, if it did. */
        public ?PasskeyFactorAssociation $factor = null,
    ) {}

    /**
     * The passkey was stored for the identity, associated as the factor given,
     * if any.
     *
     * @param  \SineMacula\Laravel\Authentication\Passkeys\PasskeySummary  $passkey
     * @param  ?\SineMacula\Laravel\Authentication\Passkeys\PasskeyFactorAssociation  $factor
     * @return self
     */
    public static function registered(PasskeySummary $passkey, ?PasskeyFactorAssociation $factor = null): self
    {
        return new self(PasskeyRegistrationStatus::REGISTERED, $passkey, $factor);
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
