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
 * registered passkey the factor gate associated, its `completion` the factor
 * package's own, uninterpreted.
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
     * The challenge is malformed, unknown, or not a registration challenge of
     * the guard for the identity.
     *
     * @return self
     */
    public static function challengeInvalid(): self
    {
        return new self(PasskeyRegistrationStatus::CHALLENGE_INVALID);
    }

    /**
     * The identity's registration challenge expired before it was answered.
     *
     * @return self
     */
    public static function challengeExpired(): self
    {
        return new self(PasskeyRegistrationStatus::CHALLENGE_EXPIRED);
    }

    /**
     * A response was submitted to the identity's registration challenge before.
     *
     * @return self
     */
    public static function challengeUsed(): self
    {
        return new self(PasskeyRegistrationStatus::CHALLENGE_USED);
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
     * The pending credential handed in names no live pending session of the
     * identity on the guard, or none the challenge was bound to.
     *
     * @return self
     */
    public static function pendingInvalid(): self
    {
        return new self(PasskeyRegistrationStatus::PENDING_INVALID);
    }

    /**
     * A cookie application's registration on a pending sign-in did not come
     * from a page of its own site.
     *
     * @return self
     */
    public static function crossSiteRequest(): self
    {
        return new self(PasskeyRegistrationStatus::CROSS_SITE_REQUEST);
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
