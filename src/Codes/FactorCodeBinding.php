<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Codes;

use SineMacula\Laravel\Authentication\Codes\Enums\CodePurpose;
use SineMacula\Laravel\Authentication\Factors\FactorReference;
use SineMacula\Laravel\Authentication\Proofs\Channel;
use SineMacula\Laravel\Authentication\Proofs\Enums\ChannelKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\Purpose;
use SineMacula\Laravel\Authentication\Proofs\ProofBinding;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;

/**
 * What a further factor's one-time code challenge is bound to: the proof's
 * binding, the factor, the channel and, for an enrolment, the grant.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class FactorCodeBinding
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Proofs\ProofBinding  $binding
     * @param  string  $factor
     * @param  \SineMacula\Laravel\Authentication\Proofs\Channel  $channel
     * @param  ?string  $grant
     *
     * @throws \InvalidArgumentException
     */
    public function __construct(

        /** The proof's binding: the identity, the application (this guard), the session's key, and `sign_in`, `step_up` or `enrollment`. */
        public ProofBinding $binding,

        /** The factor package's reference to the factor (the pending factor, for an enrolment), 1 to 255 characters. */
        public string $factor,

        /** The channel the code goes through, `sms` or `email`, with the destination in its normal form. */
        public Channel $channel,

        /** The enrolment grant, 1 to 255 characters: required for an `enrollment` binding and refused for any other. */
        #[\SensitiveParameter] public ?string $grant = null,
    ) {
        if ($binding->purpose === Purpose::REAUTHENTICATE) {
            throw new \InvalidArgumentException('A factor code is for a sign-in, a step-up or an enrolment: a reauthentication proves the first factor.');
        }

        self::assertReference('factor reference', $factor);

        if ($channel->reference === null || !in_array($channel->kind, [ChannelKind::SMS, ChannelKind::EMAIL], true)) {
            throw new \InvalidArgumentException('A factor code goes by text message or email: its channel must be `sms` or `email` and name the destination.');
        }

        if (in_array(IdentifierCoercion::stringify($binding->sessionId), [null, ''], true)) {
            throw new \InvalidArgumentException('A factor code is bound to a session: its binding must name the session\'s key.');
        }

        if ($binding->purpose !== Purpose::ENROLLMENT) {
            if ($grant !== null) {
                throw new \InvalidArgumentException('Only an enrolment\'s factor code is bound to an enrolment grant.');
            }

            return;
        }

        self::assertReference('enrolment grant', $grant);
    }

    /**
     * What the challenge is for: `enrollment` for an enrolment's binding,
     * otherwise `mfa`.
     *
     * @return \SineMacula\Laravel\Authentication\Codes\Enums\CodePurpose
     */
    public function purpose(): CodePurpose
    {
        return $this->binding->purpose === Purpose::ENROLLMENT ? CodePurpose::ENROLLMENT : CodePurpose::MFA;
    }

    /**
     * Refuse a factor reference or grant that is missing, empty or longer than
     * the longest accepted.
     *
     * @param  string  $name
     * @param  ?string  $value
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    private static function assertReference(string $name, #[\SensitiveParameter] ?string $value): void
    {
        if (!FactorReference::isValid($value)) {
            throw new \InvalidArgumentException(sprintf('A factor code\'s %s must be from 1 to %d characters.', $name, FactorReference::MAX_LENGTH));
        }
    }
}
