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
 * binding (the identity, the application, the session and the purpose), the
 * factor package's factor, and the channel the code goes through, with its
 * destination; for the confirmation of a factor being enrolled, the enrolment
 * grant as well.
 *
 * A binding whose purpose is `sign_in` or `step_up` is an `mfa` challenge; one
 * whose purpose is `enrollment` is an `enrollment` challenge, bound to the
 * pending factor and its grant. Neither is ever accepted as the other, and a
 * `reauthenticate` binding is refused: a reauthentication proves the first
 * factor, never a further one. The destination, the owner and the purpose form
 * the challenge's delivery key, on which its delivery cap and cooldown are
 * counted, never on the factor, so an enrolment restarted with a new pending
 * factor and grant is still held to them. The session, the factor and the
 * proof's purpose or grant are the challenge's transaction: a code sent for one
 * is never accepted for another.
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
