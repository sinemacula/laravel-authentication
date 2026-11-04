<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Passkeys;

use SineMacula\Laravel\Authentication\Factors\FactorReference;

/**
 * A factor package's association of a passkey being registered as one of the
 * identity's factors: its own reference to the factor, which the registration
 * answers with, and the factor package's own completion of the registration, if
 * it has one, which the registration hands back to its caller uninterpreted
 * (the judgement of the current session again, `factorChanged()`, carrying a
 * pending credential for the client when it returned to pending).
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class PasskeyFactorAssociation
{
    /**
     * Constructor.
     *
     * @param  string  $factor
     * @param  ?object  $completion
     *
     * @throws \InvalidArgumentException
     */
    public function __construct(

        /** The factor package's reference to the factor, 1 to 255 characters. */
        public string $factor,

        /** The factor package's completion of the registration, opaque to the package, or `null` for none. */
        public ?object $completion = null,
    ) {
        if (!FactorReference::isValid($factor)) {
            throw new \InvalidArgumentException(sprintf('A passkey factor\'s reference must be 1 to %d characters.', FactorReference::MAX_LENGTH));
        }
    }
}
