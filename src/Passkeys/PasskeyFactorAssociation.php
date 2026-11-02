<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Passkeys;

/**
 * A factor package's association of a passkey being registered as one of the
 * identity's factors: its own reference to the factor, which the registration
 * answers with.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class PasskeyFactorAssociation
{
    /** @var int Longest factor reference, in characters. */
    public const int FACTOR_MAX_LENGTH = 255;

    /**
     * Constructor.
     *
     * @param  string  $factor
     *
     * @throws \InvalidArgumentException
     */
    public function __construct(

        /** The factor package's reference to the factor, 1 to 255 characters. */
        public string $factor,
    ) {
        if ($factor === '' || mb_strlen($factor) > self::FACTOR_MAX_LENGTH) {
            throw new \InvalidArgumentException(sprintf('A passkey factor\'s reference must be 1 to %d characters.', self::FACTOR_MAX_LENGTH));
        }
    }
}
