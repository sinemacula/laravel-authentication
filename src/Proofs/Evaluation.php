<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Proofs;

/**
 * What the adapter that verified a further factor, or the acceptance of an
 * external provider's evidence, reported about a proof.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class Evaluation
{
    /**
     * Constructor.
     *
     * @param  bool  $accepted
     * @param  bool  $multifactor
     * @param  bool  $additionalVerification
     */
    public function __construct(

        /** Whether the adapter accepted the proof. */
        public bool $accepted,

        /** Whether the adapter reported multifactor authentication. */
        public bool $multifactor,

        /** Whether an external proof is an additional verification; ignored for other proofs. */
        public bool $additionalVerification = true,
    ) {}
}
