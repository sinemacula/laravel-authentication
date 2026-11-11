<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Requirements;

use SineMacula\Laravel\Authentication\Tenancy\SessionEvidence;

/**
 * Where a requirement judgement reads the authentication it judges: the
 * sign-in's evidence in memory, or the session's stored proofs.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ProofSource
{
    /**
     * Constructor.
     *
     * @param  ?\SineMacula\Laravel\Authentication\Tenancy\SessionEvidence  $evidence
     * @param  bool  $current
     */
    public function __construct(

        /** The sign-in's evidence, or `null` to read the session's stored proofs. */
        public ?SessionEvidence $evidence = null,

        /** Whether the session's stored proofs are read current. */
        public bool $current = false,
    ) {}
}
