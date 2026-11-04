<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Requirements;

use SineMacula\Laravel\Authentication\Tenancy\SessionEvidence;

/**
 * Where a requirement judgement reads the authentication it judges: the
 * sign-in's evidence, held in memory before its session is written, or, with
 * none, the session's stored proofs and provenance, read on the write
 * connection. Those are read current (`SessionProofs`) when asked, which only a
 * judgement made while the transaction holds the session's row locked asks.
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
