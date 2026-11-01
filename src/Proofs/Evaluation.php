<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Proofs;

/**
 * What the adapter that verified a further factor reported about it: whether it
 * accepted the proof, and whether, with what the session already proved, it
 * amounts to multifactor authentication.
 *
 * Only an accepted evaluation is stored, and multifactor authentication is
 * taken from here, never worked out from the authentication methods: `amr`
 * carries `mfa` only when an accepted evaluation reports it.
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
     */
    public function __construct(

        /** Whether the adapter accepted the proof. */
        public bool $accepted,

        /** Whether the adapter reported multifactor authentication. */
        public bool $multifactor,
    ) {}
}
