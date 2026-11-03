<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Proofs;

/**
 * What the adapter that verified a further factor reported about it: whether it
 * accepted the proof, and whether, with what the session already proved, it
 * amounts to multifactor authentication. For an external proof, it is what the
 * package's acceptance of the provider's evidence found: accepted, multifactor
 * when the evidence contract says the evidence meets multifactor
 * authentication, and an additional verification when it says the evidence
 * meets that or multifactor authentication, not when it was accepted only for
 * phishing resistance or a minimum assurance level.
 *
 * Only an accepted evaluation is stored, and multifactor authentication is
 * taken from here, never worked out from the authentication methods: `amr`
 * carries `mfa` only when an accepted evaluation reports it. Whether the proof
 * is an additional verification, which the authentication context's `mfa` reads
 * (see `Context\AuthenticationContext`), is the flag's to say only for an
 * external proof: an accepted further factor always is one and a recovery code
 * never is, whatever an adapter reports, and its proof is recorded so.
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

        /** Whether an external proof is an additional verification; a further factor always is one and a recovery code never is, whatever this says. */
        public bool $additionalVerification = true,
    ) {}
}
