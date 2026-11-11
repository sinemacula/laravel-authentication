<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Factors;

use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Session;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Proofs\RecordedProof;

/**
 * Everything an additional-factor policy decides on, once the first factor is
 * verified and before any principal is chosen.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class AdditionalFactorContext
{
    /**
     * Constructor.
     *
     * @param  string  $application
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Proofs\RecordedProof  $firstFactor
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @param  ?string  $clientName
     * @param  ?string  $platform
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Session  $provenSession
     */
    public function __construct(

        /** The application (the guard) the sign-in is for. */
        public string $application,

        /** Identity the first factor verified. */
        public Identity $identity,

        /** The proof of the first factor the identity signed in with. */
        public RecordedProof $firstFactor,

        /** Client the sign-in came from. */
        public ClientContext $client,

        /** Name the client gave itself, if any. */
        public ?string $clientName,

        /** Platform the client reported, if any. */
        public ?string $platform,

        /** Existing session of this application and identity the client proved it holds, if any. */
        public ?Session $provenSession,
    ) {}
}
