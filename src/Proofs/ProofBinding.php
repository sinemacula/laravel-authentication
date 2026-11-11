<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Proofs;

use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Proofs\Enums\Purpose;

/**
 * The identity, application, session and purpose an adapter's proof was made
 * for.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class ProofBinding
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  string  $application
     * @param  mixed  $sessionId
     * @param  \SineMacula\Laravel\Authentication\Proofs\Enums\Purpose  $purpose
     *
     * @throws \InvalidArgumentException
     */
    public function __construct(

        /** The identity the proof was made by. */
        public Identity $identity,

        /** The application (the guard's name) the proof was made on. */
        public string $application,

        /** The key of the session, active or pending, the proof was made for. */
        public mixed $sessionId,

        /** What the proof was made for. */
        public Purpose $purpose,
    ) {
        if ($application === '') {
            throw new \InvalidArgumentException('A proof\'s binding must name the application it was made on.');
        }
    }
}
