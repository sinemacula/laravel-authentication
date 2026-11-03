<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Context;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\Session;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Proofs\Provenance;
use SineMacula\Laravel\Authentication\Proofs\SessionProofs;

/**
 * What a contributor to the authentication context is given: the package's own
 * keys, already worked out, and the identity, principal, active tenant and
 * session the guard bound, as the live instances the guard holds, so it reads
 * what it needs from them without loading them again.
 *
 * The session's external provenance (the connection and tenant it was
 * established through, the provider's time and deadline, the policy version,
 * the link, the evidence accepted with the provider's own `amr`, and the
 * provider context the adapter gave, whose keys are its own) is read only when
 * a contributor first asks for it, on the write connection, and once, in one
 * query.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class ContributionSubject
{
    /** @var bool Whether the provenance has been read. */
    private bool $provenanceRead = false;

    /** @var ?\SineMacula\Laravel\Authentication\Proofs\Provenance The provenance read, if any. */
    private ?Provenance $provenance = null;

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Context\AuthenticationContext  $context
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Tenant  $tenant
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Session  $session
     */
    public function __construct(

        /** The package's own keys, with nothing contributed yet. */
        public readonly AuthenticationContext $context,

        /** The identity the guard bound. */
        public readonly Identity $identity,

        /** The principal the guard bound. */
        public readonly Principal $principal,

        /** The active tenant, if the request acts in one. */
        public readonly ?Tenant $tenant,

        /** The session the guard bound, if any. */
        public readonly ?Session $session,
    ) {}

    /**
     * How the session was established through an external provider, read on the
     * write connection the first time it is asked for; `null` for a session no
     * external provider established, and without an Eloquent session.
     *
     * @return ?\SineMacula\Laravel\Authentication\Proofs\Provenance
     *
     * @throws \InvalidArgumentException
     */
    public function provenance(): ?Provenance
    {
        if (!$this->provenanceRead) {
            $this->provenance     = self::isRecorded($this->session) ? SessionProofs::provenance($this->session) : null;
            $this->provenanceRead = true;
        }

        return $this->provenance;
    }

    /**
     * Whether the session is one the package records provenance for.
     *
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @return bool
     *
     * @phpstan-assert-if-true \SineMacula\Laravel\Authentication\Contracts\Session $session
     */
    private static function isRecorded(?Session $session): bool
    {
        return $session instanceof EloquentSession && $session instanceof Model;
    }
}
