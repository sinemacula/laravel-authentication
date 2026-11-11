<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Context;

use Carbon\CarbonInterface;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\Session;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Proofs\Provenance;
use SineMacula\Laravel\Authentication\Proofs\RecordedProof;
use SineMacula\Laravel\Authentication\Proofs\SessionProofs;
use SineMacula\Laravel\Authentication\Requirements\RequirementSubject;
use SineMacula\Laravel\Authentication\Sessions\ActiveSessionProofs;

/**
 * What a contributor to the authentication context is given.
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
     * How the session was established through an external provider, read once
     * when first asked for; `null` when no external provider established it.
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
     * The session's counting proofs, newest first, read on the write connection
     * each call; `[]` without a live, active Eloquent session.
     *
     * @param  ?\Carbon\CarbonInterface  $since
     * @param  ?list<\SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind>  $kinds
     * @param  int  $limit
     * @return list<\SineMacula\Laravel\Authentication\Proofs\RecordedProof>
     *
     * @throws \InvalidArgumentException
     *
     * @phpstan-impure
     */
    public function proofs(?CarbonInterface $since = null, ?array $kinds = null, int $limit = 50): array
    {
        if ($limit < 1 || $limit > RequirementSubject::MAX_LIMIT) {
            throw new \InvalidArgumentException(sprintf('A contribution subject returns between 1 and %d proofs at a time.', RequirementSubject::MAX_LIMIT));
        }

        return $this->session === null ? [] : ActiveSessionProofs::query($this->context->application, $this->session, $since, $kinds, $limit);
    }

    /**
     * The first factor the session signed in with, read as `proofs()` reads;
     * `null` when `proofs()` would answer `[]`.
     *
     * @return ?\SineMacula\Laravel\Authentication\Proofs\RecordedProof
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidSessionModelConfigurationException
     *
     * @phpstan-impure
     */
    public function firstFactor(): ?RecordedProof
    {
        return $this->session === null ? null : ActiveSessionProofs::firstFactor($this->context->application, $this->session);
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
