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
 * The session's counting proofs (`proofs()`) and the first factor it signed in
 * with (`firstFactor()`) are read each time a contributor asks, for the session
 * this subject was given and never the request's, by the rule
 * `Auth::sessions()->proofs()` reads by: only while it is one of the
 * application's live, active sessions of a person and its key still holds that
 * very session, and read current under its row's lock inside a transaction on
 * the session model's connection. Each answer is as of the call: a proof
 * recorded or voided after the package's own keys were worked out shows in it.
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
     * The session's counting proofs (not voided, and a further factor or
     * recovery code only when accepted), newest first by time and then by id,
     * only those made at or after `$since` when it is given (any Carbon time,
     * mutable or not, the same instant in any time zone, and never changed) and
     * of the given kinds when they are, at most `$limit` of them (1 to
     * `RequirementSubject::MAX_LIMIT`, an `InvalidArgumentException` otherwise,
     * checked first, whatever the session): the session's row and then one
     * bounded read, on the write connection, each call. `[]` without a session,
     * with one that is not an Eloquent session (no query), and with one that is
     * no longer the application's live, active session of a person or whose key
     * now holds another session, without saying which.
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
     * The first factor the session signed in with, its oldest counting
     * first-factor proof, read as `proofs()` reads, each call; `null` when
     * `proofs()` would answer `[]`, and when that proof no longer counts.
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
