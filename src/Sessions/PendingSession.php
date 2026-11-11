<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions;

use Carbon\CarbonImmutable;
use Carbon\CarbonInterface;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\Session;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Proofs\RecordedProof;
use SineMacula\Laravel\Authentication\Proofs\SessionProofs;
use SineMacula\Laravel\Authentication\Requirements\Requirement;
use SineMacula\Laravel\Authentication\Requirements\RequirementSubject;
use SineMacula\Laravel\Authentication\Sessions\Enums\PendingAction;

/**
 * A session waiting on a further factor, a choice of principal, or both, in
 * that order.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class PendingSession
{
    /**
     * Constructor.
     *
     * @param  mixed  $id
     * @param  string  $guard
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Tenant  $tenant
     * @param  non-empty-list<\SineMacula\Laravel\Authentication\Sessions\Enums\PendingRequirement>  $requires
     * @param  string  $method
     * @param  \Carbon\CarbonImmutable  $expiresAt
     * @param  \SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @param  \SineMacula\Laravel\Authentication\Requirements\Requirement  $requirement
     * @param  \SineMacula\Laravel\Authentication\Proofs\RecordedProof  $firstFactor
     * @param  list<\SineMacula\Laravel\Authentication\Contracts\Principal>  $principals
     */
    public function __construct(

        /** The session's key: its public id, the same once it activates, granting nothing. */
        public mixed $id,

        /** Name of the guard (the application) the session belongs to. */
        public string $guard,

        /** Identity the session's first factor proved. */
        public Identity $identity,

        /** Principal the session is to act as, or `null` while the choice is outstanding. */
        public ?Principal $principal,

        /** Tenant the session is to be active in, or `null` for none or while the choice is outstanding. */
        public ?Tenant $tenant,

        /** What the session waits on, in the order it must be met. */
        public array $requires,

        /** Name of the sign-in method that verified the first factor. */
        public string $method,

        /** When the pending credential, and the session with it, ends unless it activates. */
        public CarbonImmutable $expiresAt,

        /** The session record. */
        public Session $session,

        /** What its authentication still falls short of, empty while only the choice is outstanding. */
        public Requirement $requirement,

        /** The proof of the first factor the session signed in with. */
        public RecordedProof $firstFactor,

        /** The principals the identity may choose from, listed only while the choice is the first requirement. */
        public array $principals = [],
    ) {}

    /**
     * Whether the pending credential may be used for the action now.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\Enums\PendingAction  $action
     * @return bool
     */
    public function allows(PendingAction $action): bool
    {
        return in_array($action, $this->actions(), true);
    }

    /**
     * The actions the pending credential may be used for now.
     *
     * @return list<\SineMacula\Laravel\Authentication\Sessions\Enums\PendingAction>
     */
    public function actions(): array
    {
        return $this->requires[0]->actions();
    }

    /**
     * The session's counting proofs, newest first, filtered by `$since` and
     * `$kinds` and capped at `$limit`.
     *
     * @param  ?\Carbon\CarbonInterface  $since
     * @param  ?list<\SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind>  $kinds
     * @param  int  $limit
     * @return list<\SineMacula\Laravel\Authentication\Proofs\RecordedProof>
     *
     * @throws \InvalidArgumentException
     */
    public function proofs(?CarbonInterface $since = null, ?array $kinds = null, int $limit = 50): array
    {
        if ($limit < 1 || $limit > RequirementSubject::MAX_LIMIT) {
            throw new \InvalidArgumentException(sprintf('A pending session returns between 1 and %d proofs at a time.', RequirementSubject::MAX_LIMIT));
        }

        return SessionProofs::query($this->session, $since, $kinds, $limit);
    }
}
