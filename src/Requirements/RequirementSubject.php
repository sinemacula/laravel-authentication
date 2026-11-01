<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Requirements;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Session;
use SineMacula\Laravel\Authentication\Proofs\RecordedProof;

/**
 * What a requirement check judges: the identity, the application, the session
 * when there is one, the first factor it signed in with (always at hand, so a
 * check can see the first factor's channel however long the history is), the
 * time it is judged at, and a bounded query over its counting proofs (not
 * voided, and a further factor or recovery code only when accepted), never the
 * whole history in memory.
 *
 * The package builds every subject: at sign-in its proofs are the ones the
 * sign-in is about to record, held in memory; otherwise each query is one
 * indexed read on the write connection.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class RequirementSubject
{
    /** @var int The most proofs one query returns. */
    public const int MAX_LIMIT = 200;

    /**
     * Constructor.
     *
     * @internal the reader is the package's; an adapter only reads a subject
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  string  $application
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @param  \SineMacula\Laravel\Authentication\Proofs\RecordedProof  $firstFactor
     * @param  \Carbon\CarbonImmutable  $now
     * @param  \Closure(?\Carbon\CarbonImmutable, ?list<\SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind>, int): list<\SineMacula\Laravel\Authentication\Proofs\RecordedProof>  $reader
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    public function __construct(

        /** The identity whose authentication is judged. */
        public Identity $identity,

        /** The application (the guard) the session is on. */
        public string $application,

        /** The session, or `null` before one is written. */
        public ?Session $session,

        /** The first factor the session signed in with. */
        public RecordedProof $firstFactor,

        /** The time the requirement is judged at. */
        public CarbonImmutable $now,

        /** Reads the counting proofs, newest first. */
        private \Closure $reader,
    ) {}

    /**
     * The counting proofs, newest first by time and then by id, only those made
     * at or after `$since` when it is given and of the given kinds when they
     * are, at most `$limit` of them (1 to `MAX_LIMIT`).
     *
     * @param  ?\Carbon\CarbonImmutable  $since
     * @param  ?list<\SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind>  $kinds
     * @param  int  $limit
     * @return list<\SineMacula\Laravel\Authentication\Proofs\RecordedProof>
     *
     * @throws \InvalidArgumentException
     */
    public function proofs(?CarbonImmutable $since = null, ?array $kinds = null, int $limit = 50): array
    {
        if ($limit < 1 || $limit > self::MAX_LIMIT) {
            throw new \InvalidArgumentException(sprintf('A requirement subject returns between 1 and %d proofs at a time.', self::MAX_LIMIT));
        }

        return ($this->reader)($since, $kinds, $limit);
    }
}
