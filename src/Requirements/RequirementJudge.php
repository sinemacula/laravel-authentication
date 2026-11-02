<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Requirements;

use Carbon\CarbonImmutable;
use Illuminate\Container\Container;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\RequirementCheck;
use SineMacula\Laravel\Authentication\Contracts\Session;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use SineMacula\Laravel\Authentication\Proofs\RecordedProof;
use SineMacula\Laravel\Authentication\Proofs\SessionProofs;
use SineMacula\Laravel\Authentication\Tenancy\SessionEvidence;

/**
 * Judges whether a session, or a sign-in about to write one, meets a
 * requirement on its authentication, as the bound `RequirementCheck` sees it:
 * the one judge of the identity-level requirement and of a tenant's.
 *
 * A requirement that asks for nothing is met, and nothing is read or asked. A
 * session with no first factor (neither the sign-in's evidence nor a stored
 * one) meets no other. Otherwise the check is asked inside
 * `WriteConnection::during()` for the identity, with a subject whose proofs are
 * the sign-in's own, in memory, or the session's, each read a bounded query on
 * the write connection; with neither evidence nor a session there are none.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class RequirementJudge
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Whether the session, or the sign-in's evidence, meets the requirement.
     * The first factor is the one given, else the evidence's, else the one the
     * session records.
     *
     * @param  string  $application
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @param  ?\SineMacula\Laravel\Authentication\Proofs\RecordedProof  $firstFactor
     * @param  \Carbon\CarbonImmutable  $now
     * @param  ?\SineMacula\Laravel\Authentication\Tenancy\SessionEvidence  $evidence
     * @param  \SineMacula\Laravel\Authentication\Requirements\Requirement  $requirement
     * @return bool
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     */
    public static function isMet(
        string $application,
        Identity $identity,
        ?Session $session,
        ?RecordedProof $firstFactor,
        CarbonImmutable $now,
        ?SessionEvidence $evidence,
        Requirement $requirement,
    ): bool {
        if ($requirement->isEmpty()) {
            return true;
        }

        $firstFactor = self::firstFactor($session, $firstFactor, $evidence);

        if ($firstFactor === null) {
            return false;
        }

        $subject = new RequirementSubject($identity, $application, $session, $firstFactor, $now, self::reader($session, $evidence));
        $check   = Container::getInstance()->make(RequirementCheck::class);

        return WriteConnection::during($identity, static fn (): bool => $check->evaluate($subject, $requirement)->isMet());
    }

    /**
     * The first factor a judgement of the session, or of the sign-in's
     * evidence, is made on: the one given, else the evidence's, else the one
     * the session records, read on the write connection; `null` when there is
     * none.
     *
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @param  ?\SineMacula\Laravel\Authentication\Proofs\RecordedProof  $firstFactor
     * @param  ?\SineMacula\Laravel\Authentication\Tenancy\SessionEvidence  $evidence
     * @return ?\SineMacula\Laravel\Authentication\Proofs\RecordedProof
     *
     * @throws \InvalidArgumentException
     */
    public static function firstFactor(?Session $session, ?RecordedProof $firstFactor, ?SessionEvidence $evidence): ?RecordedProof
    {
        $firstFactor ??= $evidence?->firstFactor;

        return $firstFactor === null && $session !== null ? SessionProofs::firstFactor($session) : $firstFactor;
    }

    /**
     * How the subject reads its counting proofs: from the sign-in's evidence in
     * memory, or the session's on the write connection. In memory, as in the
     * stored proofs' query, which binds the time to the second, a proof made in
     * the second `$since` falls in counts.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @param  ?\SineMacula\Laravel\Authentication\Tenancy\SessionEvidence  $evidence
     * @return \Closure(?\Carbon\CarbonImmutable, ?list<\SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind>, int): list<\SineMacula\Laravel\Authentication\Proofs\RecordedProof>
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    private static function reader(?Session $session, ?SessionEvidence $evidence): \Closure
    {
        if ($evidence !== null || $session === null) {
            $proofs = $evidence === null ? [] : $evidence->proofs;

            return static fn (?CarbonImmutable $since, ?array $kinds, int $limit): array => array_slice(array_values(array_filter(
                $proofs,
                static fn (RecordedProof $proof): bool => ($since === null || $proof->authenticatedAt->greaterThanOrEqualTo($since->startOfSecond()))
                    && ($kinds === null || in_array($proof->kind, $kinds, true)),
            )), 0, $limit);
        }

        return static fn (?CarbonImmutable $since, ?array $kinds, int $limit): array => SessionProofs::query($session, $since, $kinds, $limit);
    }
}
