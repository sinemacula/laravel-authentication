<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Requirements;

use Carbon\CarbonImmutable;
use Illuminate\Container\Container;
use SineMacula\Laravel\Authentication\Contracts\ExternalEvidencePolicy;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\RequirementCheck;
use SineMacula\Laravel\Authentication\Contracts\Session;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use SineMacula\Laravel\Authentication\External\EvidenceAcceptance;
use SineMacula\Laravel\Authentication\External\EvidenceSubject;
use SineMacula\Laravel\Authentication\Proofs\Enums\ChannelKind;
use SineMacula\Laravel\Authentication\Proofs\RecordedProof;
use SineMacula\Laravel\Authentication\Proofs\SessionProofs;
use SineMacula\Laravel\Authentication\Tenancy\TenantFactor;

/**
 * Judges whether a session, or a sign-in about to write one, meets a
 * requirement on its authentication: the one judge of the identity-level
 * requirement and of a tenant's.
 *
 * A requirement that asks for nothing is met, and nothing is read or asked. A
 * session with no first factor (neither the sign-in's evidence nor a stored
 * one) meets no other. A session an external provider established is asked of
 * first: the bound `ExternalEvidencePolicy` is asked whether any of its
 * accepted evidence (the sign-in's own, in memory, or what its proofs record,
 * `SessionProofs::acceptedEvidence()`) meets the whole requirement, told the
 * connection and the tenant whose requirement it is (none for the identity
 * level's). Otherwise, or when the evidence falls short, the bound
 * `RequirementCheck` judges it, as the factor package sees it: evidence never
 * meets part of a requirement and leaves the rest to the factor package's
 * proofs. Either is asked inside `WriteConnection::during()` for the identity,
 * the check with a subject whose proofs are the sign-in's own, in memory, or
 * the session's, read on the write connection.
 *
 * A judgement made while the transaction holds the session's row locked reads
 * current (`ProofSource::$current`): every read of the session's proofs it
 * makes, its first factor, its accepted evidence and each query the check makes
 * of the subject, is then a current read (`SessionProofs`), so on MySQL and
 * MariaDB at REPEATABLE READ it judges the proofs committed by the time the
 * lock was taken, not the snapshot of the transaction's first read. With the
 * sign-in's evidence in memory, or no session, nothing is read either way.
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
     * Whether the session, or the sign-in's evidence, meets the requirement: a
     * tenant's, given with the tenant, or the identity-level one. The first
     * factor is the one given, else the evidence's, else the one the session
     * records. Read current only for a session whose row this transaction holds
     * locked.
     *
     * @param  string  $application
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @param  ?\SineMacula\Laravel\Authentication\Proofs\RecordedProof  $firstFactor
     * @param  \Carbon\CarbonImmutable  $now
     * @param  \SineMacula\Laravel\Authentication\Requirements\ProofSource  $source
     * @param  \SineMacula\Laravel\Authentication\Requirements\Requirement|\SineMacula\Laravel\Authentication\Tenancy\TenantFactor  $requirement
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
        ProofSource $source,
        Requirement|TenantFactor $requirement,
    ): bool {
        [$requirement, $tenant] = $requirement instanceof TenantFactor ? [$requirement->requirement, $requirement->tenant] : [$requirement, null];

        if ($requirement->isEmpty()) {
            return true;
        }

        $firstFactor = self::firstFactor($session, $firstFactor, $source);

        if ($firstFactor === null) {
            return false;
        }

        $connectionId = $firstFactor->channel->kind === ChannelKind::EXTERNAL_PROVIDER ? $firstFactor->channel->reference : null;

        return ($connectionId !== null && self::meetsByEvidence(new EvidenceSubject($identity, $application, $connectionId, $now, $tenant), $session, $source, $requirement))
            || self::meetsByCheck(new RequirementSubject($identity, $application, $session, $firstFactor, $now, self::reader($session, $source)), $requirement);
    }

    /**
     * The first factor a judgement of the session, or of the sign-in's
     * evidence, is made on: the one given, else the evidence's, else the one
     * the session records, read on the write connection (current when the
     * source asks); `null` when there is none.
     *
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @param  ?\SineMacula\Laravel\Authentication\Proofs\RecordedProof  $firstFactor
     * @param  \SineMacula\Laravel\Authentication\Requirements\ProofSource  $source
     * @return ?\SineMacula\Laravel\Authentication\Proofs\RecordedProof
     *
     * @throws \InvalidArgumentException
     */
    public static function firstFactor(?Session $session, ?RecordedProof $firstFactor, ProofSource $source): ?RecordedProof
    {
        $firstFactor ??= $source->evidence?->firstFactor;

        return $firstFactor === null && $session !== null ? SessionProofs::firstFactor($session, $source->current) : $firstFactor;
    }

    /**
     * Whether the bound `RequirementCheck` finds the requirement met for the
     * subject, asked inside `WriteConnection::during()` for its identity.
     *
     * @param  \SineMacula\Laravel\Authentication\Requirements\RequirementSubject  $subject
     * @param  \SineMacula\Laravel\Authentication\Requirements\Requirement  $requirement
     * @return bool
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private static function meetsByCheck(RequirementSubject $subject, Requirement $requirement): bool
    {
        $check = Container::getInstance()->make(RequirementCheck::class);

        return WriteConnection::during($subject->identity, static fn (): bool => $check->evaluate($subject, $requirement)->isMet());
    }

    /**
     * Whether any external evidence the session, or the sign-in, holds accepted
     * meets the whole requirement for the subject (the connection the session
     * was established through, and the tenant whose requirement it is), as the
     * bound `ExternalEvidencePolicy` says, asked of the newest first and no
     * further once one does; `false` when it holds none.
     *
     * @param  \SineMacula\Laravel\Authentication\External\EvidenceSubject  $subject
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @param  \SineMacula\Laravel\Authentication\Requirements\ProofSource  $source
     * @param  \SineMacula\Laravel\Authentication\Requirements\Requirement  $requirement
     * @return bool
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     */
    private static function meetsByEvidence(EvidenceSubject $subject, ?Session $session, ProofSource $source, Requirement $requirement): bool
    {
        $evidence = $source->evidence;
        $held     = $evidence !== null || $session === null ? array_filter([$evidence?->externalEvidence]) : SessionProofs::acceptedEvidence($session, $source->current);
        $policy   = Container::getInstance()->make(ExternalEvidencePolicy::class);

        foreach ($held as $external) {
            $judged = EvidenceAcceptance::asOf($external, $subject);

            if (WriteConnection::during($subject->identity, static fn (): bool => $policy->meets($judged, $requirement, $subject))) {
                return true;
            }
        }

        return false;
    }

    /**
     * How the subject reads its counting proofs: from the sign-in's evidence in
     * memory, or the session's on the write connection, each query current when
     * the source asks. In memory, as in the stored proofs' query, which binds
     * the time to the second, a proof made in the second `$since` falls in
     * counts.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @param  \SineMacula\Laravel\Authentication\Requirements\ProofSource  $source
     * @return \Closure(?\Carbon\CarbonImmutable, ?list<\SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind>, int): list<\SineMacula\Laravel\Authentication\Proofs\RecordedProof>
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    private static function reader(?Session $session, ProofSource $source): \Closure
    {
        $evidence = $source->evidence;

        if ($evidence !== null || $session === null) {
            $proofs = $evidence === null ? [] : $evidence->proofs;

            return static fn (?CarbonImmutable $since, ?array $kinds, int $limit): array => array_slice(array_filter(
                $proofs,
                static fn (RecordedProof $proof): bool => ($since === null || $proof->authenticatedAt->greaterThanOrEqualTo($since->startOfSecond()))
                    && ($kinds === null || in_array($proof->kind, $kinds, true)),
            ), 0, $limit);
        }

        $current = $source->current;

        return static fn (?CarbonImmutable $since, ?array $kinds, int $limit): array => SessionProofs::query($session, $since, $kinds === null ? null : array_values($kinds), $limit, $current);
    }
}
