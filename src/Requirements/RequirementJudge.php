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
use SineMacula\Laravel\Authentication\Tenancy\SessionEvidence;
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
     * records.
     *
     * @param  string  $application
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @param  ?\SineMacula\Laravel\Authentication\Proofs\RecordedProof  $firstFactor
     * @param  \Carbon\CarbonImmutable  $now
     * @param  ?\SineMacula\Laravel\Authentication\Tenancy\SessionEvidence  $evidence
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
        ?SessionEvidence $evidence,
        Requirement|TenantFactor $requirement,
    ): bool {
        [$requirement, $tenant] = $requirement instanceof TenantFactor ? [$requirement->requirement, $requirement->tenant] : [$requirement, null];

        if ($requirement->isEmpty()) {
            return true;
        }

        $firstFactor = self::firstFactor($session, $firstFactor, $evidence);

        if ($firstFactor === null) {
            return false;
        }

        $connectionId = $firstFactor->channel->kind === ChannelKind::EXTERNAL_PROVIDER ? $firstFactor->channel->reference : null;

        return ($connectionId !== null && self::meetsByEvidence(new EvidenceSubject($identity, $application, $connectionId, $now, $tenant), $session, $evidence, $requirement))
            || self::meetsByCheck($application, $identity, $session, $firstFactor, $now, $evidence, $requirement);
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
     * Whether the bound `RequirementCheck` finds the requirement met, asked
     * inside `WriteConnection::during()` for the identity, about the session's
     * proofs or the sign-in's.
     *
     * @param  string  $application
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @param  \SineMacula\Laravel\Authentication\Proofs\RecordedProof  $firstFactor
     * @param  \Carbon\CarbonImmutable  $now
     * @param  ?\SineMacula\Laravel\Authentication\Tenancy\SessionEvidence  $evidence
     * @param  \SineMacula\Laravel\Authentication\Requirements\Requirement  $requirement
     * @return bool
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private static function meetsByCheck(
        string $application,
        Identity $identity,
        ?Session $session,
        RecordedProof $firstFactor,
        CarbonImmutable $now,
        ?SessionEvidence $evidence,
        Requirement $requirement,
    ): bool {
        $subject = new RequirementSubject($identity, $application, $session, $firstFactor, $now, self::reader($session, $evidence));
        $check   = Container::getInstance()->make(RequirementCheck::class);

        return WriteConnection::during($identity, static fn (): bool => $check->evaluate($subject, $requirement)->isMet());
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
     * @param  ?\SineMacula\Laravel\Authentication\Tenancy\SessionEvidence  $evidence
     * @param  \SineMacula\Laravel\Authentication\Requirements\Requirement  $requirement
     * @return bool
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     */
    private static function meetsByEvidence(EvidenceSubject $subject, ?Session $session, ?SessionEvidence $evidence, Requirement $requirement): bool
    {
        $held   = $evidence !== null || $session === null ? array_filter([$evidence?->externalEvidence]) : SessionProofs::acceptedEvidence($session);
        $policy = Container::getInstance()->make(ExternalEvidencePolicy::class);

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

            return static fn (?CarbonImmutable $since, ?array $kinds, int $limit): array => array_slice(array_filter(
                $proofs,
                static fn (RecordedProof $proof): bool => ($since === null || $proof->authenticatedAt->greaterThanOrEqualTo($since->startOfSecond()))
                    && ($kinds === null || in_array($proof->kind, $kinds, true)),
            ), 0, $limit);
        }

        return static fn (?CarbonImmutable $since, ?array $kinds, int $limit): array => SessionProofs::query($session, $since, $kinds, $limit);
    }
}
