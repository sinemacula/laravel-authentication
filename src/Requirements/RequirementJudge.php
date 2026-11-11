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
 * Judges whether a session, or a sign-in about to write one, meets an
 * identity-level or tenant requirement on its authentication.
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
     * The first factor a judgement is made on: the one given, else the
     * evidence's, else the one the session records.
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
     * subject.
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
     * Whether any accepted external evidence the session or sign-in holds meets
     * the whole requirement, as the bound `ExternalEvidencePolicy` says.
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
     * memory, or the session's on the write connection.
     *
     * In memory `$since` is truncated to the second, as the stored query binds
     * it.
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

        return static fn (?CarbonImmutable $since, ?array $kinds, int $limit): array => SessionProofs::query(
            $session,
            $since,
            $kinds === null ? null : array_values($kinds),
            $limit,
            $current,
        );
    }
}
