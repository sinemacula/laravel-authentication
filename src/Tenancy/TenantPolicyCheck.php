<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Tenancy;

use Carbon\CarbonImmutable;
use Illuminate\Container\Container;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\RequirementCheck;
use SineMacula\Laravel\Authentication\Contracts\Session;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Contracts\TenantAuthenticationPolicy;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use SineMacula\Laravel\Authentication\Proofs\RecordedProof;
use SineMacula\Laravel\Authentication\Proofs\SessionProofs;
use SineMacula\Laravel\Authentication\Requirements\RequirementSubject;
use SineMacula\Laravel\Authentication\Tenancy\Enums\TenantPolicyStanding;

/**
 * Judges a session, or a sign-in about to write one, against the authentication
 * policy of the tenant it is to act in.
 *
 * The policy is asked inside `WriteConnection::during()` for the tenant. A
 * session falls short as `SSO_REQUIRED` when the answer names connections and
 * it was not established through one of them, else as `FACTOR_REQUIRED` when
 * the answer requires a further factor that `RequirementCheck`, asked inside
 * `WriteConnection::during()` for the identity, does not find met; otherwise it
 * meets the policy. The evidence is the sign-in's own, in memory, or the
 * session's provenance and proofs, read on the write connection only when the
 * answer needs them, so the default policy costs no query. With neither a
 * session nor evidence, no connection and no further factor is met. A
 * destination of no tenant has no policy: it is met, with no version, and
 * nothing is asked.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class TenantPolicyCheck
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Ask the tenant's policy and judge the session, or the sign-in's evidence,
     * against it.
     *
     * @param  string  $guard
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Tenant  $tenant
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @param  \Carbon\CarbonImmutable  $now
     * @param  ?\SineMacula\Laravel\Authentication\Tenancy\SessionEvidence  $evidence
     * @return \SineMacula\Laravel\Authentication\Tenancy\TenantPolicyVerdict
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     */
    public static function check(
        string $guard,
        Identity $identity,
        Principal $principal,
        ?Tenant $tenant,
        ?Session $session,
        CarbonImmutable $now,
        ?SessionEvidence $evidence = null,
    ): TenantPolicyVerdict {
        if ($tenant === null) {
            return new TenantPolicyVerdict(TenantPolicyStanding::MET, null);
        }

        return self::judge(self::requirementFor($guard, $identity, $principal, $tenant, $session), $guard, $identity, $session, $now, $evidence);
    }

    /**
     * What the tenant's policy requires of the session, asked inside
     * `WriteConnection::during()` for the tenant.
     *
     * @param  string  $guard
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  \SineMacula\Laravel\Authentication\Contracts\Tenant  $tenant
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @return \SineMacula\Laravel\Authentication\Tenancy\TenantRequirement
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public static function requirementFor(string $guard, Identity $identity, Principal $principal, Tenant $tenant, ?Session $session): TenantRequirement
    {
        $policy  = Container::getInstance()->make(TenantAuthenticationPolicy::class);
        $context = new TenantPolicyContext($guard, $identity, $principal, $tenant, $session);

        return WriteConnection::during($tenant, static fn (): TenantRequirement => $policy->requirementFor($context));
    }

    /**
     * Judge the session, or the sign-in's evidence, against the answer.
     *
     * @param  \SineMacula\Laravel\Authentication\Tenancy\TenantRequirement  $requirement
     * @param  string  $guard
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @param  \Carbon\CarbonImmutable  $now
     * @param  ?\SineMacula\Laravel\Authentication\Tenancy\SessionEvidence  $evidence
     * @return \SineMacula\Laravel\Authentication\Tenancy\TenantPolicyVerdict
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     */
    public static function judge(
        TenantRequirement $requirement,
        string $guard,
        Identity $identity,
        ?Session $session,
        CarbonImmutable $now,
        ?SessionEvidence $evidence,
    ): TenantPolicyVerdict {
        $standing = match (true) {
            !self::meetsConnections($requirement, $session, $evidence)                     => TenantPolicyStanding::SSO_REQUIRED,
            !self::meetsFactor($requirement, $guard, $identity, $session, $now, $evidence) => TenantPolicyStanding::FACTOR_REQUIRED,
            default                                                                        => TenantPolicyStanding::MET,
        };

        return new TenantPolicyVerdict($standing, $requirement->version);
    }

    /**
     * Whether the session was established through a connection the answer
     * names, when it names any: the sign-in's own, or the one the session's
     * provenance records.
     *
     * @param  \SineMacula\Laravel\Authentication\Tenancy\TenantRequirement  $requirement
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @param  ?\SineMacula\Laravel\Authentication\Tenancy\SessionEvidence  $evidence
     * @return bool
     */
    private static function meetsConnections(TenantRequirement $requirement, ?Session $session, ?SessionEvidence $evidence): bool
    {
        if ($requirement->connections === null) {
            return true;
        }

        if ($evidence !== null) {
            return $requirement->admitsConnection($evidence->connectionId);
        }

        return $requirement->admitsConnection($session === null ? null : SessionProofs::connectionId($session));
    }

    /**
     * Whether the further factor the answer requires, if any, is met, as the
     * bound `RequirementCheck` judges it, asked inside
     * `WriteConnection::during()` for the identity.
     *
     * @param  \SineMacula\Laravel\Authentication\Tenancy\TenantRequirement  $requirement
     * @param  string  $guard
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @param  \Carbon\CarbonImmutable  $now
     * @param  ?\SineMacula\Laravel\Authentication\Tenancy\SessionEvidence  $evidence
     * @return bool
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     */
    private static function meetsFactor(
        TenantRequirement $requirement,
        string $guard,
        Identity $identity,
        ?Session $session,
        CarbonImmutable $now,
        ?SessionEvidence $evidence,
    ): bool {
        if ($requirement->factor->isEmpty()) {
            return true;
        }

        $firstFactor = $evidence?->firstFactor;

        if ($firstFactor === null && $session !== null) {
            $firstFactor = SessionProofs::firstFactor($session);
        }

        if ($firstFactor === null) {
            return false;
        }

        $subject = new RequirementSubject($identity, $guard, $session, $firstFactor, $now, self::reader($session, $evidence));
        $check   = Container::getInstance()->make(RequirementCheck::class);

        return WriteConnection::during($identity, static fn (): bool => $check->evaluate($subject, $requirement->factor)->isMet());
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
