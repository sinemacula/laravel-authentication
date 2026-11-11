<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Tenancy;

use Carbon\CarbonImmutable;
use Illuminate\Container\Container;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\Session;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Contracts\TenantAuthenticationPolicy;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use SineMacula\Laravel\Authentication\Proofs\SessionProofs;
use SineMacula\Laravel\Authentication\Requirements\ProofSource;
use SineMacula\Laravel\Authentication\Requirements\RequirementJudge;
use SineMacula\Laravel\Authentication\Tenancy\Enums\TenantPolicyStanding;

/**
 * Judges a session, or a sign-in about to write one, against the authentication
 * policy of the tenant it is to act in.
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
     * @param  \SineMacula\Laravel\Authentication\Requirements\ProofSource  $source
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
        ProofSource $source = new ProofSource,
    ): TenantPolicyVerdict {
        if ($tenant === null) {
            return new TenantPolicyVerdict(TenantPolicyStanding::MET, null);
        }

        $context = self::contextFor($guard, $identity, $principal, $tenant, $session, $source);

        try {
            return self::judge(self::requirementFor($context), $context, $now, $source);
        } finally {
            $context->expire();
        }
    }

    /**
     * The context the policy is asked about, with its connection found lazily.
     *
     * @param  string  $guard
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  \SineMacula\Laravel\Authentication\Contracts\Tenant  $tenant
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @param  \SineMacula\Laravel\Authentication\Requirements\ProofSource  $source
     * @return \SineMacula\Laravel\Authentication\Tenancy\TenantPolicyContext
     */
    public static function contextFor(string $guard, Identity $identity, Principal $principal, Tenant $tenant, ?Session $session, ProofSource $source): TenantPolicyContext
    {
        $connectionId = static fn (): ?string => match (true) {
            $source->evidence !== null => $source->evidence->connectionId,
            $session === null          => null,
            default                    => SessionProofs::connectionId($session, $source->current),
        };

        return new TenantPolicyContext($guard, $identity, $principal, $tenant, $session, $connectionId);
    }

    /**
     * What the tenant's policy requires of the session.
     *
     * @param  \SineMacula\Laravel\Authentication\Tenancy\TenantPolicyContext  $context
     * @return \SineMacula\Laravel\Authentication\Tenancy\TenantRequirement
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public static function requirementFor(TenantPolicyContext $context): TenantRequirement
    {
        $policy = Container::getInstance()->make(TenantAuthenticationPolicy::class);

        return WriteConnection::during($context->tenant, static fn (): TenantRequirement => $policy->requirementFor($context));
    }

    /**
     * Judge the session, or the sign-in's evidence, against the tenant's
     * answer.
     *
     * @param  \SineMacula\Laravel\Authentication\Tenancy\TenantRequirement  $requirement
     * @param  \SineMacula\Laravel\Authentication\Tenancy\TenantPolicyContext  $context
     * @param  \Carbon\CarbonImmutable  $now
     * @param  \SineMacula\Laravel\Authentication\Requirements\ProofSource  $source
     * @return \SineMacula\Laravel\Authentication\Tenancy\TenantPolicyVerdict
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     */
    public static function judge(TenantRequirement $requirement, TenantPolicyContext $context, CarbonImmutable $now, ProofSource $source): TenantPolicyVerdict
    {
        if ($requirement->connections !== null && !$requirement->admitsConnection($context->connectionId())) {
            return new TenantPolicyVerdict(TenantPolicyStanding::SSO_REQUIRED, $requirement->version);
        }

        $firstFactor = $requirement->factor->isEmpty() ? null : RequirementJudge::firstFactor($context->session, null, $source);
        $factor      = new TenantFactor($context->tenant, $requirement->factor);

        return RequirementJudge::isMet($context->application, $context->identity, $context->session, $firstFactor, $now, $source, $factor)
            ? new TenantPolicyVerdict(TenantPolicyStanding::MET, $requirement->version, firstFactor: $firstFactor)
            : new TenantPolicyVerdict(TenantPolicyStanding::FACTOR_REQUIRED, $requirement->version, $requirement->factor, $firstFactor);
    }
}
