<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Container\Container;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Admission\ActivationPolicy;
use SineMacula\Laravel\Authentication\Admission\Admitted;
use SineMacula\Laravel\Authentication\Admission\PinnedPrincipal;
use SineMacula\Laravel\Authentication\Admission\PrincipalAdmission;
use SineMacula\Laravel\Authentication\Admission\PrincipalListing;
use SineMacula\Laravel\Authentication\Admission\TenantAdmission;
use SineMacula\Laravel\Authentication\Contracts\AdditionalFactorPolicy;
use SineMacula\Laravel\Authentication\Contracts\ApplicationPolicy;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Contracts\HasPrincipals;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\MachineIdentity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\Session;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Factors\AdditionalFactorContext;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Proofs\RecordedProof;
use SineMacula\Laravel\Authentication\Proofs\SessionProofs;
use SineMacula\Laravel\Authentication\Requirements\ProofSource;
use SineMacula\Laravel\Authentication\Requirements\Requirement;
use SineMacula\Laravel\Authentication\Requirements\RequirementJudge;
use SineMacula\Laravel\Authentication\Runtime\GuardContext;
use SineMacula\Laravel\Authentication\Sessions\Enums\PendingRequirement;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use SineMacula\Laravel\Authentication\Tenancy\Enums\TenantPolicyStanding;
use SineMacula\Laravel\Authentication\Tenancy\SessionEvidence;
use SineMacula\Laravel\Authentication\Tenancy\TenantPolicyCheck;
use SineMacula\Laravel\Authentication\Tenancy\TenantPolicyVerdict;
use SineMacula\Laravel\Authentication\Tenancy\TenantSelection;

/**
 * The checks a sign-in passes on its way to a session, which a pending session
 * passes again each time it is acted on.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class PendingEvaluation
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Runtime\GuardContext  $context
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** The context of the guard whose sign-ins are evaluated. */
        private GuardContext $context,

        /** Container the application and factor policies are resolved from. */
        private Container $container,
    ) {}

    /**
     * Why the identity may not sign in to the guard, or `null` when it may.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  ?string  $identifierType
     * @return ?\SineMacula\Laravel\Authentication\Events\Enums\FailureReason
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function identityRefusal(Identity $identity, ?string $identifierType): ?FailureReason
    {
        return match (true) {
            $identity instanceof MachineIdentity   => FailureReason::MACHINE_IDENTITY,
            !ActivationPolicy::isActive($identity) => FailureReason::IDENTITY_INACTIVE,
            default                                => $this->identifierRefusal($identity, $identifierType),
        };
    }

    /**
     * Whether the application policy still allows the sign-in method.
     *
     * @param  string  $method
     * @return bool
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function allowsMethod(string $method): bool
    {
        return $this->policy()->allowsMethod($this->context->name(), $method);
    }

    /**
     * The principals the identity may use the application as, and the reason
     * the last one left out was refused, if any.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  ?string  $identifierType
     * @return array{0: list<\SineMacula\Laravel\Authentication\Contracts\Principal>, 1: ?\SineMacula\Laravel\Authentication\Events\Enums\FailureReason}
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    public function principals(Identity $identity, ?string $identifierType = null): array
    {
        $refusal = $identifierType === null ? null : $this->identifierRefusal($identity, $identifierType);

        if ($refusal !== null) {
            return [[], $refusal];
        }

        $listing    = $this->candidates($identity);
        $candidates = array_values(array_filter($listing->candidates, static fn (mixed $candidate): bool => $candidate instanceof Principal));
        $principals = [];

        foreach ($listing->refusals($this->context->name(), $candidates) as $index => $reason) {

            if ($reason === null) {
                $principals[] = $candidates[$index];
            }

            $refusal = $reason ?? $refusal;
        }

        return [$principals, $refusal];
    }

    /**
     * The one principal with the identifier among those `principals()` lists
     * for the identity, or `null`.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  mixed  $id
     * @param  ?string  $identifierType
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Principal
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    public function principal(Identity $identity, mixed $id, ?string $identifierType = null): ?Principal
    {
        if ($identifierType !== null && $this->identifierRefusal($identity, $identifierType) !== null) {
            return null;
        }

        $listing   = $this->candidates($identity);
        $principal = null;

        foreach ($listing->candidates as $candidate) {

            if (!$candidate instanceof Principal || !IdentifierCoercion::matches($candidate->getPrincipalIdentifier(), $id)) {
                continue;
            }

            if ($principal !== null) {
                return null;
            }

            $principal = $candidate;
        }

        return $principal !== null && $listing->refusals($this->context->name(), [$principal]) === [null] ? $principal : null;
    }

    /**
     * The principal a sign-in acts as and the principals it may choose from, or
     * why there is none.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Principal  $named
     * @return array{0: ?\SineMacula\Laravel\Authentication\Contracts\Principal, 1: list<\SineMacula\Laravel\Authentication\Contracts\Principal>}|\SineMacula\Laravel\Authentication\Events\Enums\FailureReason
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    public function selection(Identity $identity, ?Principal $named): array|FailureReason
    {
        if ($named !== null) {

            $principal = $this->named($identity, $named);

            return $principal instanceof Principal ? [$principal, []] : $principal;
        }

        [$principals, $refusal] = $this->principals($identity);

        return match (count($principals)) {
            0       => $refusal ?? FailureReason::PRINCIPAL_UNRESOLVED,
            1       => [$principals[0], []],
            default => [null, $principals],
        };
    }

    /**
     * The principal named, when the identity owns it and the application admits
     * it, or why not.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $named
     * @return \SineMacula\Laravel\Authentication\Contracts\Principal|\SineMacula\Laravel\Authentication\Events\Enums\FailureReason
     *
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    public function named(Identity $identity, Principal $named): FailureReason|Principal
    {
        $principal = PinnedPrincipal::resolve($this->context->resolver(), $identity, $named);

        if ($principal === null) {
            return FailureReason::PRINCIPAL_MISMATCH;
        }

        return PrincipalAdmission::refusal($this->context->name(), $principal) ?? $principal;
    }

    /**
     * The tenant the principal is to be active in for the selection (the
     * principal's own unless one is named), or why it may not be.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?\SineMacula\Laravel\Authentication\Tenancy\TenantSelection  $selection
     * @return \SineMacula\Laravel\Authentication\Contracts\Tenant|\SineMacula\Laravel\Authentication\Events\Enums\FailureReason|null
     *
     * @throws \LogicException
     */
    public function destination(Principal $principal, ?TenantSelection $selection): FailureReason|Tenant|null
    {
        return TenantAdmission::select($principal, $selection ?? TenantSelection::principalDefault());
    }

    /**
     * The active tenant a pending session records, while its recorded principal
     * and that tenant still stand, or why not.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @return \SineMacula\Laravel\Authentication\Contracts\Tenant|\SineMacula\Laravel\Authentication\Events\Enums\FailureReason|null
     *
     * @throws \LogicException
     */
    public function recorded(EloquentSession&Model $session, Principal $principal): FailureReason|Tenant|null
    {
        return PrincipalAdmission::refusal($this->context->name(), $principal)
            ?? TenantAdmission::recorded($principal, WriteConnection::during($session, static fn (): ?string => $session->getTenantId()), true);
    }

    /**
     * What the identity-level factor policy asks of the session beyond its
     * first factor.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Proofs\RecordedProof  $firstFactor
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @param  ?string  $clientName
     * @param  ?string  $platform
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Session  $proven
     * @return \SineMacula\Laravel\Authentication\Requirements\Requirement
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function factorRequirement(Identity $identity, RecordedProof $firstFactor, ClientContext $client, ?string $clientName, ?string $platform, ?Session $proven): Requirement
    {
        $policy  = $this->container->make(AdditionalFactorPolicy::class);
        $context = new AdditionalFactorContext($this->context->name(), $identity, $firstFactor, $client, $clientName, $platform, $proven);

        return WriteConnection::during($identity, static fn (): Requirement => $policy->requirementFor($context));
    }

    /**
     * What the identity still owes of what its factor policy asks; pass
     * `$current` only for a session whose row this transaction holds locked.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Proofs\RecordedProof  $firstFactor
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @param  ?string  $clientName
     * @param  ?string  $platform
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Session  $proven
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @param  \Carbon\CarbonImmutable  $now
     * @param  ?\SineMacula\Laravel\Authentication\Tenancy\SessionEvidence  $evidence
     * @param  bool  $current
     * @return \SineMacula\Laravel\Authentication\Requirements\Requirement
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     */
    public function owedFactor(
        Identity $identity,
        RecordedProof $firstFactor,
        ClientContext $client,
        ?string $clientName,
        ?string $platform,
        ?Session $proven,
        ?Session $session,
        CarbonImmutable $now,
        ?SessionEvidence $evidence = null,
        bool $current = false,
    ): Requirement {
        $requirement = $this->factorRequirement($identity, $firstFactor, $client, $clientName, $platform, $proven);
        $source      = new ProofSource($evidence, $current);

        return RequirementJudge::isMet($this->context->name(), $identity, $session, $firstFactor, $now, $source, $requirement) ? new Requirement : $requirement;
    }

    /**
     * What the identity still owes on the stored session, asked as its sign-in
     * was.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Proofs\RecordedProof  $firstFactor
     * @param  (\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession)|null  $proven
     * @param  \Carbon\CarbonImmutable  $now
     * @param  bool  $current
     * @return \SineMacula\Laravel\Authentication\Requirements\Requirement
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     */
    public function owedFactorOn(
        EloquentSession&Model $session,
        Identity $identity,
        RecordedProof $firstFactor,
        (EloquentSession&Model)|null $proven,
        CarbonImmutable $now,
        bool $current = false,
    ): Requirement {
        $origin   = new ClientContext(self::described($session, $session->getCreatedIpName()), self::described($session, $session->getCreatedUserAgentName()));
        $client   = self::described($session, $session->getClientNameName());
        $platform = self::described($session, $session->getPlatformName());

        return $this->owedFactor($identity, $firstFactor, $origin, $client, $platform, $proven, $session, $now, current: $current);
    }

    /**
     * The first factor the session signed in with, as it records it.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @param  bool  $current
     * @return \SineMacula\Laravel\Authentication\Proofs\RecordedProof
     *
     * @throws \LogicException
     */
    public static function firstFactorOf(Session $session, bool $current = false): RecordedProof
    {
        return SessionProofs::firstFactor($session, $current) ?? throw new \LogicException('A session the package wrote always records the proof of its first factor.');
    }

    /**
     * How the session, or the sign-in's evidence, stands against the
     * authentication policy of the tenant the principal is to act in.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Tenant  $tenant
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @param  ?\SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @param  \Carbon\CarbonImmutable  $now
     * @param  ?\SineMacula\Laravel\Authentication\Tenancy\SessionEvidence  $evidence
     * @param  bool  $current
     * @return \SineMacula\Laravel\Authentication\Tenancy\TenantPolicyVerdict
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     */
    public function tenantPolicy(
        Identity $identity,
        ?Principal $principal,
        ?Tenant $tenant,
        ?Session $session,
        ?ClientContext $client,
        CarbonImmutable $now,
        ?SessionEvidence $evidence = null,
        bool $current = false,
    ): TenantPolicyVerdict {
        return $principal === null
            ? new TenantPolicyVerdict(TenantPolicyStanding::MET, null)
            : TenantPolicyCheck::check($this->context->name(), new Admitted($identity, $principal, $tenant), $session, $client, $now, new ProofSource($evidence, $current));
    }

    /**
     * What a session still waits on, in order.
     *
     * @param  \SineMacula\Laravel\Authentication\Requirements\Requirement  $outstanding
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @return ($principal is null ? non-empty-array : array)&list<\SineMacula\Laravel\Authentication\Sessions\Enums\PendingRequirement>
     */
    public static function requirements(Requirement $outstanding, ?Principal $principal): array
    {
        return [
            ...$outstanding->isEmpty() ? [] : [PendingRequirement::MFA],
            ...$principal === null ? [PendingRequirement::PRINCIPAL] : [],
        ];
    }

    /**
     * A description the session recorded, as the model reads it, or `null`.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $session
     * @param  string  $column
     * @return ?string
     */
    private static function described(Model $session, string $column): ?string
    {
        $value = $session->getAttribute($column);

        return is_scalar($value) ? (string) $value : null;
    }

    /**
     * The application policy's `admitIdentifier()` answer for the identity.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  ?string  $identifierType
     * @return ?\SineMacula\Laravel\Authentication\Events\Enums\FailureReason
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function identifierRefusal(Identity $identity, ?string $identifierType): ?FailureReason
    {
        $policy = $this->policy();
        $guard  = $this->context->name();

        return WriteConnection::during($identity, static fn (): ?FailureReason => $policy->admitIdentifier($guard, $identity, $identifierType));
    }

    /**
     * The principals the identity may act as, before any check.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @return \SineMacula\Laravel\Authentication\Admission\PrincipalListing
     *
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    private function candidates(Identity $identity): PrincipalListing
    {
        return $identity instanceof HasPrincipals && !$identity instanceof Principal
            ? PrincipalListing::of($identity)
            : PrincipalListing::resolved($this->context->resolver()->resolve($identity));
    }

    /**
     * The application policy.
     *
     * @return \SineMacula\Laravel\Authentication\Contracts\ApplicationPolicy
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function policy(): ApplicationPolicy
    {
        return $this->container->make(ApplicationPolicy::class);
    }
}
