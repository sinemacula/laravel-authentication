<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Container\Container;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Admission\ActivationPolicy;
use SineMacula\Laravel\Authentication\Admission\PinnedPrincipal;
use SineMacula\Laravel\Authentication\Admission\PrincipalAdmission;
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
use SineMacula\Laravel\Authentication\Proofs\SessionProofs;
use SineMacula\Laravel\Authentication\Runtime\GuardContext;
use SineMacula\Laravel\Authentication\Sessions\Enums\PendingRequirement;
use SineMacula\Laravel\Authentication\Tenancy\Enums\TenantPolicyStanding;
use SineMacula\Laravel\Authentication\Tenancy\SessionEvidence;
use SineMacula\Laravel\Authentication\Tenancy\TenantPolicyCheck;
use SineMacula\Laravel\Authentication\Tenancy\TenantPolicyVerdict;
use SineMacula\Laravel\Authentication\Tenancy\TenantSelection;

/**
 * The checks a sign-in passes on its way to a session, in the order sign-in
 * takes them, and the gate a pending session passes again each time it is acted
 * on: the same checks against current state, so nothing that changed while the
 * session waited is skipped.
 *
 * In order: the identity (not a machine identity, active, and admitted by the
 * application policy with the identifier type the sign-in used); the principals
 * the application admits (its `principals()`, read on the write connection, or
 * the resolver's default for an identity that is its own principal or lists
 * none), each active, in an active tenant and allowed to use
 * the application, with none left a refusal after the credential is verified;
 * the principal selected (the one named, when it is among them, else the only
 * one, else none and a choice is outstanding); the identity-level factor
 * policy, asked before any principal is chosen and met once the session holds
 * an accepted further factor or recovery code; and, with a principal, the
 * tenant it is to be active in and that tenant's authentication policy.
 *
 * It decides; it writes nothing. Every read and every contract is asked on the
 * write connection.
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
     * Why the identity may not sign in to the guard, or `null` when it may: a
     * machine identity, an inactive one, or one the application policy refuses
     * with the identifier type the sign-in used.
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
     * the last one left out was refused, if any. With an identifier type, the
     * application policy must admit the identity with it first, or none is
     * listed (not even which there are) and its reason is returned.
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

        $principals = [];

        foreach ($this->candidates($identity) as $candidate) {

            if (!$candidate instanceof Principal) {
                continue;
            }

            $reason = PrincipalAdmission::refusal($this->context->name(), $candidate);

            if ($reason === null) {
                $principals[] = $candidate;
            }

            $refusal = $reason ?? $refusal;
        }

        return [$principals, $refusal];
    }

    /**
     * The principal a sign-in acts as and the principals it may choose from:
     * the one named, when the identity owns it (resolved through the hinted
     * path as that very principal) and the application admits it, with none to
     * choose from; otherwise the only principal the application admits, or none
     * and the principals to choose from. A principal named that is not the
     * identity's is refused as `principal_mismatch`, one the application
     * refuses with its reason, and an identity left with none with the reason
     * the last was refused, or `principal_unresolved`.
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
     * The principal named, when the identity owns it (resolved through the
     * hinted path as that very principal) and the application admits it; else
     * `principal_mismatch`, or the reason the application refuses it.
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
     * Whether a pending session's recorded principal (one the identity owns)
     * may still hold it, and the active tenant it records: the principal
     * admitted by the application, and the tenant still one it may act in and
     * active; else why not.
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
     * Whether the identity still owes the further factor its factor policy asks
     * of it: the policy, asked about the identity and the sign-in (never a
     * principal, since it is asked before one is chosen), requires one, and the
     * session, when there is one yet, holds no accepted further factor or
     * recovery code.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  string  $method
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @param  ?string  $clientName
     * @param  ?string  $platform
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Session  $proven
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @return bool
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     */
    public function owesFactor(Identity $identity, string $method, ClientContext $client, ?string $clientName, ?string $platform, ?Session $proven, ?Session $session): bool
    {
        $required = $this->container->make(AdditionalFactorPolicy::class)->requiresAdditionalFactor(
            new AdditionalFactorContext($this->context->name(), $identity, $method, $client, $clientName, $platform, $proven),
        );

        return $required && ($session === null || !SessionProofs::hasAcceptedAdditional($session));
    }

    /**
     * How the session, or the sign-in's evidence, stands against the
     * authentication policy of the tenant the principal is to act in; with no
     * principal selected yet there is none to ask, and nothing falls short.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Tenant  $tenant
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @param  \Carbon\CarbonImmutable  $now
     * @param  ?\SineMacula\Laravel\Authentication\Tenancy\SessionEvidence  $evidence
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
        CarbonImmutable $now,
        ?SessionEvidence $evidence = null,
    ): TenantPolicyVerdict {
        return $principal === null
            ? new TenantPolicyVerdict(TenantPolicyStanding::MET, null)
            : TenantPolicyCheck::check($this->context->name(), $identity, $principal, $tenant, $session, $now, $evidence);
    }

    /**
     * What a session still waits on, in order: the further factor when it is
     * owed, then the choice when no principal is selected.
     *
     * @param  bool  $owesFactor
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @return list<\SineMacula\Laravel\Authentication\Sessions\Enums\PendingRequirement>
     */
    public static function requirements(bool $owesFactor, ?Principal $principal): array
    {
        return [
            ...$owesFactor ? [PendingRequirement::MFA] : [],
            ...$principal === null ? [PendingRequirement::PRINCIPAL] : [],
        ];
    }

    /**
     * The application policy's `admitIdentifier()` answer for the identity,
     * asked on the write connection.
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
     * The principals the identity may act as, before any check: its
     * `principals()` read on the write connection, or, for an identity that is
     * its own principal or has no `principals()`, the resolver's default.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @return array<array-key, mixed>
     *
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    private function candidates(Identity $identity): array
    {
        return $identity instanceof HasPrincipals && !$identity instanceof Principal
            ? WriteConnection::during($identity, static fn (): array => WriteConnection::query($identity->principals())->get()->all())
            : [$this->context->resolver()->resolve($identity)];
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
