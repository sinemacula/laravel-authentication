<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Authentication\Admission\ActivationPolicy;
use SineMacula\Laravel\Authentication\Admission\Refused;
use SineMacula\Laravel\Authentication\Contracts\AudiencePolicy;
use SineMacula\Laravel\Authentication\Contracts\HasPrincipals;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Database\AfterCommit;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\EventContext;
use SineMacula\Laravel\Authentication\Events\PrincipalChoiceRequired;
use SineMacula\Laravel\Authentication\Models\PendingSignIn;
use SineMacula\Laravel\Authentication\Runtime\GuardContext;

/**
 * The principals an identity may sign in as on one guard, and the choice a
 * sign-in that names none waits on.
 *
 * A sign-in (`signIn()`, `start()`) that names no principal, for an identity
 * whose resolver has no default but which may act as one or more principals on
 * this guard, waits for the identity to choose: it hands out a single-use
 * choice token (`PrincipalChoice`), the attempt-limit slots it took stay
 * counted, and `PrincipalChoiceRequired` reports it once committed. Policy over
 * the audience policy and the guard's resolver, read on the write connection;
 * the only thing it writes is the choice.
 *
 * It runs on the guard's context: the event carries the client of the sign-in
 * it reports, and goes to the context's dispatcher as it is when it is
 * dispatched.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class PrincipalChoices
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Runtime\GuardContext  $context
     * @param  \SineMacula\Laravel\Authentication\Sessions\DeviceProof  $proof
     * @param  \SineMacula\Laravel\Authentication\Sessions\PendingSignIns  $pendings
     * @param  \SineMacula\Laravel\Authentication\Database\AfterCommit  $afterCommit
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** The context of the guard whose principals are chosen. */
        private GuardContext $context,

        /** Decides which device a client proved it holds. */
        private DeviceProof $proof,

        /** Issues the choices. */
        private PendingSignIns $pendings,

        /** Defers `PrincipalChoiceRequired` until the choice commits. */
        private AfterCommit $afterCommit,

        /** Container the audience policy is resolved from. */
        private Container $container,
    ) {}

    /**
     * Whether a refusal is of a verified identity that only lacks a principal:
     * no principal was named and the resolver has no default.
     *
     * @param  \SineMacula\Laravel\Authentication\Admission\Refused  $refused
     * @return bool
     */
    public static function awaitsChoice(Refused $refused): bool
    {
        return $refused->reason === FailureReason::PRINCIPAL_UNRESOLVED && $refused->identity !== null;
    }

    /**
     * Hold a verified sign-in that lacks a principal for the identity to choose
     * one, when it has eligible principals: store the choice with the device
     * the client proved it holds for the identity and the attempt-limit slots
     * it took, and report `PrincipalChoiceRequired` once committed. An identity
     * with no eligible principal fails as `principal_unresolved`.
     *
     * The audience policy admits each principal with the identifier type the
     * sign-in used, as it would a sign-in that named one, so a guard that
     * requires a verified identifier lists no principal (not even which there
     * are) to an identity whose identifier is unverified: when it refuses every
     * principal, the sign-in fails with its reason (`identifier_unverified`),
     * with no choice stored or reported.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  string  $method
     * @param  ?string  $identifierType
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignInContext  $context
     * @param  ?list<array<string, string>>  $attemptWindows
     * @return \SineMacula\Laravel\Authentication\Admission\Refused|\SineMacula\Laravel\Authentication\Sessions\SignInResult
     *
     * @throws \Throwable
     */
    public function offerChoice(Identity $identity, string $method, ?string $identifierType, SignInContext $context, ?array $attemptWindows): Refused|SignInResult
    {
        $guard = $this->context->name();

        [$principals, $refusal] = $this->admissible($identity, $identifierType);

        if ($principals === []) {
            return new Refused($refusal ?? FailureReason::PRINCIPAL_UNRESOLVED, $identity);
        }

        $now    = CarbonImmutable::now()->startOfSecond();
        $proven = $context->refreshToken === null ? null : $this->proof->provenDeviceOf($guard, $identity, null, $context->refreshToken);

        [$token, $expiresAt] = $this->pendings->issueChoice($guard, $identity, $proven, $method, $identifierType, $context, $now, $attemptWindows);

        $event = new PrincipalChoiceRequired(new EventContext($guard, $context->client, $identity, device: $proven, method: $method), $expiresAt);

        $this->afterCommit->run(new PendingSignIn, fn () => $this->context->dispatch($event));

        return SignInResult::principalRequired(new PrincipalChoice($token, $guard, $identity, $principals, $method, $expiresAt));
    }

    /**
     * The eligible principals the audience policy also admits with the
     * identifier type a sign-in used, and its reason for refusing the identity
     * with it, or for the last principal it refused with it, if any. A sign-in
     * that used no identifier is not held to it.
     *
     * Eligibility is that of `principals()`: active, within an active tenant or
     * none, and admitted with no identifier type; a principal that is not
     * eligible is left out without a reason.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  ?string  $identifierType
     * @return array{0: list<\SineMacula\Laravel\Authentication\Contracts\Principal>, 1: ?\SineMacula\Laravel\Authentication\Events\Enums\FailureReason}
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    public function admissible(Identity $identity, ?string $identifierType): array
    {
        $guard    = $this->context->name();
        $audience = $this->container->make(AudiencePolicy::class);
        $refusal  = $identifierType === null ? null : $audience->admitIdentifier($guard, $identity, $identifierType);

        if ($refusal !== null) {
            return [[], $refusal];
        }

        $principals = [];

        foreach ($this->candidates($identity) as $principal) {

            if (!$principal instanceof Principal) {
                continue;
            }

            $reason = self::refusalOf($audience, $guard, $identity, $principal, $identifierType);

            if ($reason === null) {
                $principals[] = $principal;
            }

            $refusal = $reason instanceof FailureReason ? $reason : $refusal;
        }

        return [$principals, $refusal];
    }

    /**
     * The live choice of this guard the token names, with its secret and its
     * identity reloaded through the guard's provider as the very owner it
     * recorded, or `null`.
     *
     * @param  string  $token
     * @param  \Carbon\CarbonImmutable  $now
     * @return ?array{0: \SineMacula\Laravel\Authentication\Models\PendingSignIn, 1: string, 2: \SineMacula\Laravel\Authentication\Contracts\Identity}
     *
     * @throws \InvalidArgumentException
     */
    public function liveChoice(#[\SensitiveParameter] string $token, CarbonImmutable $now): ?array
    {
        [$pending, $secret] = PendingSignIns::live($this->context->name(), $token, $now, PendingSignIn::PRINCIPAL_CHOICE) ?? [null, ''];

        $identity = $pending === null ? null : PendingSignIns::owner($pending, $this->context->provider());

        return $pending === null || $identity === null ? null : [$pending, $secret, $identity];
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
     * Whether the audience policy refuses the principal to the identifier type:
     * `false` when the principal is not eligible at all (inactive, within an
     * inactive tenant, or refused with no identifier type), the policy's reason
     * when it refuses the eligible principal to the type, and `null` when it
     * admits it. The principal is read through `WriteConnection::stored()`, so
     * its tenant, which the checks read, is loaded even when a collection
     * hydrated it with lazy loading prevented.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\AudiencePolicy  $audience
     * @param  string  $guard
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?string  $identifierType
     * @return false|\SineMacula\Laravel\Authentication\Events\Enums\FailureReason|null
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    private static function refusalOf(AudiencePolicy $audience, string $guard, Identity $identity, Principal $principal, ?string $identifierType): FailureReason|false|null
    {
        return WriteConnection::stored($principal, static function (Principal $stored) use ($audience, $guard, $identity, $identifierType): FailureReason|false|null {

            if (!ActivationPolicy::isPrincipalActive($stored) || $audience->admit($guard, $identity, $stored, null) !== null) {
                return false;
            }

            return $identifierType === null ? null : $audience->admit($guard, $identity, $stored, $identifierType);
        });
    }
}
