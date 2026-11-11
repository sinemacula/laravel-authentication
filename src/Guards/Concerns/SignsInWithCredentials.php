<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Guards\Concerns;

use Carbon\CarbonImmutable;
use Illuminate\Container\Container;
use Illuminate\Support\Timebox;
use SineMacula\Laravel\Authentication\Admission\Admitted;
use SineMacula\Laravel\Authentication\Admission\Refused;
use SineMacula\Laravel\Authentication\Admission\SignInAdmission;
use SineMacula\Laravel\Authentication\Admission\TenantAdmission;
use SineMacula\Laravel\Authentication\Contracts\AdditionalFactorPolicy;
use SineMacula\Laravel\Authentication\Contracts\AttemptLimiter;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\Session;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Factors\AdditionalFactorContext;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Proofs\Channel;
use SineMacula\Laravel\Authentication\Proofs\Enums\ChannelKind;
use SineMacula\Laravel\Authentication\Proofs\FirstFactor;
use SineMacula\Laravel\Authentication\Proofs\SignInProof;
use SineMacula\Laravel\Authentication\RateLimiting\AccountAttempts;
use SineMacula\Laravel\Authentication\RateLimiting\AttemptSubject;
use SineMacula\Laravel\Authentication\RateLimiting\Enums\AttemptFlow;
use SineMacula\Laravel\Authentication\Requirements\ProofSource;
use SineMacula\Laravel\Authentication\Requirements\Requirement;
use SineMacula\Laravel\Authentication\Requirements\RequirementJudge;
use SineMacula\Laravel\Authentication\Sessions\CredentialAttempt;
use SineMacula\Laravel\Authentication\Sessions\Methods\PasswordSignIn;
use SineMacula\Laravel\Authentication\Tenancy\Enums\TenantPolicyStanding;
use SineMacula\Laravel\Authentication\Tenancy\SessionEvidence;
use SineMacula\Laravel\Authentication\Tenancy\TenantPolicyCheck;

/**
 * The sign-in policy checks behind `attempt()`.
 *
 * Policies are resolved from the container each time, so a binding made later,
 * such as an MFA package's, is the one used.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @phpstan-require-extends \SineMacula\Laravel\Authentication\Guards\AbstractGuard
 */
trait SignsInWithCredentials
{
    /**
     * Run an `attempt()` sign-in up to the bind, giving the attempt's slots
     * back only when it succeeds.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\Methods\PasswordSignIn  $password
     * @param  array<string, mixed>  $credentials
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Authentication\Admission\Admitted|\SineMacula\Laravel\Authentication\Admission\Refused
     *
     * @throws \Throwable
     */
    private function signInWithCredentials(
        PasswordSignIn $password,
        #[\SensitiveParameter] array $credentials,
        ?Principal $principal,
        ?Session $session,
        ClientContext $client,
    ): Admitted|Refused {
        $guard  = $this->context->name();
        $policy = CredentialAttempt::checkMethod(Container::getInstance(), $guard, PasswordSignIn::NAME);

        if ($policy instanceof Refused) {
            return $policy;
        }

        $type    = $password->identifierType($guard);
        $limiter = self::signInCollaborator(AttemptLimiter::class);
        $subject = new AttemptSubject($guard, AttemptFlow::SIGN_IN, $password->identifier($guard, $credentials), $type, $client->ip);
        $attempt = CredentialAttempt::begin($limiter, $policy, $subject);

        if ($attempt instanceof Refused) {
            return $attempt;
        }

        // `#[\SensitiveParameter]` does not cover what a closure captures,
        // which a dump of the trace shows.
        $held = new \SensitiveParameterValue($credentials);

        $outcome = $this->context->timebox()->run(
            function (Timebox $timebox) use ($password, $held, $principal, $session, $client, $type, $attempt): Admitted|Refused {

                $credentials = $held->getValue();
                $user        = $this->verifyAttemptedCredentials($password, $credentials, $attempt->accounts);

                if ($user === null) {
                    return $attempt->accountRefusal() ?? new Refused(FailureReason::INVALID_CREDENTIALS);
                }

                $this->fireValidatedEvent($user);

                $outcome = $this->admitVerifiedIdentity(new SignInAdmission($attempt->policy), $user, $principal, $session, $type);

                if ($outcome instanceof Admitted) {

                    $password->rehash($this->context->provider(), $user, $credentials);

                    $outcome = $this->refuseIfAFactorIsRequired($outcome, $client);
                }

                if ($outcome instanceof Admitted) {
                    $timebox->returnEarly();
                }

                return $outcome;
            },
        );

        if ($outcome instanceof Admitted) {
            $attempt->release();
        }

        return $outcome;
    }

    /**
     * Return the identity the credentials of an `attempt()` find and whose
     * password they match, or `null`.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\Methods\PasswordSignIn  $password
     * @param  array<string, mixed>  $credentials
     * @param  \SineMacula\Laravel\Authentication\RateLimiting\AccountAttempts  $accounts
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Identity
     *
     * @throws \InvalidArgumentException
     */
    private function verifyAttemptedCredentials(PasswordSignIn $password, #[\SensitiveParameter] array $credentials, AccountAttempts $accounts): ?Identity
    {
        $lookup = $password->lookupCredentials($this->context->name(), $credentials);

        if ($lookup === null) {
            return null;
        }

        $user = $password->retrieve($this->context->provider(), $lookup);

        $this->lastRetrievedUser = $user;

        return $user instanceof Identity && $password->verifyPassword($accounts, $this->context->provider(), $user, $lookup) ? $user : null;
    }

    /**
     * Admit an identity whose password was accepted, with its principal,
     * policies and pinned session.
     *
     * @param  \SineMacula\Laravel\Authentication\Admission\SignInAdmission  $admission
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @param  string  $identifierType
     * @return \SineMacula\Laravel\Authentication\Admission\Admitted|\SineMacula\Laravel\Authentication\Admission\Refused
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    private function admitVerifiedIdentity(SignInAdmission $admission, Identity $identity, ?Principal $principal, ?Session $session, string $identifierType): Admitted|Refused
    {
        $admitted = $admission->admit(
            $this->context->name(),
            $identity,
            fn (): ?Principal => $principal === null ? $this->resolvePrincipal($identity) : $this->resolvePinnedPrincipal($identity, $principal),
            $principal === null ? FailureReason::PRINCIPAL_UNRESOLVED : FailureReason::PRINCIPAL_MISMATCH,
            $identifierType,
        );

        if ($admitted instanceof Refused) {
            return $admitted;
        }

        if ($session === null) {
            return $admitted;
        }

        $resolvedSession = $this->resolvePinnedSession($identity, $admitted->principal, $session);

        return $resolvedSession === null
            ? Refused::after(FailureReason::SESSION_MISMATCH, $admitted)
            : self::inPinnedSession($admitted, $resolvedSession);
    }

    /**
     * The admitted sign-in on the pinned session, in the tenant the session
     * acts in, or why not.
     *
     * @param  \SineMacula\Laravel\Authentication\Admission\Admitted  $admitted
     * @param  \SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @return \SineMacula\Laravel\Authentication\Admission\Admitted|\SineMacula\Laravel\Authentication\Admission\Refused
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \LogicException
     */
    private static function inPinnedSession(Admitted $admitted, Session $session): Admitted|Refused
    {
        $tenant = TenantAdmission::recorded($admitted->principal, WriteConnection::during($session, static fn (): ?string => $session->getTenantId()), true);

        return $tenant instanceof FailureReason
            ? Refused::after($tenant, $admitted->on($session))
            : new Admitted($admitted->identity, $admitted->principal, $tenant, $session);
    }

    /**
     * Refuse the admitted sign-in when the additional-factor or tenant
     * authentication policy asks for more than the password.
     *
     * @param  \SineMacula\Laravel\Authentication\Admission\Admitted  $admitted
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Authentication\Admission\Admitted|\SineMacula\Laravel\Authentication\Admission\Refused
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     */
    private function refuseIfAFactorIsRequired(Admitted $admitted, ClientContext $client): Admitted|Refused
    {
        $now      = CarbonImmutable::now()->startOfSecond();
        $password = SignInProof::verified(PasswordSignIn::NAME, new FirstFactor($admitted->identity, new Channel(ChannelKind::PASSWORD), methods: [PasswordSignIn::AMR]), $now);
        $evidence = SessionEvidence::of($password);
        $factors  = self::signInCollaborator(AdditionalFactorPolicy::class);
        $context  = new AdditionalFactorContext($this->context->name(), $admitted->identity, $evidence->firstFactor, $client, null, null, null);
        $required = WriteConnection::during($admitted->identity, static fn (): Requirement => $factors->requirementFor($context));

        if (!RequirementJudge::isMet($this->context->name(), $admitted->identity, null, null, $now, new ProofSource($evidence), $required)) {
            return Refused::after(FailureReason::ADDITIONAL_FACTOR_REQUIRED, $admitted);
        }

        $policy = TenantPolicyCheck::check($this->context->name(), $admitted->identity, $admitted->principal, $admitted->tenant, null, $now, new ProofSource($evidence));

        return match ($policy->standing) {
            TenantPolicyStanding::SSO_REQUIRED    => Refused::after(FailureReason::SSO_REQUIRED, $admitted),
            TenantPolicyStanding::FACTOR_REQUIRED => Refused::after(FailureReason::ADDITIONAL_FACTOR_REQUIRED, $admitted),
            TenantPolicyStanding::MET             => $admitted,
        };
    }

    /**
     * Resolve a sign-in collaborator from the container.
     *
     * @template TCollaborator of object
     *
     * @param  class-string<TCollaborator>  $abstract
     * @return TCollaborator
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private static function signInCollaborator(string $abstract): object
    {
        return Container::getInstance()->make($abstract);
    }
}
