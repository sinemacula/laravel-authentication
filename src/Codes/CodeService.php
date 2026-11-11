<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Codes;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Authentication\Codes\Enums\VerificationOutcome;
use SineMacula\Laravel\Authentication\Contracts\ApplicationPolicy;
use SineMacula\Laravel\Authentication\Contracts\AttemptLimiter;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\MachineIdentity;
use SineMacula\Laravel\Authentication\Delivery\QueuedDelivery;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\Enums\AuthenticationFlow;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\EventContext;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Identifiers\IdentifierType;
use SineMacula\Laravel\Authentication\Models\OneTimeCode;
use SineMacula\Laravel\Authentication\RateLimiting\AccountAttempts;
use SineMacula\Laravel\Authentication\RateLimiting\AttemptSubject;
use SineMacula\Laravel\Authentication\RateLimiting\Enums\AttemptFlow;
use SineMacula\Laravel\Authentication\RateLimiting\LimitedOutcome;
use SineMacula\Laravel\Authentication\Runtime\GuardContext;
use SineMacula\Laravel\Authentication\Sessions\SignInMethodManager;
use SineMacula\Laravel\Authentication\Verification\Enums\IdentifierVerification;
use SineMacula\Laravel\Authentication\Verification\IdentifierVerifier;

/**
 * The one-time code service of a JWT guard (`Auth::codes($guard)`), for
 * sign-in, verification and further-factor codes.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class CodeService
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Runtime\GuardContext  $context
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** The context of the guard whose codes the service sends and checks. */
        private GuardContext $context,

        /** Container the methods, policies, limiter, engine and queue are resolved from. */
        private Container $container,
    ) {}

    /**
     * Send a sign-in code for the named code sign-in method to the identifier
     * the input names under the method's identifier type.
     *
     * @param  string  $method
     * @param  array<array-key, mixed>  $input
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Authentication\Codes\CodeRequest
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Random\RandomException
     */
    public function send(string $method, #[\SensitiveParameter] array $input, ClientContext $client): CodeRequest
    {
        $driver  = $this->codeMethod($method);
        $guard   = $this->context->name();
        $context = new EventContext($guard, $client, method: $method);
        $given   = $driver->identifier($guard, $input);

        if (!$this->collaborator(ApplicationPolicy::class)->allowsMethod($guard, $method)) {
            return $this->refuse(CodeRequest::methodNotAllowed(), FailureReason::METHOD_NOT_ALLOWED, $context, $given);
        }

        $binding = $driver->binding($guard, $input);

        return $binding === null
            ? $this->refuse(CodeRequest::identifierInvalid(), FailureReason::INVALID_CREDENTIALS, $context, $given)
            : $this->issue($binding, $context, $given, new AttemptSubject($guard, AttemptFlow::CODE_REQUEST, $binding->identifier, $binding->type, $context->client->ip));
    }

    /**
     * Send a code that verifies the identity's current identifier of the type
     * to that identifier.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  string  $type
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Authentication\Codes\CodeRequest
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Random\RandomException
     */
    public function sendVerification(Identity $identity, string $type, ClientContext $client): CodeRequest
    {
        $binding = $this->verificationBinding($identity, $type);
        $context = new EventContext($this->context->name(), $client, $identity);

        if ($binding === null) {
            return $this->refuse(CodeRequest::identifierInvalid(), FailureReason::INVALID_CREDENTIALS, $context, null);
        }

        $subject = new AttemptSubject($binding->guard, AttemptFlow::CODE_REQUEST, $binding->identifier, $binding->type, $context->client->ip);

        return $this->issue($binding, $context, null, $subject, $identity);
    }

    /**
     * Check a verification code sent for the challenge named, and record the
     * identifier verified when it is accepted.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  string  $type
     * @param  string  $challengeId
     * @param  string  $code
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Authentication\RateLimiting\LimitedOutcome<\SineMacula\Laravel\Authentication\Codes\Enums\VerificationOutcome>
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public function verify(Identity $identity, string $type, string $challengeId, #[\SensitiveParameter] string $code, ClientContext $client): LimitedOutcome
    {
        $binding   = $this->verificationBinding($identity, $type);
        $context   = new EventContext($this->context->name(), $client, $identity);
        $codes     = $this->collaborator(OneTimeCodes::class);
        $challenge = $codes->isWellFormedChallenge($challengeId) ? $challengeId : null;

        $limiter     = $this->collaborator(AttemptLimiter::class);
        $reservation = $limiter->acquire(
            new AttemptSubject($this->context->name(), AttemptFlow::IDENTIFIER_VERIFICATION, null, null, $context->client->ip, AccountAttempts::account($identity)),
        );

        if ($reservation->retryAfter !== null) {
            $this->report($context, AuthenticationFlow::IDENTIFIER_VERIFICATION, FailureReason::RATE_LIMITED, null, $reservation->retryAfter, $challenge);

            return new LimitedOutcome(VerificationOutcome::RATE_LIMITED, $reservation->retryAfter);
        }

        if ($binding === null || $challenge === null || !$codes->isWellFormed($code)) {
            return $this->refuseVerification($context, FailureReason::INVALID_CREDENTIALS, $challenge);
        }

        $failure = $codes->check($binding, $challengeId, $code, CarbonImmutable::now()->startOfSecond())->failure();

        if ($failure === null) {
            $limiter->release($reservation);
        }

        return $failure === null
            ? self::verifierOutcome($this->collaborator(IdentifierVerifier::class)->verify($this->context->name(), $identity, $type, $binding->identifier, $context->client))
            : $this->refuseVerification($context, $failure, $challenge);
    }

    /**
     * Send a further factor's code, or an enrolment's, to the destination of
     * the binding's channel.
     *
     * @param  \SineMacula\Laravel\Authentication\Codes\FactorCodeBinding  $binding
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Authentication\Codes\CodeRequest
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Random\RandomException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidSessionModelConfigurationException
     * @throws \Throwable
     */
    public function sendFactorCode(FactorCodeBinding $binding, ClientContext $client): CodeRequest
    {
        return (new FactorCodes($this->context, $this->container))->send($binding, $this->validated(), $client);
    }

    /**
     * Check a further factor's code, or an enrolment's, sent for the challenge
     * named, against the binding.
     *
     * @param  \SineMacula\Laravel\Authentication\Codes\FactorCodeBinding  $binding
     * @param  string  $challengeId
     * @param  string  $code
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Authentication\Codes\FactorCodeCheck
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \Throwable
     */
    public function verifyFactorCode(FactorCodeBinding $binding, string $challengeId, #[\SensitiveParameter] string $code, ClientContext $client): FactorCodeCheck
    {
        (new CodeKeys($this->collaborator(Repository::class)))->validate();

        return (new FactorCodes($this->context, $this->container))->verify($binding, $challengeId, $code, $client);
    }

    /**
     * Take a code request from the subject's limits, issue the code and queue
     * its delivery.
     *
     * @param  \SineMacula\Laravel\Authentication\Codes\CodeBinding  $binding
     * @param  \SineMacula\Laravel\Authentication\Events\EventContext  $context
     * @param  ?string  $given
     * @param  \SineMacula\Laravel\Authentication\RateLimiting\AttemptSubject  $subject
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @return \SineMacula\Laravel\Authentication\Codes\CodeRequest
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \Random\RandomException
     */
    private function issue(CodeBinding $binding, EventContext $context, ?string $given, AttemptSubject $subject, ?Identity $identity = null): CodeRequest
    {
        $delivery    = $this->validated();
        $reservation = $this->collaborator(AttemptLimiter::class)->acquire($subject);

        if ($reservation->retryAfter !== null) {
            return $this->refuse(CodeRequest::rateLimited($reservation->retryAfter), FailureReason::RATE_LIMITED, $context, $given, $reservation->retryAfter);
        }

        $issued = $this->collaborator(OneTimeCodes::class)->issue($binding, CarbonImmutable::now()->startOfSecond());

        if ($issued instanceof DeliveryRefusal) {
            return $this->refuse($issued->request(), $issued->reason(), $context, $given, $issued->retryAfter);
        }

        $delivery->dispatch(new SendOneTimeCode($binding, $issued, $identity), new OneTimeCode);

        return CodeRequest::sent($issued->expiresAt, $issued->resendAvailableAt, $issued->challengeId);
    }

    /**
     * Validate every setting a code request reads, failing closed, and answer
     * the delivery they configure.
     *
     * @return \SineMacula\Laravel\Authentication\Delivery\QueuedDelivery
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     */
    private function validated(): QueuedDelivery
    {
        $config   = $this->collaborator(Repository::class);
        $delivery = new QueuedDelivery($this->container);

        (new CodeSettings($config))->validate();
        (new CodeKeys($config))->validate();
        $delivery->settings();

        return $delivery;
    }

    /**
     * The verification binding of the identity's current identifier of the
     * type, or `null` when it has none the type's normaliser accepts.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  string  $type
     * @return ?\SineMacula\Laravel\Authentication\Codes\CodeBinding
     *
     * @throws \InvalidArgumentException
     */
    private function verificationBinding(Identity $identity, string $type): ?CodeBinding
    {
        if ($identity instanceof MachineIdentity) {
            throw new \InvalidArgumentException(sprintf('%s is a machine identity: it has no identifiers to verify by code.', $identity::class));
        }

        $identifier = CodeIdentifiers::of(IdentifierVerifier::verifiable($identity), IdentifierType::assertValid($type), $this->collaborator(IdentifierVerifier::class));

        return $identifier === null ? null : CodeBinding::verification($this->context->name(), $type, $identifier, $identity);
    }

    /**
     * Report a refused code request with `AuthenticationFailed` and answer it.
     *
     * @param  \SineMacula\Laravel\Authentication\Codes\CodeRequest  $request
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\FailureReason  $reason
     * @param  \SineMacula\Laravel\Authentication\Events\EventContext  $context
     * @param  ?string  $given
     * @param  ?int  $retryAfter
     * @return \SineMacula\Laravel\Authentication\Codes\CodeRequest
     */
    private function refuse(CodeRequest $request, FailureReason $reason, EventContext $context, ?string $given, ?int $retryAfter = null): CodeRequest
    {
        $this->report($context, AuthenticationFlow::CODE_REQUEST, $reason, $given, $retryAfter);

        return $request;
    }

    /**
     * Report a refused verification with `AuthenticationFailed` and answer it
     * with the outcome the reason names.
     *
     * @param  \SineMacula\Laravel\Authentication\Events\EventContext  $context
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\FailureReason  $reason
     * @param  ?string  $challengeId
     * @return \SineMacula\Laravel\Authentication\RateLimiting\LimitedOutcome<\SineMacula\Laravel\Authentication\Codes\Enums\VerificationOutcome>
     */
    private function refuseVerification(EventContext $context, FailureReason $reason, ?string $challengeId): LimitedOutcome
    {
        $this->report($context, AuthenticationFlow::IDENTIFIER_VERIFICATION, $reason, null, null, $challengeId);

        return new LimitedOutcome(match ($reason) {
            FailureReason::CODE_EXPIRED   => VerificationOutcome::EXPIRED,
            FailureReason::CODE_EXHAUSTED => VerificationOutcome::EXHAUSTED,
            default                       => VerificationOutcome::INVALID,
        });
    }

    /**
     * The result of an accepted code, as the verifier answered it.
     *
     * @param  \SineMacula\Laravel\Authentication\Verification\Enums\IdentifierVerification  $verification
     * @return \SineMacula\Laravel\Authentication\RateLimiting\LimitedOutcome<\SineMacula\Laravel\Authentication\Codes\Enums\VerificationOutcome>
     */
    private static function verifierOutcome(IdentifierVerification $verification): LimitedOutcome
    {
        return new LimitedOutcome(match ($verification) {
            IdentifierVerification::VERIFIED         => VerificationOutcome::VERIFIED,
            IdentifierVerification::ALREADY_VERIFIED => VerificationOutcome::ALREADY_VERIFIED,
            IdentifierVerification::MISMATCH         => VerificationOutcome::MISMATCH,
        });
    }

    /**
     * Dispatch `AuthenticationFailed` on the guard's current dispatcher.
     *
     * @param  \SineMacula\Laravel\Authentication\Events\EventContext  $context
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\AuthenticationFlow  $flow
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\FailureReason  $reason
     * @param  ?string  $identifier
     * @param  ?int  $retryAfter
     * @param  ?string  $challengeId
     * @return void
     */
    private function report(EventContext $context, AuthenticationFlow $flow, FailureReason $reason, ?string $identifier, ?int $retryAfter, ?string $challengeId = null): void
    {
        $this->context->dispatch(new AuthenticationFailed($context, $flow, $reason, $identifier, $retryAfter, $challengeId));
    }

    /**
     * The code sign-in method registered under the name.
     *
     * @param  string  $method
     * @return \SineMacula\Laravel\Authentication\Codes\CodeSignIn
     *
     * @throws \InvalidArgumentException
     */
    private function codeMethod(string $method): CodeSignIn
    {
        $driver = $this->collaborator(SignInMethodManager::class)->method($method);

        if (!$driver instanceof CodeSignIn) {
            throw new \InvalidArgumentException(sprintf('Sign-in method [%s] does not sign in with one-time codes.', $method));
        }

        return $driver;
    }

    /**
     * Resolve a collaborator from the container, so the binding in effect when
     * it is needed is the one used.
     *
     * @template TCollaborator of object
     *
     * @param  class-string<TCollaborator>  $abstract
     * @return TCollaborator
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function collaborator(string $abstract): object
    {
        return $this->container->make($abstract);
    }
}
