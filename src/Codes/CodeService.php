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
 * The one-time code service of a JWT guard (`Auth::codes($guard)`): sends
 * sign-in codes for the code sign-in methods, sends and checks codes that
 * verify an identity's identifier, and sends and checks a factor package's
 * further-factor and enrolment codes.
 *
 * Every code is a challenge: the request answers its id (`CodeRequest::
 * $challengeId`), which the check must name, and a resend within the delivery
 * window keeps it, with its attempts, while it is live (see
 * `authentication.codes`).
 *
 * Sending a sign-in code does no work that depends on whether an identity has
 * the identifier: the guard must allow the method, the identifier must be one
 * its type's normaliser accepts, the identifier and the IP address must have
 * code requests left (`code_request` limits, counted on every request), and no
 * code may have been issued for the identifier within the resend cooldown;
 * then a code is issued and its delivery queued, once the code is committed.
 * The result (a challenge id among it), the statements run and the time taken
 * are the same for an identifier no one has, and the queued job alone decides,
 * later, whether anyone receives the code. The code signs in through
 * `Auth::sessions($guard)->signIn($method, ...)`, with its challenge id.
 *
 * Verifying by code is the code form of the verification helpers: a code bound
 * to the guard, the identity and its current identifier of the type, which,
 * checked with `verify()`, records the verification through
 * `IdentifierVerifier`. It never signs anyone in. Checks count against the
 * identity's account and the IP address (`identifier_verification`).
 *
 * A factor package's codes (`sendFactorCode()`, `verifyFactorCode()`) are bound
 * to a `FactorCodeBinding`: the identity, this guard, the session, the factor
 * and its purpose (`mfa` for a sign-in or a step-up, `enrollment` for the
 * confirmation of a factor being enrolled, with its grant). The bound
 * `FactorCodeCounters` is asked before each delivery and each check, inside one
 * transaction on the storage connection, and told the outcome of every attempt
 * counted, in the transaction that counts it; its default refuses every code.
 * This service keeps the per-challenge counts and the per-IP limits.
 *
 * Failures are results, reported by `AuthenticationFailed`; exceptions are kept
 * for misconfiguration and server errors. The service keeps no state between
 * calls: it reads the request and dispatcher from the guard's context, and
 * resolves the methods, policies, limiter and engine from the container, each
 * time.
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
     * the input names under the method's identifier type (for `phone_code`,
     * `['phone' => '+447700900123']`). A method that does not sign in with
     * codes is a misconfiguration (`InvalidArgumentException`).
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
     * Send a code that verifies the identity's current identifier of the type,
     * read on the write connection, to that identifier. An identity that cannot
     * verify identifiers (`LogicException`), or that is a machine identity,
     * which has none to verify (`InvalidArgumentException`), is a
     * misconfiguration; one with no identifier of the type, or one its type's
     * normaliser rejects, is `identifier_invalid`.
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
     * Check a verification code, sent for the challenge named, for the
     * identity's current identifier of the type, and record the identifier
     * verified when it is accepted: `verified` or `already_verified`, as
     * `IdentifierVerifier::verify()` answers it. Otherwise why not (`invalid`,
     * `expired`, `exhausted` or `rate_limited`; not concealed, since the caller
     * already holds the identity), reported by `AuthenticationFailed` as
     * `invalid_credentials`, `code_expired`, `code_exhausted` or
     * `rate_limited`, the last with the wait on the result. A check of a
     * well-formed code and challenge id counts against the identity's account
     * and the IP address (`identifier_verification`) and gives them back once
     * the code is accepted. A code sent before the identifier changed is bound
     * to the old one, so it verifies nothing; one whose identifier changed
     * after the identity was loaded is used up and answers `mismatch`, with
     * nothing recorded or reported, as the verifier gives it.
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

        if ($binding === null || $challenge === null || !$codes->isWellFormed($code)) {
            return $this->refuseVerification($context, FailureReason::INVALID_CREDENTIALS, $challenge);
        }

        $limiter     = $this->collaborator(AttemptLimiter::class);
        $reservation = $limiter->acquire(
            new AttemptSubject($binding->guard, AttemptFlow::IDENTIFIER_VERIFICATION, null, null, $context->client->ip, AccountAttempts::account($identity)),
        );

        if ($reservation->retryAfter !== null) {
            $this->report($context, AuthenticationFlow::IDENTIFIER_VERIFICATION, FailureReason::RATE_LIMITED, null, $reservation->retryAfter, $challenge);

            return new LimitedOutcome(VerificationOutcome::RATE_LIMITED, $reservation->retryAfter);
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
     * the binding's channel, for the identity, the session and the factor it
     * names. A binding for another application than this guard is a
     * misconfiguration (`InvalidArgumentException`), as are malformed settings,
     * refused before anything is counted.
     *
     * The request counts under `code_request` on the destination, the
     * identity's account and the IP address; then, in one transaction on the
     * storage connection (a savepoint of the caller's), the bound
     * `FactorCodeCounters` is asked first (`locked` or `refused`, nothing
     * written), and the code is issued: a resend of the live challenge for the
     * same session, factor and purpose (or grant) keeps its id and its
     * attempts, anything else is a new challenge, and the destination's
     * cooldown and delivery cap hold whichever factor or grant the binding
     * names. The delivery is queued once the transaction commits, through the
     * application's `OneTimeCodeSender`, with the purpose `mfa` or `enrollment`
     * and the channel's kind as the type. Every refusal is reported by
     * `AuthenticationFailed` (flow `factor_code`).
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
     * named, against the binding: the same identity, guard, session, factor and
     * purpose (or grant) the code was sent for, or it is `invalid`. A binding
     * for another application than this guard is a misconfiguration
     * (`InvalidArgumentException`).
     *
     * A malformed code or challenge id is `invalid`, with nothing counted and
     * nothing reported to the factor package. A check counts per IP address
     * (`factor_code`), then, in one transaction on the storage connection (a
     * savepoint of the caller's): asks the bound `FactorCodeCounters` first
     * (`locked` or `refused`, the challenge untouched, nothing reported); locks
     * the challenge's row; answers a challenge that is not the live one, or
     * whose transaction is another, as `invalid`, and an expired or exhausted
     * one as such, without counting or reporting; otherwise counts the attempt,
     * compares the code, uses the challenge up when it matches, and reports the
     * attempt to the counters exactly once, whose answer stands: a matching
     * code is `verified` only when they admit it, and `locked` or `refused`
     * otherwise (the challenge stays used up); a wrong one is `invalid`,
     * carrying any lock they reported. A verified code gives its IP slot back.
     * Every refusal is reported by `AuthenticationFailed` (flow `factor_code`).
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
     * its delivery (see `QueuedDelivery`); malformed settings, the code key and
     * the delivery queue among them, fail closed before anything is counted.
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
     * Validate every setting a code request reads (the codes, their key and the
     * delivery queue), failing closed before anything is counted, and answer
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
     * type, read on the write connection, in its normal form; `null` when it
     * has none the type's normaliser accepts.
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
