<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Codes;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Authentication\Codes\Enums\CodeCheck;
use SineMacula\Laravel\Authentication\Codes\Enums\FactorCodeOutcome;
use SineMacula\Laravel\Authentication\Codes\Enums\FactorCodeStanding;
use SineMacula\Laravel\Authentication\Contracts\AttemptLimiter;
use SineMacula\Laravel\Authentication\Contracts\FactorCodeCounters;
use SineMacula\Laravel\Authentication\Delivery\QueuedDelivery;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\Enums\AuthenticationFlow;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\EventContext;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Models\OneTimeCode;
use SineMacula\Laravel\Authentication\RateLimiting\AttemptSubject;
use SineMacula\Laravel\Authentication\RateLimiting\Enums\AttemptFlow;
use SineMacula\Laravel\Authentication\Runtime\GuardContext;

/**
 * Sends and checks a factor package's codes for a guard, as
 * `CodeService::sendFactorCode()` and `verifyFactorCode()` describe: a further
 * factor's `mfa` challenges and the `enrollment` challenges that confirm a
 * factor being enrolled, with the bound `FactorCodeCounters` asked and told
 * inside one transaction on the storage connection.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class FactorCodes
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Runtime\GuardContext  $context
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** The context of the guard the codes are sent and checked through. */
        private GuardContext $context,

        /** Container the counters, limiter, engine and delivery are resolved from. */
        private Container $container,
    ) {}

    /**
     * Send the binding's code, after the `code_request` limits and the
     * counters' admission, and queue its delivery once it commits.
     *
     * @param  \SineMacula\Laravel\Authentication\Codes\FactorCodeBinding  $binding
     * @param  \SineMacula\Laravel\Authentication\Delivery\QueuedDelivery  $delivery
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Authentication\Codes\CodeRequest
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \Throwable
     */
    public function send(FactorCodeBinding $binding, QueuedDelivery $delivery, ClientContext $client): CodeRequest
    {
        $guard   = $this->application($binding);
        $context = new EventContext($guard, $client, $binding->binding->identity);
        $code    = CodeBinding::factor($guard, $binding);

        $reservation = $this->container->make(AttemptLimiter::class)->acquire(
            new AttemptSubject($guard, AttemptFlow::CODE_REQUEST, $code->identifier, $code->type, $context->client->ip, $code->identity),
        );

        if ($reservation->retryAfter !== null) {
            return $this->refuse(CodeRequest::rateLimited($reservation->retryAfter), FailureReason::RATE_LIMITED, $context, $reservation->retryAfter);
        }

        $counters = $this->container->make(FactorCodeCounters::class);
        $codes    = $this->container->make(OneTimeCodes::class);

        $issued = (new OneTimeCode)->getConnection()->transaction(
            static fn (): DeliveryRefusal|FactorCodeAdmission|IssuedCode => self::issue($counters, $codes, $binding, $code, $delivery),
        );

        return $this->answer($issued, $context);
    }

    /**
     * Check the code for the challenge against the binding, after the
     * `factor_code` limits, inside one transaction that asks the counters first
     * and reports the attempt it counts.
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
    public function verify(FactorCodeBinding $binding, string $challengeId, #[\SensitiveParameter] string $code, ClientContext $client): FactorCodeCheck
    {
        $guard   = $this->application($binding);
        $context = new EventContext($guard, $client, $binding->binding->identity);
        $codes   = $this->container->make(OneTimeCodes::class);

        $limiter     = $this->container->make(AttemptLimiter::class);
        $reservation = $limiter->acquire(new AttemptSubject($guard, AttemptFlow::FACTOR_CODE, null, null, $context->client->ip));

        if ($reservation->retryAfter !== null) {
            return $this->refuseCheck(new FactorCodeCheck(FactorCodeOutcome::RATE_LIMITED, $challengeId, retryAfter: $reservation->retryAfter), $context);
        }

        if (!$codes->isWellFormedChallenge($challengeId) || !$codes->isWellFormed($code)) {
            $outcome = $codes->isWellFormedChallenge($challengeId) ? FactorCodeOutcome::INVALID : FactorCodeOutcome::NOT_FOUND;

            return $this->refuseCheck(new FactorCodeCheck($outcome, $challengeId), $context);
        }

        // `#[\SensitiveParameter]` does not cover what a closure captures,
        // which a dump of the trace shows.
        $secret   = new \SensitiveParameterValue($code);
        $counters = $this->container->make(FactorCodeCounters::class);
        $bound    = CodeBinding::factor($guard, $binding);

        $check = (new OneTimeCode)->getConnection()->transaction(
            static fn (): FactorCodeCheck => self::consume($counters, $codes, $binding, $bound, $challengeId, $secret->getValue()),
        );

        if ($check->isVerified()) {
            $limiter->release($reservation);
        } else {
            $this->refuseCheck($check, $context);
        }

        return $check;
    }

    /**
     * Inside the send's transaction: ask the counters, then issue the code and
     * queue its delivery to the identity once the transaction commits.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\FactorCodeCounters  $counters
     * @param  \SineMacula\Laravel\Authentication\Codes\OneTimeCodes  $codes
     * @param  \SineMacula\Laravel\Authentication\Codes\FactorCodeBinding  $binding
     * @param  \SineMacula\Laravel\Authentication\Codes\CodeBinding  $code
     * @param  \SineMacula\Laravel\Authentication\Delivery\QueuedDelivery  $delivery
     * @return \SineMacula\Laravel\Authentication\Codes\DeliveryRefusal|\SineMacula\Laravel\Authentication\Codes\FactorCodeAdmission|\SineMacula\Laravel\Authentication\Codes\IssuedCode
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \Random\RandomException
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    private static function issue(
        FactorCodeCounters $counters,
        OneTimeCodes $codes,
        FactorCodeBinding $binding,
        CodeBinding $code,
        QueuedDelivery $delivery,
    ): DeliveryRefusal|FactorCodeAdmission|IssuedCode {
        $admission = $counters->admit($binding);

        if (!$admission->isAdmitted()) {
            return $admission;
        }

        $issued = $codes->issue($code, CarbonImmutable::now()->startOfSecond());

        if ($issued instanceof IssuedCode) {
            $delivery->dispatch(new SendOneTimeCode($code, $issued, $binding->binding->identity), new OneTimeCode);
        }

        return $issued;
    }

    /**
     * Inside the check's transaction: ask the counters, then check the code
     * against the challenge, locked, and report the attempt it counted.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\FactorCodeCounters  $counters
     * @param  \SineMacula\Laravel\Authentication\Codes\OneTimeCodes  $codes
     * @param  \SineMacula\Laravel\Authentication\Codes\FactorCodeBinding  $binding
     * @param  \SineMacula\Laravel\Authentication\Codes\CodeBinding  $bound
     * @param  string  $challengeId
     * @param  string  $code
     * @return \SineMacula\Laravel\Authentication\Codes\FactorCodeCheck
     *
     * @throws \InvalidArgumentException
     */
    private static function consume(
        FactorCodeCounters $counters,
        OneTimeCodes $codes,
        FactorCodeBinding $binding,
        CodeBinding $bound,
        string $challengeId,
        #[\SensitiveParameter] string $code,
    ): FactorCodeCheck {
        $admission = $counters->admit($binding);

        if (!$admission->isAdmitted()) {
            return self::checked($admission, $challengeId);
        }

        $now = CarbonImmutable::now()->startOfSecond();

        return match ($codes->check($bound, $challengeId, $code, $now, true)) {
            CodeCheck::INVALID   => new FactorCodeCheck(FactorCodeOutcome::INVALID, $challengeId),
            CodeCheck::NOT_FOUND => new FactorCodeCheck(FactorCodeOutcome::NOT_FOUND, $challengeId),
            CodeCheck::USED      => new FactorCodeCheck(FactorCodeOutcome::USED, $challengeId),
            CodeCheck::EXPIRED   => new FactorCodeCheck(FactorCodeOutcome::EXPIRED, $challengeId),
            CodeCheck::EXHAUSTED => new FactorCodeCheck(FactorCodeOutcome::EXHAUSTED, $challengeId),
            CodeCheck::ACCEPTED  => self::checked($counters->report($binding, $challengeId, true), $challengeId, $now),
            CodeCheck::WRONG     => self::checked($counters->report($binding, $challengeId, false), $challengeId, wrong: true),
        };
    }

    /**
     * The check a factor code ends in once the counters answered: `verified`
     * at the time given, when they admitted a matching code; `locked` or
     * `refused` when they did not admit one, or did not admit the check at
     * all; `invalid`, carrying any lock or refusal they reported, for a wrong
     * code. A challenge that is absent or used is answered before the counters
     * are told, so is never one of these.
     *
     * @param  \SineMacula\Laravel\Authentication\Codes\FactorCodeAdmission  $admission
     * @param  string  $challengeId
     * @param  ?\Carbon\CarbonImmutable  $matchedAt
     * @param  bool  $wrong
     * @return \SineMacula\Laravel\Authentication\Codes\FactorCodeCheck
     */
    private static function checked(FactorCodeAdmission $admission, string $challengeId, ?CarbonImmutable $matchedAt = null, bool $wrong = false): FactorCodeCheck
    {
        $outcome = match (true) {
            $wrong                                              => FactorCodeOutcome::INVALID,
            $admission->standing === FactorCodeStanding::LOCKED => FactorCodeOutcome::LOCKED,
            $admission->isAdmitted()                            => FactorCodeOutcome::VERIFIED,
            default                                             => FactorCodeOutcome::REFUSED,
        };

        return new FactorCodeCheck($outcome, $challengeId, $outcome === FactorCodeOutcome::VERIFIED ? $matchedAt : null, $admission->lockedUntil, $admission->refusal);
    }

    /**
     * The answer to a send once its transaction ended: sent, or why not,
     * reported.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  \SineMacula\Laravel\Authentication\Codes\DeliveryRefusal|\SineMacula\Laravel\Authentication\Codes\FactorCodeAdmission|\SineMacula\Laravel\Authentication\Codes\IssuedCode  $issued
     * @param  \SineMacula\Laravel\Authentication\Events\EventContext  $context
     * @return \SineMacula\Laravel\Authentication\Codes\CodeRequest
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    private function answer(DeliveryRefusal|FactorCodeAdmission|IssuedCode $issued, EventContext $context): CodeRequest
    {
        return match (true) {
            $issued instanceof IssuedCode                    => CodeRequest::sent($issued->expiresAt, $issued->resendAvailableAt, $issued->challengeId),
            $issued instanceof DeliveryRefusal               => $this->refuse($issued->request(), $issued->reason(), $context, $issued->retryAfter),
            $issued->standing === FactorCodeStanding::LOCKED => $this->refuse(CodeRequest::locked($issued->lockedUntil), FailureReason::FACTOR_CODE_LOCKED, $context),
            default                                          => $this->refuse(CodeRequest::refused($issued->refusal), FailureReason::FACTOR_CODE_REFUSED, $context),
        };
    }

    /**
     * The guard the binding is for, which must be this one.
     *
     * @param  \SineMacula\Laravel\Authentication\Codes\FactorCodeBinding  $binding
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    private function application(FactorCodeBinding $binding): string
    {
        $guard = $this->context->name();

        if ($binding->binding->application !== $guard) {
            $message = sprintf('A factor code bound to application [%s] cannot be sent or checked', $binding->binding->application);

            throw new \InvalidArgumentException(sprintf('%s through guard [%s].', $message, $guard));
        }

        return $guard;
    }

    /**
     * Report a refused send with `AuthenticationFailed` and answer it.
     *
     * @param  \SineMacula\Laravel\Authentication\Codes\CodeRequest  $request
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\FailureReason  $reason
     * @param  \SineMacula\Laravel\Authentication\Events\EventContext  $context
     * @param  ?int  $retryAfter
     * @return \SineMacula\Laravel\Authentication\Codes\CodeRequest
     */
    private function refuse(CodeRequest $request, FailureReason $reason, EventContext $context, ?int $retryAfter = null): CodeRequest
    {
        $this->context->dispatch(new AuthenticationFailed($context, AuthenticationFlow::FACTOR_CODE, $reason, null, $retryAfter));

        return $request;
    }

    /**
     * Report a check that was not verified with `AuthenticationFailed`, with
     * the id of the challenge it checked when that is in the form the engine
     * issues, and answer it.
     *
     * @param  \SineMacula\Laravel\Authentication\Codes\FactorCodeCheck  $check
     * @param  \SineMacula\Laravel\Authentication\Events\EventContext  $context
     * @return \SineMacula\Laravel\Authentication\Codes\FactorCodeCheck
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function refuseCheck(FactorCodeCheck $check, EventContext $context): FactorCodeCheck
    {
        $reason = match ($check->outcome) {
            FactorCodeOutcome::EXPIRED      => FailureReason::CODE_EXPIRED,
            FactorCodeOutcome::EXHAUSTED    => FailureReason::CODE_EXHAUSTED,
            FactorCodeOutcome::LOCKED       => FailureReason::FACTOR_CODE_LOCKED,
            FactorCodeOutcome::REFUSED      => FailureReason::FACTOR_CODE_REFUSED,
            FactorCodeOutcome::RATE_LIMITED => FailureReason::RATE_LIMITED,
            default                         => FailureReason::INVALID_CREDENTIALS,
        };

        $challengeId = $this->container->make(OneTimeCodes::class)->isWellFormedChallenge($check->challengeId) ? $check->challengeId : null;

        $this->context->dispatch(new AuthenticationFailed($context, AuthenticationFlow::FACTOR_CODE, $reason, null, $check->retryAfter, $challengeId));

        return $check;
    }
}
