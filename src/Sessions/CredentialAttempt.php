<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions;

use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Authentication\Admission\Refused;
use SineMacula\Laravel\Authentication\Contracts\ApplicationPolicy;
use SineMacula\Laravel\Authentication\Contracts\AttemptLimiter;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\RateLimiting\AccountAttempts;
use SineMacula\Laravel\Authentication\RateLimiting\AttemptReservation;
use SineMacula\Laravel\Authentication\RateLimiting\AttemptSubject;

/**
 * One credential sign-in's attempt: the steps the guard's `attempt()` and the
 * session service's `signIn()` share.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class CredentialAttempt
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\ApplicationPolicy  $policy
     * @param  \SineMacula\Laravel\Authentication\RateLimiting\AccountAttempts  $accounts
     * @param  \SineMacula\Laravel\Authentication\Contracts\AttemptLimiter  $limiter
     * @param  \SineMacula\Laravel\Authentication\RateLimiting\AttemptReservation  $reservation
     */
    private function __construct(

        /** The application policy that allowed the method. */
        public ApplicationPolicy $policy,

        /** The slots the sign-in takes on the accounts whose secret it checks. */
        public AccountAttempts $accounts,

        /** The limiter the slots were taken from. */
        private AttemptLimiter $limiter,

        /** The sign-in's slot on the identifier and IP limits. */
        private AttemptReservation $reservation,
    ) {}

    /**
     * The application policy when it allows the method on the guard, or the
     * `method_not_allowed` refusal.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  string  $guard
     * @param  string  $method
     * @return \SineMacula\Laravel\Authentication\Admission\Refused|\SineMacula\Laravel\Authentication\Contracts\ApplicationPolicy
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public static function checkMethod(Container $container, string $guard, string $method): ApplicationPolicy|Refused
    {
        $policy = $container->make(ApplicationPolicy::class);

        return $policy->allowsMethod($guard, $method) ? $policy : new Refused(FailureReason::METHOD_NOT_ALLOWED);
    }

    /**
     * Begin a sign-in, refused as `rate_limited` when the identifier or IP
     * address has no attempts left.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\AttemptLimiter  $limiter
     * @param  \SineMacula\Laravel\Authentication\Contracts\ApplicationPolicy  $policy
     * @param  \SineMacula\Laravel\Authentication\RateLimiting\AttemptSubject  $subject
     * @return self|\SineMacula\Laravel\Authentication\Admission\Refused
     */
    public static function begin(AttemptLimiter $limiter, ApplicationPolicy $policy, AttemptSubject $subject): Refused|self
    {
        $reservation = $limiter->acquire($subject);

        if (!$reservation->granted()) {
            return new Refused(FailureReason::RATE_LIMITED, retryAfter: $reservation->retryAfter);
        }

        return new self($policy, new AccountAttempts($limiter, $subject->guard), $limiter, $reservation);
    }

    /**
     * The `account_rate_limited` refusal when an account whose secret was
     * checked had no attempts left.
     *
     * @return ?\SineMacula\Laravel\Authentication\Admission\Refused
     */
    public function accountRefusal(): ?Refused
    {
        $wait = $this->accounts->refusedFor();

        return $wait === null ? null : new Refused(FailureReason::ACCOUNT_RATE_LIMITED, retryAfter: $wait);
    }

    /**
     * The windows of every slot the sign-in holds, its own first.
     *
     * @return list<array<string, string>>
     */
    public function windows(): array
    {
        return [$this->reservation->windows, ...$this->accounts->windows()];
    }

    /**
     * Give back every slot the sign-in holds.
     *
     * @return void
     */
    public function release(): void
    {
        $this->limiter->release($this->reservation);
        $this->accounts->release();
    }
}
