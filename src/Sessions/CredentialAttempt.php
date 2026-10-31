<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions;

use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Authentication\Admission\Refused;
use SineMacula\Laravel\Authentication\Contracts\AttemptLimiter;
use SineMacula\Laravel\Authentication\Contracts\AudiencePolicy;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\RateLimiting\AccountAttempts;
use SineMacula\Laravel\Authentication\RateLimiting\AttemptReservation;
use SineMacula\Laravel\Authentication\RateLimiting\AttemptSubject;

/**
 * One credential sign-in's attempt: the steps the guard's `attempt()` and the
 * session service's `signIn()` both take, and take the same way, each calling
 * them in its own order.
 *
 * `checkMethod()` asks the audience policy whether it allows the method, and
 * `begin()` then takes the sign-in's slot on the identifier and IP limits from
 * the limiter the entry point resolved, so each entry point keeps its own order
 * between the two: when it reads the identifier for the limits and when it
 * resolves the limiter. The attempt holds that slot and the account attempts
 * the secret checks count against, refuses a sign-in an account had no attempts
 * left for (`accountRefusal()`), hands a pending sign-in the windows it keeps
 * until it completes (`windows()`), and gives every slot back for a sign-in
 * that started its session (`release()`).
 *
 * What differs between the two entry points stays with each: the timebox and
 * what runs inside it, `Validated`, the admission and its pins, when the
 * password is rehashed, what a verified identity continues to, and the bind.
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
     * @param  \SineMacula\Laravel\Authentication\Contracts\AudiencePolicy  $audience
     * @param  \SineMacula\Laravel\Authentication\RateLimiting\AccountAttempts  $accounts
     * @param  \SineMacula\Laravel\Authentication\Contracts\AttemptLimiter  $limiter
     * @param  \SineMacula\Laravel\Authentication\RateLimiting\AttemptReservation  $reservation
     */
    private function __construct(

        /** The audience policy that allowed the method. */
        public AudiencePolicy $audience,

        /** The slots the sign-in takes on the accounts whose secret it checks. */
        public AccountAttempts $accounts,

        /** The limiter the slots were taken from. */
        private AttemptLimiter $limiter,

        /** The sign-in's slot on the identifier and IP limits. */
        private AttemptReservation $reservation,
    ) {}

    /**
     * The audience policy, resolved from the container then, when it allows the
     * method on the guard, or the refusal (`method_not_allowed`) of a sign-in
     * it does not allow, before anything is counted.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  string  $guard
     * @param  string  $method
     * @return \SineMacula\Laravel\Authentication\Admission\Refused|\SineMacula\Laravel\Authentication\Contracts\AudiencePolicy
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public static function checkMethod(Container $container, string $guard, string $method): AudiencePolicy|Refused
    {
        $audience = $container->make(AudiencePolicy::class);

        return $audience->allowsMethod($guard, $method) ? $audience : new Refused(FailureReason::METHOD_NOT_ALLOWED);
    }

    /**
     * Begin a sign-in the audience policy allowed: the identifier and the IP
     * address must have attempts left on the limiter (`rate_limited`, with the
     * wait).
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\AttemptLimiter  $limiter
     * @param  \SineMacula\Laravel\Authentication\Contracts\AudiencePolicy  $audience
     * @param  \SineMacula\Laravel\Authentication\RateLimiting\AttemptSubject  $subject
     * @return self|\SineMacula\Laravel\Authentication\Admission\Refused
     */
    public static function begin(AttemptLimiter $limiter, AudiencePolicy $audience, AttemptSubject $subject): Refused|self
    {
        $reservation = $limiter->acquire($subject);

        if (!$reservation->granted()) {
            return new Refused(FailureReason::RATE_LIMITED, retryAfter: $reservation->retryAfter);
        }

        return new self($audience, new AccountAttempts($limiter, $subject->guard), $limiter, $reservation);
    }

    /**
     * The refusal of a sign-in in which an account whose secret it checked had
     * no attempts left (`account_rate_limited`, with that account's wait), or
     * `null` when every account had attempts left.
     *
     * @return ?\SineMacula\Laravel\Authentication\Admission\Refused
     */
    public function accountRefusal(): ?Refused
    {
        $wait = $this->accounts->refusedFor();

        return $wait === null ? null : new Refused(FailureReason::ACCOUNT_RATE_LIMITED, retryAfter: $wait);
    }

    /**
     * The windows of every slot the sign-in holds, its own first, for a pending
     * sign-in to keep and give back when it completes.
     *
     * @return list<array<string, string>>
     */
    public function windows(): array
    {
        return [$this->reservation->windows, ...$this->accounts->windows()];
    }

    /**
     * Give back every slot the sign-in holds, its own and the accounts', for a
     * sign-in that started its session.
     *
     * @return void
     */
    public function release(): void
    {
        $this->limiter->release($this->reservation);
        $this->accounts->release();
    }
}
