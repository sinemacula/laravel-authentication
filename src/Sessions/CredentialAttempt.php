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
 * `begin()` checks that the audience policy allows the method and takes the
 * sign-in's slot on the identifier and IP limits; the attempt then holds that
 * slot and the account attempts the secret checks count against, refuses a
 * sign-in an account had no attempts left for (`accountRefusal()`), hands a
 * pending sign-in the windows it keeps until it completes (`windows()`), and
 * gives every slot back for a sign-in that started its session (`release()`).
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
     * Begin the sign-in: the audience policy must allow the method
     * (`method_not_allowed`, nothing taken), and the identifier and the IP
     * address must have attempts left (`rate_limited`, with the wait). The
     * policy and the limiter are resolved from the container then, the limiter
     * only once the method is allowed.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  \SineMacula\Laravel\Authentication\RateLimiting\AttemptSubject  $subject
     * @param  string  $method
     * @return self|\SineMacula\Laravel\Authentication\Admission\Refused
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public static function begin(Container $container, AttemptSubject $subject, string $method): Refused|self
    {
        $audience = $container->make(AudiencePolicy::class);

        if (!$audience->allowsMethod($subject->guard, $method)) {
            return new Refused(FailureReason::METHOD_NOT_ALLOWED);
        }

        $limiter     = $container->make(AttemptLimiter::class);
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
