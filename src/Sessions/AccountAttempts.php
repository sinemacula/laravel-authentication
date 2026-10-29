<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Contracts\AttemptLimiter;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Jwt\IdentifierCoercion;
use SineMacula\Laravel\Authentication\RateLimiting\AttemptReservation;
use SineMacula\Laravel\Authentication\RateLimiting\AttemptSubject;
use SineMacula\Laravel\Authentication\RateLimiting\Enums\AttemptFlow;

/**
 * The slots one sign-in takes on the limits of the accounts whose secret it
 * checks, held for as long as the sign-in lasts: given back when it starts a
 * session, kept by a pending sign-in until that completes, and left counted
 * when it fails, exactly as the sign-in's own identifier and IP slots are. A
 * check whose slot is given back as soon as the secret matches would let every
 * spelling of an identifier that finds the account mint a pending sign-in, and
 * so a guess at a further factor, outside the account's limit.
 *
 * It remembers when an account had no attempts left, so the failure events can
 * say so. Made for one sign-in and dropped with it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class AccountAttempts
{
    /** @var list<\SineMacula\Laravel\Authentication\RateLimiting\AttemptReservation> The granted reservations held. */
    private array $held = [];

    /** @var ?int Seconds until an account that had no attempts left allows another, once one has refused. */
    private ?int $refusedFor = null;

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\AttemptLimiter  $limiter
     * @param  string  $guard
     */
    public function __construct(

        /** The limiter the slots are taken from and given back to. */
        private readonly AttemptLimiter $limiter,

        /** Guard the sign-in is for, whose identifier limit the accounts are held to. */
        private readonly string $guard,
    ) {}

    /**
     * Take a slot on the identity's account limit before its secret is checked,
     * and hold it. Returns `false`, holding nothing, when the account has no
     * attempts left.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @return bool
     *
     * @throws \InvalidArgumentException
     *
     * @phpstan-impure
     *
     * @imperative
     */
    public function reserve(Identity $identity): bool
    {
        $reservation = $this->limiter->acquire(new AttemptSubject($this->guard, AttemptFlow::SIGN_IN, null, null, null, self::account($identity)));

        if (!$reservation->granted()) {

            $this->refusedFor = $reservation->retryAfter;

            return false;
        }

        $this->held[] = $reservation;

        return true;
    }

    /**
     * Give back every slot held, for a sign-in that started its session.
     *
     * @return void
     */
    public function release(): void
    {
        foreach ($this->held as $reservation) {
            $this->limiter->release($reservation);
        }
    }

    /**
     * The windows of each reservation held, one entry per reservation, for a
     * pending sign-in to keep until it completes and then give back as they
     * were taken: two reservations of one account (a method that checks two
     * secrets) give back two slots.
     *
     * @return list<array<string, string>>
     */
    public function windows(): array
    {
        return array_map(static fn (AttemptReservation $reservation): array => $reservation->windows, $this->held);
    }

    /**
     * What identifies the identity's account to its limit: for an Eloquent
     * model, the row it is stored in (its connection, that connection's
     * database, its table and its key), so every model class that reads the
     * table (an `Admin` that extends `User`, say) counts in the account's one
     * counter, and the same key in another database (another tenant's) counts
     * apart; for any other identity, its class and auth identifier.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @return string
     */
    public static function account(Identity $identity): string
    {
        if (!$identity instanceof Model) {
            return implode("\0", ['class', $identity::class, IdentifierCoercion::stringify($identity->getAuthIdentifier())]);
        }

        $connection = $identity->getConnection();

        return implode("\0", [
            'row',
            $connection->getName(),
            $connection->getDatabaseName(),
            $connection->getTablePrefix() . $identity->getTable(),
            IdentifierCoercion::stringify($identity->getKey()),
        ]);
    }

    /**
     * Seconds until the account that had no attempts left allows another, or
     * `null` when no account refused.
     *
     * @return ?int
     */
    public function refusedFor(): ?int
    {
        return $this->refusedFor;
    }
}
