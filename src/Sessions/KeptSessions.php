<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions;

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Contracts\HasTokensValidAfter;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use SineMacula\Laravel\Authentication\Support\RowKey;

/**
 * The sessions a bulk revocation kept on purpose while it moved a "tokens valid
 * after" cutoff (the session a password change, a password establishment, a
 * credential's removal or a sign-out everywhere keeps), each with the cutoffs
 * such revocations moved for each holder, so the check a sign-in, a choice or a
 * switch is held to (`AdmissionRecheck`) does not take a cutoff moved by a
 * revocation that saw its session, and kept it, for one that could not see it.
 *
 * Only a revocation and a check of the same request or job meet here, which is
 * where the check can be waiting when such a revocation runs: inside a caller's
 * transaction, which the check waits for. Sessions and holders are told apart
 * as their rows are (`RowKey`) for Eloquent models, and by class and identifier
 * for any other identity or principal. A record is forgotten when the move of
 * an Eloquent holder's cutoff it stands for rolls back (`RevocationWriter`).
 *
 * One instance is shared through the container, scoped, so nothing one request
 * or job kept is seen by the next.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class KeptSessions
{
    /** @var array<string, array<int, \Carbon\CarbonImmutable>> Per session and holder, each cutoff a revocation that kept the session moved, by number. */
    private array $kept = [];

    /**
     * Record that a revocation kept the session while it moved the holder's
     * cutoff to the time given, and return what forgets that record again, for
     * a move of the cutoff that is rolled back.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $session
     * @param  \SineMacula\Laravel\Authentication\Contracts\HasTokensValidAfter  $holder
     * @param  \Carbon\CarbonImmutable  $cutoff
     * @return \Closure(): void
     */
    public function keep(Model $session, HasTokensValidAfter $holder, CarbonImmutable $cutoff): \Closure
    {
        $key = self::key($session, $holder);

        $this->kept[$key][] = $cutoff;

        $number = array_key_last($this->kept[$key]);

        return function () use ($key, $number): void {
            unset($this->kept[$key][$number]);
        };
    }

    /**
     * The time the holder's cutoff must pass to end the session's call: the
     * call's start, or the latest cutoff a revocation that kept the session
     * moved, when later.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $session
     * @param  \SineMacula\Laravel\Authentication\Contracts\HasTokensValidAfter  $holder
     * @param  \Carbon\CarbonImmutable  $began
     * @return \Carbon\CarbonImmutable
     */
    public function floor(Model $session, HasTokensValidAfter $holder, CarbonImmutable $began): CarbonImmutable
    {
        return max([$began, ...$this->kept[self::key($session, $holder)] ?? []]);
    }

    /**
     * What tells the session and the holder apart, together.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $session
     * @param  \SineMacula\Laravel\Authentication\Contracts\HasTokensValidAfter  $holder
     * @return string
     */
    private static function key(Model $session, HasTokensValidAfter $holder): string
    {
        return implode("\0\0", [RowKey::of($session), $holder instanceof Model ? RowKey::of($holder) : self::subject($holder)]);
    }

    /**
     * What tells a holder that is no Eloquent model apart: its class and its
     * identifier as an identity (its auth identifier) or a principal, or the
     * instance itself for any other.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\HasTokensValidAfter  $holder
     * @return string
     */
    private static function subject(HasTokensValidAfter $holder): string
    {
        $id = match (true) {
            $holder instanceof Identity  => IdentifierCoercion::stringify($holder->getAuthIdentifier()),
            $holder instanceof Principal => IdentifierCoercion::stringify($holder->getPrincipalIdentifier()),
            default                      => spl_object_id($holder),
        };

        return implode("\0", ['class', $holder::class, $id]);
    }
}
