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
 * after" cutoff, with the cutoffs it moved for each holder.
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
     * cutoff, returning what forgets the record again.
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
     * The time the holder's cutoff must pass to end the session's call.
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
     * What tells a holder that is no Eloquent model apart.
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
