<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\SessionRecords;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Contracts\Session;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;

/**
 * Decide whether two session rows are one session, by the generation each
 * records.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class SessionGeneration
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Whether the row stored under the key of the session given is that
     * session.
     *
     * @formatter:off
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @param  (\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession)|null  $stored
     * @return bool
     *
     * @phpstan-assert-if-true \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession $session
     * @phpstan-assert-if-true !null $stored
     *
     * @formatter:on
     */
    public static function isHeld(Session $session, (EloquentSession&Model)|null $stored): bool
    {
        return $stored !== null && $session instanceof EloquentSession && $session instanceof Model && self::isSame($session, $stored);
    }

    /**
     * Whether the two rows record the same generation.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $other
     * @return bool
     */
    public static function isSame(EloquentSession&Model $session, EloquentSession&Model $other): bool
    {
        $generation = self::of($session);

        return $generation !== null && $generation === self::of($other);
    }

    /**
     * The generation the row records, or `null` for none.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @return ?string
     */
    private static function of(EloquentSession&Model $session): ?string
    {
        return IdentifierCoercion::stringify($session->getAttribute($session->getGenerationName()));
    }
}
