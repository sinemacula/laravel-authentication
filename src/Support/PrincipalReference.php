<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Support;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Contracts\Principal;

/**
 * How a principal is recorded on the rows that remember it (a session, a
 * pending sign-in): a polymorphic type, which is an Eloquent principal's morph
 * class and any other principal's class name, and its identifier as a string.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class PrincipalReference
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * The type recorded for the principal.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @return string
     */
    public static function type(Principal $principal): string
    {
        return $principal instanceof Model ? $principal->getMorphClass() : $principal::class;
    }

    /**
     * The identifier recorded for the principal, or `null` when it has none
     * that can be written (an unsaved model's).
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @return ?string
     */
    public static function id(Principal $principal): ?string
    {
        return IdentifierCoercion::stringify($principal->getPrincipalIdentifier());
    }

    /**
     * Whether the session records the principal as the one it acts as: the same
     * type and identifier, read from the columns of the session's `principal()`
     * relation without a query.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @return bool
     */
    public static function isRecordedOn(EloquentSession&Model $session, Principal $principal): bool
    {
        [$type, $id] = self::columns($session);

        return $session->getAttribute($type) === self::type($principal)
            && IdentifierCoercion::matches($session->getAttribute($id), self::id($principal));
    }

    /**
     * The session's principal morph type and identifier columns, read from its
     * `principal()` relation on a blank instance: building the relation on a
     * session that records a principal would instantiate the recorded type,
     * which for a principal that is not an Eloquent model is not a model.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @return array{0: string, 1: string}
     */
    public static function columns(EloquentSession&Model $session): array
    {
        /** @var \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession $blank */
        $blank    = $session->newInstance();
        $relation = $blank->principal();

        return [$relation->getMorphType(), $relation->getForeignKeyName()];
    }
}
