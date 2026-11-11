<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Support;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Contracts\Principal;

/**
 * How a principal is recorded on session rows: a morph type and a string id.
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
     * The identifier recorded for the principal, or `null` for an unsaved
     * model.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @return ?string
     */
    public static function id(Principal $principal): ?string
    {
        return IdentifierCoercion::stringify($principal->getPrincipalIdentifier());
    }

    /**
     * Whether the session records the principal, read without a query.
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
     * The session's principal morph type and identifier columns.
     *
     * Read on a blank instance, since a recorded non-model type cannot build
     * the relation.
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
