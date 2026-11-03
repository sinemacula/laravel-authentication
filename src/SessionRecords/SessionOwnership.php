<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\SessionRecords;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\Relation;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\MachineIdentity;
use SineMacula\Laravel\Authentication\Contracts\Session;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;

/**
 * Read a session row's owner and decide whether an identity is that owner.
 *
 * The owner is recorded on the session row through its polymorphic
 * `authenticatable` relation: a morph type and the owner's key. Reading those
 * two columns needs no query, which lets the refresh path load the owner
 * through the guard's own identity provider instead of the relation, and then
 * check the provider returned the exact owner.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class SessionOwnership
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Return the owner key stored on the session row (the owner's primary key),
     * or `null` when the row records none.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @return ?string
     */
    public static function ownerKey(EloquentSession&Model $session): ?string
    {
        return IdentifierCoercion::stringify($session->getAttribute($session->authenticatable()->getForeignKeyName()));
    }

    /**
     * Whether the session row records a non-human identity as its owner: its
     * morph type names a class, through the morph map or directly, that
     * implements `MachineIdentity`. The type column is read through the
     * relation of a blank instance, so a recorded type that names no class is
     * not instantiated.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @return bool
     */
    public static function isMachineOwned(EloquentSession&Model $session): bool
    {
        /** @var \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession $blank */
        $blank = $session->newInstance();
        $type  = $session->getAttribute($blank->authenticatable()->getMorphType());
        $class = is_string($type) ? Relation::getMorphedModel($type) ?? $type : null;

        return $class !== null && is_a($class, MachineIdentity::class, true);
    }

    /**
     * Whether the identity is the session's exact owner: an Eloquent model of
     * the session row's morph type whose key is the session row's owner key.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @return bool
     */
    public static function isOwner(EloquentSession&Model $session, Identity $identity): bool
    {
        $ownerKey = self::ownerKey($session);

        return $ownerKey !== null
            && $identity instanceof Model
            && $identity->getMorphClass()                         === $session->getAttribute($session->authenticatable()->getMorphType())
            && IdentifierCoercion::stringify($identity->getKey()) === $ownerKey;
    }

    /**
     * Whether the row stored under the key of the session given is that very
     * session: of the same generation (`SessionGeneration::isHeld()`) and
     * recording the same owner's morph type and key, read with no query. A
     * session that is not an Eloquent session records neither, so it is never
     * the stored one; nor is a key that holds no row.
     *
     * @formatter:off
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @param  (\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession)|null  $stored
     * @return bool
     *
     * @phpstan-assert-if-true !null $stored
     *
     * @formatter:on
     */
    public static function isSameSession(Session $session, (EloquentSession&Model)|null $stored): bool
    {
        return SessionGeneration::isHeld($session, $stored) && self::owner($session) === self::owner($stored);
    }

    /**
     * The owner's morph type and key the session records. The columns are named
     * by the relation of a blank instance, so the recorded type is never
     * instantiated.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @return array{0: ?string, 1: ?string}
     */
    private static function owner(EloquentSession&Model $session): array
    {
        /** @var \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession $blank */
        $blank = $session->newInstance();
        $owner = $blank->authenticatable();

        return [
            IdentifierCoercion::stringify($session->getAttribute($owner->getMorphType())),
            IdentifierCoercion::stringify($session->getAttribute($owner->getForeignKeyName())),
        ];
    }
}
