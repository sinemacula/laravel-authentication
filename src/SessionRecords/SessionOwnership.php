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
     * The owner key stored on the session row, or `null` when it records none.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @return ?string
     */
    public static function ownerKey(EloquentSession&Model $session): ?string
    {
        return IdentifierCoercion::stringify($session->getAttribute($session->authenticatable()->getForeignKeyName()));
    }

    /**
     * Whether the session row's owner type implements `MachineIdentity`.
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
     * Whether the identity is the session's exact owner.
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
     * session, by generation and owner.
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
     * The owner's morph type and key the session records.
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
