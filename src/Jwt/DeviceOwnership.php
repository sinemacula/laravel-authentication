<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Jwt;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\Relation;
use SineMacula\Laravel\Authentication\Contracts\EloquentDevice;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\MachineIdentity;

/**
 * Read a device row's owner and decide whether an identity is that owner.
 *
 * The owner is recorded on the device row through its polymorphic
 * `authenticatable` relation: a morph type and the owner's key. Reading those
 * two columns needs no query, which lets the refresh path load the owner
 * through the guard's own identity provider instead of the relation, and then
 * check the provider returned the exact owner.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class DeviceOwnership
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Return the owner key stored on the device row (the owner's primary key),
     * or `null` when the row records none.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentDevice  $device
     * @return ?string
     */
    public static function ownerKey(EloquentDevice&Model $device): ?string
    {
        return IdentifierCoercion::stringify($device->getAttribute($device->authenticatable()->getForeignKeyName()));
    }

    /**
     * Whether the device row records a non-human identity as its owner: its
     * morph type names a class, through the morph map or directly, that
     * implements `MachineIdentity`. The type column is read through the
     * relation of a blank instance, so a recorded type that names no class is
     * not instantiated.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentDevice  $device
     * @return bool
     */
    public static function isMachineOwned(EloquentDevice&Model $device): bool
    {
        /** @var \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentDevice $blank */
        $blank = $device->newInstance();
        $type  = $device->getAttribute($blank->authenticatable()->getMorphType());
        $class = is_string($type) ? Relation::getMorphedModel($type) ?? $type : null;

        return $class !== null && is_a($class, MachineIdentity::class, true);
    }

    /**
     * Whether the identity is the device's exact owner: an Eloquent model of
     * the device row's morph type whose key is the device row's owner key.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentDevice  $device
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @return bool
     */
    public static function isOwner(EloquentDevice&Model $device, Identity $identity): bool
    {
        $ownerKey = self::ownerKey($device);

        return $ownerKey !== null
            && $identity instanceof Model
            && $identity->getMorphClass()                         === $device->getAttribute($device->authenticatable()->getMorphType())
            && IdentifierCoercion::stringify($identity->getKey()) === $ownerKey;
    }
}
