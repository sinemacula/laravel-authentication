<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Passkeys;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\IdentityProvider;
use SineMacula\Laravel\Authentication\Contracts\MachineIdentity;
use SineMacula\Laravel\Authentication\Models\Passkey;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;

/**
 * Who a passkey or a ceremony belongs to, recorded as devices record their
 * owner: the identity's morph class and its key as a string, so a passkey can
 * only be registered for, listed for and used by an Eloquent identity, and is
 * found again through the guard's provider only as that very model.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class PasskeyOwner
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * The identity as the owner of passkeys: an Eloquent identity that is not a
     * machine identity. A machine identity has no interactive sign-in, so it
     * holds no passkey (`InvalidArgumentException`); an identity that is not a
     * model cannot be recorded as an owner (`LogicException`).
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @return \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\Identity
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public static function of(Identity $identity): Identity&Model
    {
        if ($identity instanceof MachineIdentity) {
            throw new \InvalidArgumentException(sprintf('%s is a machine identity, which signs in with no passkey.', $identity::class));
        }

        if (!$identity instanceof Model) {
            throw new \LogicException(sprintf('Passkeys can only belong to an Eloquent identity; %s is not a model.', $identity::class));
        }

        return $identity;
    }

    /**
     * The recorded type and key of the owner, which must be saved: an identity
     * without a key cannot hold a passkey (`LogicException`).
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\Identity  $owner
     * @return array{0: string, 1: string}
     *
     * @throws \LogicException
     */
    public static function columns(Identity&Model $owner): array
    {
        $key = IdentifierCoercion::stringify($owner->getKey());

        if ($key === null) {
            throw new \LogicException(sprintf('%s must be saved before it can hold passkeys.', $owner::class));
        }

        return [$owner->getMorphClass(), $key];
    }

    /**
     * Whether the passkey records the owner.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\Identity  $owner
     * @param  \SineMacula\Laravel\Authentication\Models\Passkey  $passkey
     * @return bool
     */
    public static function owns(Identity&Model $owner, Passkey $passkey): bool
    {
        return $passkey->authenticatable_type === $owner->getMorphClass()
            && IdentifierCoercion::matches($owner->getKey(), $passkey->authenticatable_id);
    }

    /**
     * Load the passkey's owner through the guard's provider, when the provider
     * returns that very model, whether or not it is still active (the session
     * service decides activity).
     *
     * @param  \SineMacula\Laravel\Authentication\Models\Passkey  $passkey
     * @param  \SineMacula\Laravel\Authentication\Contracts\IdentityProvider  $provider
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Identity
     */
    public static function load(Passkey $passkey, IdentityProvider $provider): ?Identity
    {
        $identity = $provider->retrieveById($passkey->authenticatable_id);

        return $identity instanceof Identity && $identity instanceof Model && self::owns($identity, $passkey) ? $identity : null;
    }
}
