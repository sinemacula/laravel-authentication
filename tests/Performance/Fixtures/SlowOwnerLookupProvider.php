<?php

declare(strict_types = 1);

namespace Tests\Performance\Fixtures;

use Illuminate\Contracts\Auth\Authenticatable;
use SineMacula\Laravel\Authentication\Providers\ModelProvider;

/**
 * An identity provider whose lookup by id takes a known time, as a remote or
 * heavily scoped user store might, and counts its lookups, so the passkey
 * timing tests can show a refused sign-in takes the timebox whether or not an
 * owner was looked up.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class SlowOwnerLookupProvider extends ModelProvider
{
    /** @var int How long a lookup by id takes, in microseconds. */
    public const int LOOKUP_MICROSECONDS = 60000;

    /** @var int Lookups by id made since the provider was built. */
    public static int $lookups = 0;

    /**
     * Look the identity up by id, slowly.
     *
     * @param  mixed  $identifier
     * @return ?\Illuminate\Contracts\Auth\Authenticatable
     */
    #[\Override]
    public function retrieveById(mixed $identifier): ?Authenticatable
    {
        self::$lookups++;

        usleep(self::LOOKUP_MICROSECONDS);

        return parent::retrieveById($identifier);
    }
}
