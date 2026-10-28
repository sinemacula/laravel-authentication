<?php

declare(strict_types = 1);

namespace Tests\Performance\Fixtures;

use Illuminate\Contracts\Auth\Authenticatable;
use SineMacula\Laravel\Authentication\Providers\ModelProvider;

/**
 * The `model` provider with a slow lookup, as a remote or heavily indexed user
 * store might be, counting each lookup: a found identity takes longer than a
 * miss, so a flow whose timing depended on the lookup would show it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class SlowModelProvider extends ModelProvider
{
    /** @var int How long a lookup that finds an identity takes, in microseconds. */
    public const int FOUND_MICROSECONDS = 60000;

    /** @var int Lookups made since the counter was reset. */
    public static int $lookups = 0;

    /**
     * Look the identity up, slowly when it is found.
     *
     * @param  array<array-key, mixed>  $credentials
     * @return ?\Illuminate\Contracts\Auth\Authenticatable
     */
    #[\Override]
    public function retrieveByCredentials(#[\SensitiveParameter] array $credentials): ?Authenticatable
    {
        self::$lookups++;

        $found = parent::retrieveByCredentials($credentials);

        if ($found !== null) {
            usleep(self::FOUND_MICROSECONDS);
        }

        return $found;
    }
}
