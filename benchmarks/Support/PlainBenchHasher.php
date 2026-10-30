<?php

declare(strict_types = 1);

namespace Benchmarks\Support;

use Illuminate\Contracts\Hashing\Hasher;

/**
 * A hasher that costs next to nothing, for the benchmarks that check a
 * password: bcrypt or Argon2 is tuned to take tens of milliseconds, which would
 * bury the package's own work on a sign-in. It is not a password hash and is
 * never used outside the benchmarks.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class PlainBenchHasher implements Hasher
{
    /** @var string Prefix of every value this hasher makes. */
    private const string PREFIX = 'plain$';

    /**
     * Describe the hashed value.
     *
     * @param  mixed  $hashedValue
     * @return array<string, mixed>
     */
    #[\Override]
    public function info(mixed $hashedValue): array
    {
        return ['algo' => 'plain', 'algoName' => 'plain', 'options' => []];
    }

    /**
     * Hash the value.
     *
     * @param  mixed  $value
     * @param  array<array-key, mixed>  $options
     * @return string
     */
    #[\Override]
    public function make(#[\SensitiveParameter] mixed $value, array $options = []): string
    {
        return self::PREFIX . hash('sha256', is_string($value) ? $value : '');
    }

    // phpcs:disable SineMacula.NamingConventions.BooleanMethodName.NotPredicate -- the name is the Hasher contract's

    /**
     * Whether the value hashes to the hashed value.
     *
     * @param  mixed  $value
     * @param  mixed  $hashedValue
     * @param  array<array-key, mixed>  $options
     * @return bool
     */
    #[\Override]
    public function check(#[\SensitiveParameter] mixed $value, mixed $hashedValue, array $options = []): bool
    {
        return is_string($hashedValue) && hash_equals($hashedValue, $this->make($value));
    }

    // phpcs:enable SineMacula.NamingConventions.BooleanMethodName.NotPredicate

    /**
     * Never: every value this hasher made is current.
     *
     * @param  mixed  $hashedValue
     * @param  array<array-key, mixed>  $options
     * @return bool
     */
    #[\Override]
    public function needsRehash(mixed $hashedValue, array $options = []): bool
    {
        return false;
    }
}
