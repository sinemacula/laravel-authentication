<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\RateLimiting;

use Illuminate\Contracts\Config\Repository;
use SineMacula\Laravel\Authentication\RateLimiting\Enums\AttemptFlow;

/**
 * The keys the attempt limiter stores its counters under: HMAC-SHA256 digests,
 * keyed with a key derived from the application key (`app.key`).
 *
 * What a counter counts (an IP address, an identifier, an account's id) is
 * usually easy to enumerate, so a plain digest of it could be reversed by
 * anyone who reads the table, from a backup or a replica, say, by hashing every
 * candidate. A keyed digest cannot be recomputed without the application key,
 * and stays deterministic, so every server counts in the same row. Rotating the
 * application key starts every counter afresh.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class CounterKeys
{
    /** @var string Scope of the counter kept per account, under the identifier's limit. */
    private const string PER_ACCOUNT = 'per_account';

    /** @var string What the key derived from the application key is for, so it is used for nothing else. */
    private const string PURPOSE = 'sinemacula/laravel-authentication rate limit counters';

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     */
    public function __construct(

        /** Configuration the application key is read from on every call. */
        private Repository $config,
    ) {}

    /**
     * The key of a guard's counter for a flow, a scope and a canonical value
     * (an identifier or an IP address).
     *
     * @param  string  $guard
     * @param  \SineMacula\Laravel\Authentication\RateLimiting\Enums\AttemptFlow  $flow
     * @param  string  $scope
     * @param  string  $value
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    public function counter(string $guard, AttemptFlow $flow, string $scope, #[\SensitiveParameter] string $value): string
    {
        return $this->digest([$guard, $flow->value, $scope, $value]);
    }

    /**
     * The key of an account's counter for a flow, without the guard, so every
     * guard counts the account's attempts in one counter.
     *
     * @param  \SineMacula\Laravel\Authentication\RateLimiting\Enums\AttemptFlow  $flow
     * @param  string  $account
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    public function account(AttemptFlow $flow, string $account): string
    {
        return $this->digest([$flow->value, self::PER_ACCOUNT, $account]);
    }

    /**
     * The keyed digest of the parts, as 64 hexadecimal characters.
     *
     * @param  list<string>  $parts
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    private function digest(#[\SensitiveParameter] array $parts): string
    {
        return hash_hmac('sha256', implode("\0", $parts), $this->secret());
    }

    /**
     * The key the digests are made with, derived from the application key.
     *
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    private function secret(): string
    {
        $key = $this->config->get('app.key');

        if (!is_string($key) || $key === '') {
            throw new \InvalidArgumentException('The attempt limiter keys its counters with the application key; set `app.key`.');
        }

        return hash_hmac('sha256', self::PURPOSE, $key, true);
    }
}
