<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\RateLimiting;

use Illuminate\Config\Repository as ConfigRepository;
use SineMacula\Laravel\Authentication\RateLimiting\Enums\AttemptFlow;

/**
 * Each guard's limits on each flow: its `rate_limits` block over the package
 * defaults in `authentication.rate_limits`.
 *
 * Every flow has a `per_identifier` and a `per_ip` limit, each either
 * `['max' => int, 'decay_seconds' => int]` or `null` (off). A request for
 * passkey sign-in options names no identifier, so its `per_identifier` limit
 * must be `null`: one that could never apply fails closed rather than seeming
 * to limit something. A guard's flow block that is present wins for the scopes
 * it sets, `null` included, and a flow block of `null` turns the flow's limits
 * off. Nothing falls back to a literal: a scope missing at both levels, a
 * malformed value, or an unknown key fails closed with an
 * `InvalidArgumentException` naming the guard and the key. The configuration is
 * read on every call.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class AttemptLimits
{
    /** @var string Scope counting attempts per identifier. */
    public const string PER_IDENTIFIER = 'per_identifier';

    /** @var string Scope counting attempts per IP address. */
    public const string PER_IP = 'per_ip';

    /** @var list<string> Keys of the package `rate_limits` block besides its flows. */
    private const array STORAGE_KEYS = ['table', 'connection'];

    /**
     * Constructor.
     *
     * @param  \Illuminate\Config\Repository  $config
     */
    public function __construct(

        /** Configuration holding the guards and the package defaults. */
        private ConfigRepository $config,
    ) {}

    /**
     * The guard's limits on the flow, by scope; `null` where a scope is off.
     *
     * @param  string  $guard
     * @param  \SineMacula\Laravel\Authentication\RateLimiting\Enums\AttemptFlow  $flow
     * @return array{per_identifier: ?\SineMacula\Laravel\Authentication\RateLimiting\AttemptLimit, per_ip: ?\SineMacula\Laravel\Authentication\RateLimiting\AttemptLimit}
     *
     * @throws \InvalidArgumentException
     */
    public function for(string $guard, AttemptFlow $flow): array
    {
        $overrides = $this->flowBlock($guard, $flow, $this->guardBlock($guard), 'the guard\'s `rate_limits`');
        $defaults  = $this->flowBlock($guard, $flow, $this->packageBlock($guard), '`authentication.rate_limits`');

        return [
            self::PER_IDENTIFIER => $this->limit($guard, $flow, self::PER_IDENTIFIER, $overrides, $defaults),
            self::PER_IP         => $this->limit($guard, $flow, self::PER_IP, $overrides, $defaults),
        ];
    }

    /**
     * Resolve one scope's limit: the guard's value when its flow block has the
     * scope, otherwise the package value.
     *
     * @param  string  $guard
     * @param  \SineMacula\Laravel\Authentication\RateLimiting\Enums\AttemptFlow  $flow
     * @param  string  $scope
     * @param  ?array<array-key, mixed>  $overrides
     * @param  ?array<array-key, mixed>  $defaults
     * @return ?\SineMacula\Laravel\Authentication\RateLimiting\AttemptLimit
     *
     * @throws \InvalidArgumentException
     */
    private function limit(string $guard, AttemptFlow $flow, string $scope, ?array $overrides, ?array $defaults): ?AttemptLimit
    {
        $source = $overrides === null || array_key_exists($scope, $overrides) ? $overrides : $defaults;

        if ($source === null) {
            return null;
        }

        if (!array_key_exists($scope, $source)) {
            throw new \InvalidArgumentException(self::message($guard, $flow, $scope));
        }

        if ($source[$scope] === null) {
            return null;
        }

        if ($scope === self::PER_IDENTIFIER && $flow === AttemptFlow::PASSKEY_OPTIONS) {
            $message = sprintf('Rate limit `%s.%s` for guard [%s] must be null: a request for passkey sign-in options', $flow->value, $scope, $guard);

            throw new \InvalidArgumentException($message . ' names no identifier, so only `per_ip` limits it.');
        }

        return self::fromValue($guard, $flow, $scope, $source[$scope]);
    }

    /**
     * Build a limit from its configured value: exactly a `max` and a
     * `decay_seconds`, each an integer or the canonical string form of one,
     * within range.
     *
     * @param  string  $guard
     * @param  \SineMacula\Laravel\Authentication\RateLimiting\Enums\AttemptFlow  $flow
     * @param  string  $scope
     * @param  mixed  $value
     * @return \SineMacula\Laravel\Authentication\RateLimiting\AttemptLimit
     *
     * @throws \InvalidArgumentException
     */
    private static function fromValue(string $guard, AttemptFlow $flow, string $scope, mixed $value): AttemptLimit
    {
        $max   = is_array($value) && count($value) === 2 ? self::toInteger($value['max'] ?? null) : null;
        $decay = is_array($value) ? self::toInteger($value['decay_seconds'] ?? null) : null;

        if ($max === null || $decay === null) {
            throw new \InvalidArgumentException(self::message($guard, $flow, $scope));
        }

        try {
            return new AttemptLimit($max, $decay);
        } catch (\InvalidArgumentException) {
            throw new \InvalidArgumentException(self::message($guard, $flow, $scope));
        }
    }

    /**
     * Read the flow's block from a `rate_limits` block: `null` when the flow is
     * turned off, an empty array when the block does not mention it.
     *
     * @param  string  $guard
     * @param  \SineMacula\Laravel\Authentication\RateLimiting\Enums\AttemptFlow  $flow
     * @param  array<array-key, mixed>  $block
     * @param  string  $name
     * @return ?array<array-key, mixed>
     *
     * @throws \InvalidArgumentException
     */
    private function flowBlock(string $guard, AttemptFlow $flow, array $block, string $name): ?array
    {
        if (!array_key_exists($flow->value, $block)) {
            return [];
        }

        $flowBlock = $block[$flow->value];

        if ($flowBlock === null) {
            return null;
        }

        if (!is_array($flowBlock)) {
            throw new \InvalidArgumentException("Rate limits for guard [{$guard}]: {$name} `{$flow->value}` must be an array or null.");
        }

        self::assertKnownKeys($guard, $flowBlock, [self::PER_IDENTIFIER, self::PER_IP], "{$name} `{$flow->value}`");

        return $flowBlock;
    }

    /**
     * The guard's `rate_limits` block; `null` or absent means no overrides.
     *
     * @param  string  $guard
     * @return array<array-key, mixed>
     *
     * @throws \InvalidArgumentException
     */
    private function guardBlock(string $guard): array
    {
        $config = $this->config->get("auth.guards.{$guard}");

        if (!is_array($config)) {
            throw new \InvalidArgumentException("Auth guard [{$guard}] is not configured.");
        }

        $block = $config['rate_limits'] ?? [];

        if (!is_array($block)) {
            throw new \InvalidArgumentException("Rate limits for guard [{$guard}]: the guard's `rate_limits` must be an array.");
        }

        self::assertKnownKeys($guard, $block, self::flowNames(), 'the guard\'s `rate_limits`');

        return $block;
    }

    /**
     * The package `rate_limits` block.
     *
     * @param  string  $guard
     * @return array<array-key, mixed>
     *
     * @throws \InvalidArgumentException
     */
    private function packageBlock(string $guard): array
    {
        $block = $this->config->get('authentication.rate_limits');

        if (!is_array($block)) {
            throw new \InvalidArgumentException("Rate limits for guard [{$guard}]: `authentication.rate_limits` must be an array.");
        }

        self::assertKnownKeys($guard, $block, [...self::STORAGE_KEYS, ...self::flowNames()], '`authentication.rate_limits`');

        return $block;
    }

    /**
     * The names of every flow, as their blocks are keyed.
     *
     * @return list<string>
     */
    private static function flowNames(): array
    {
        return array_map(static fn (AttemptFlow $flow): string => $flow->value, AttemptFlow::cases());
    }

    /**
     * Reject a block holding a key outside the known ones.
     *
     * @param  string  $guard
     * @param  array<array-key, mixed>  $block
     * @param  list<string>  $known
     * @param  string  $name
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    private static function assertKnownKeys(string $guard, array $block, array $known, string $name): void
    {
        foreach (array_keys($block) as $key) {
            if (!in_array($key, $known, true)) {
                throw new \InvalidArgumentException("Rate limits for guard [{$guard}]: {$name} has an unknown key `{$key}`.");
            }
        }
    }

    /**
     * Read an integer, or the canonical string form of one, as an integer.
     *
     * @param  mixed  $value
     * @return ?int
     */
    private static function toInteger(mixed $value): ?int
    {
        if (is_int($value)) {
            return $value;
        }

        return is_string($value) && (string) (int) $value === $value ? (int) $value : null;
    }

    /**
     * Build the message for a limit that is missing or malformed.
     *
     * @param  string  $guard
     * @param  \SineMacula\Laravel\Authentication\RateLimiting\Enums\AttemptFlow  $flow
     * @param  string  $scope
     * @return string
     */
    private static function message(string $guard, AttemptFlow $flow, string $scope): string
    {
        $key = "{$flow->value}.{$scope}";

        return "Rate limit `{$key}` for guard [{$guard}] must be null or ['max' => an integer of at least 1,"
            . ' \'decay_seconds\' => an integer from 1 to ' . AttemptLimit::MAX_DECAY_SECONDS . ']:'
            . " set `authentication.rate_limits.{$key}` or the guard's `rate_limits.{$key}` override.";
    }
}
