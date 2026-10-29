<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Jwt;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use Psr\Log\LoggerInterface;

/**
 * Guard-scoped JWT token-service factory.
 *
 * Resolves `auth.guards.<name>.jwt` config layered over the package-wide
 * `authentication.jwt.*` values so issuance and verification share the same
 * guard-local signing material, claim policy, and lifetimes, plus the guard's
 * own lifetimes per principal type (`jwt.by_principal_type`).
 *
 * The package values, defaults included, come only from the merged
 * `config/authentication.php`; nothing here falls back to a literal. A value
 * missing at both levels, of the wrong type, or out of range fails closed with
 * an `InvalidJwtConfigurationException`, at either level: a malformed guard
 * override is never ignored in favour of the package value. Only `issuer` and
 * `audience` may resolve to `null`, which turns that claim check off.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class JwtTokenServiceFactory
{
    /** @var int Largest accepted clock-skew leeway, in seconds. */
    private const int MAX_LEEWAY_SECONDS = 300;

    /** @var array<string, int> Lifetime keys a principal type may override, with the largest value of each. */
    private const array PRINCIPAL_TYPE_KEYS = [
        'access_ttl_minutes'           => TokenLifetimes::MAX_ACCESS_TTL_MINUTES,
        'refresh_idle_ttl_minutes'     => TokenLifetimes::MAX_REFRESH_TTL_MINUTES,
        'refresh_absolute_ttl_minutes' => TokenLifetimes::MAX_REFRESH_TTL_MINUTES,
    ];

    /** @var array<string, \SineMacula\Laravel\Authentication\Jwt\JwtTokenService> Memoized services keyed by guard name. */
    private array $resolved = [];

    /**
     * Constructor.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @param  \Illuminate\Config\Repository  $config
     */
    public function __construct(

        /** @var \Illuminate\Foundation\Application */
        private readonly Application $app,

        /** @var \Illuminate\Config\Repository */
        private readonly ConfigRepository $config,
    ) {}

    /**
     * Build a `JwtTokenService` for the named guard.
     *
     * @param  string  $guard
     * @return \SineMacula\Laravel\Authentication\Jwt\JwtTokenService
     *
     * @throws \InvalidArgumentException
     */
    public function forGuard(string $guard): JwtTokenService
    {
        if ($guard === '') {
            throw new \InvalidArgumentException('JWT token service resolution requires a non-empty guard name.');
        }

        return $this->resolved[$guard] ??= $this->buildForGuard($guard);
    }

    /**
     * Construct a fresh `JwtTokenService` for the named guard.
     *
     * @param  string  $guard
     * @return \SineMacula\Laravel\Authentication\Jwt\JwtTokenService
     *
     * @throws \InvalidArgumentException
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \SineMacula\Laravel\Authentication\Jwt\InvalidJwtConfigurationException
     */
    private function buildForGuard(string $guard): JwtTokenService
    {
        $guardJwtConfig = $this->guardJwtConfig($guard);
        $algorithm      = $this->resolveAlgorithm($guard, $guardJwtConfig);
        $lifetimes      = $this->resolveLifetimes($guard, $guardJwtConfig);

        return new JwtTokenService(
            $this->buildKeyring($guardJwtConfig, $algorithm),
            $guard,
            $lifetimes,
            $this->resolveJwtInteger($guard, $guardJwtConfig, 'leeway_seconds', 0, self::MAX_LEEWAY_SECONDS),
            $this->resolveJwtNullableString($guard, $guardJwtConfig, 'issuer'),
            $this->resolveJwtNullableString($guard, $guardJwtConfig, 'audience'),
            $this->resolveOptionalLogger(),
            $this->resolvePrincipalTypeLifetimes($guard, $guardJwtConfig, $lifetimes),
        );
    }

    /**
     * Resolve the guard's `jwt` overrides: none when the guard has no `jwt`
     * entry or sets it to `null`. Any other value that is not an array fails
     * closed rather than silently dropping the guard's overrides.
     *
     * @param  string  $guard
     * @return array<string, mixed>
     *
     * @throws \SineMacula\Laravel\Authentication\Jwt\InvalidJwtConfigurationException
     */
    private function guardJwtConfig(string $guard): array
    {
        $overrides = $this->guardConfig($guard)['jwt'] ?? [];

        if (!is_array($overrides)) {
            throw new InvalidJwtConfigurationException("Auth guard [{$guard}] `jwt` overrides must be an array.");
        }

        /** @var array<string, mixed> $overrides */
        return $overrides;
    }

    /**
     * Resolve the guard's token and session lifetimes and its refresh grace
     * window.
     *
     * @param  string  $guard
     * @param  array<string, mixed>  $guardJwtConfig
     * @return \SineMacula\Laravel\Authentication\Jwt\TokenLifetimes
     *
     * @throws \SineMacula\Laravel\Authentication\Jwt\InvalidJwtConfigurationException
     */
    private function resolveLifetimes(string $guard, #[\SensitiveParameter] array $guardJwtConfig): TokenLifetimes
    {
        return new TokenLifetimes(
            $this->resolveJwtInteger($guard, $guardJwtConfig, 'access_ttl_minutes', TokenLifetimes::MIN_TTL_MINUTES, TokenLifetimes::MAX_ACCESS_TTL_MINUTES),
            $this->resolveJwtInteger($guard, $guardJwtConfig, 'refresh_idle_ttl_minutes', TokenLifetimes::MIN_TTL_MINUTES, TokenLifetimes::MAX_REFRESH_TTL_MINUTES),
            $this->resolveJwtInteger($guard, $guardJwtConfig, 'refresh_absolute_ttl_minutes', TokenLifetimes::MIN_TTL_MINUTES, TokenLifetimes::MAX_REFRESH_TTL_MINUTES),
            $this->resolveJwtInteger($guard, $guardJwtConfig, 'refresh_grace_seconds', 0, TokenLifetimes::MAX_GRACE_SECONDS),
        );
    }

    /**
     * Resolve the guard's lifetimes per principal type from its
     * `jwt.by_principal_type` map: for each type, any of the access, idle and
     * absolute lifetimes, each falling back to the guard's own. The grace
     * window stays the guard's, since a refresh judges grace before it knows
     * the principal.
     *
     * The map is per guard only. `null` or absent means none; anything else
     * that is not a map of non-empty type names to arrays of known keys with
     * integers in range fails closed.
     *
     * @param  string  $guard
     * @param  array<string, mixed>  $guardJwtConfig
     * @param  \SineMacula\Laravel\Authentication\Jwt\TokenLifetimes  $lifetimes
     * @return array<string, \SineMacula\Laravel\Authentication\Jwt\TokenLifetimes>
     *
     * @throws \SineMacula\Laravel\Authentication\Jwt\InvalidJwtConfigurationException
     */
    private function resolvePrincipalTypeLifetimes(string $guard, #[\SensitiveParameter] array $guardJwtConfig, TokenLifetimes $lifetimes): array
    {
        $map = $guardJwtConfig['by_principal_type'] ?? [];

        if (!is_array($map)) {
            throw new InvalidJwtConfigurationException("Auth guard [{$guard}] `jwt.by_principal_type` must be an array keyed by principal type.");
        }

        $resolved = [];

        foreach ($map as $type => $overrides) {

            if (!is_string($type) || $type === '' || !is_array($overrides)) {
                throw new InvalidJwtConfigurationException("Auth guard [{$guard}] `jwt.by_principal_type` must map each principal type name to an array of lifetimes.");
            }

            self::assertPrincipalTypeKeys($guard, $type, $overrides);

            $resolved[$type] = new TokenLifetimes(
                $this->resolvePrincipalTypeInteger($guard, $type, $overrides, 'access_ttl_minutes', $lifetimes->accessTtlMinutes),
                $this->resolvePrincipalTypeInteger($guard, $type, $overrides, 'refresh_idle_ttl_minutes', $lifetimes->refreshIdleTtlMinutes),
                $this->resolvePrincipalTypeInteger($guard, $type, $overrides, 'refresh_absolute_ttl_minutes', $lifetimes->refreshAbsoluteTtlMinutes),
                $lifetimes->refreshGraceSeconds,
            );
        }

        return $resolved;
    }

    /**
     * Reject a principal type's lifetimes that set a key other than the access,
     * idle and absolute lifetimes, rather than ignore it.
     *
     * @param  string  $guard
     * @param  string  $type
     * @param  array<array-key, mixed>  $overrides
     * @return void
     *
     * @throws \SineMacula\Laravel\Authentication\Jwt\InvalidJwtConfigurationException
     */
    private static function assertPrincipalTypeKeys(string $guard, string $type, array $overrides): void
    {
        $unknown = array_diff(array_keys($overrides), array_keys(self::PRINCIPAL_TYPE_KEYS));

        if ($unknown === []) {
            return;
        }

        $message = "Auth guard [{$guard}] `jwt.by_principal_type.{$type}` may set only `"
            . implode('`, `', array_keys(self::PRINCIPAL_TYPE_KEYS))
            . '`, not `' . implode('`, `', $unknown) . '`.';

        throw new InvalidJwtConfigurationException($message);
    }

    /**
     * Resolve one lifetime of a principal type: its override when present and
     * not `null`, otherwise the guard's value. An override must be an integer
     * or canonical digit string within the key's range.
     *
     * @param  string  $guard
     * @param  string  $type
     * @param  array<array-key, mixed>  $overrides
     * @param  string  $key
     * @param  int  $fallback
     * @return int
     *
     * @throws \SineMacula\Laravel\Authentication\Jwt\InvalidJwtConfigurationException
     */
    private function resolvePrincipalTypeInteger(string $guard, string $type, array $overrides, string $key, int $fallback): int
    {
        if (($overrides[$key] ?? null) === null) {
            return $fallback;
        }

        $max     = self::PRINCIPAL_TYPE_KEYS[$key];
        $integer = self::toInteger($overrides[$key]);

        if ($integer === null || $integer < TokenLifetimes::MIN_TTL_MINUTES || $integer > $max) {

            $message = "Auth guard [{$guard}] `jwt.by_principal_type.{$type}.{$key}` must be an integer from "
                . TokenLifetimes::MIN_TTL_MINUTES . " to {$max}.";

            throw new InvalidJwtConfigurationException($message);
        }

        return $integer;
    }

    /**
     * Resolve and validate the guard config block.
     *
     * @param  string  $guard
     * @return array<string, mixed>
     *
     * @throws \InvalidArgumentException
     */
    private function guardConfig(string $guard): array
    {
        $guardConfig = $this->config->get("auth.guards.{$guard}");

        if (!is_array($guardConfig)) {
            throw new \InvalidArgumentException("Auth guard [{$guard}] is not configured.");
        }

        if (($guardConfig['driver'] ?? null) !== 'jwt') {
            throw new \InvalidArgumentException("Auth guard [{$guard}] does not use the jwt driver.");
        }

        return $guardConfig;
    }

    /**
     * Resolve the signing algorithm: a per-guard override that is present and
     * not `null` wins, otherwise the package value. There is no literal
     * default, and an override that is not a string fails closed rather than
     * falling back to the package algorithm.
     *
     * @param  string  $guard
     * @param  array<string, mixed>  $guardJwtConfig
     * @return string
     *
     * @throws \SineMacula\Laravel\Authentication\Jwt\InvalidJwtConfigurationException
     */
    private function resolveAlgorithm(string $guard, #[\SensitiveParameter] array $guardJwtConfig): string
    {
        $algorithm = $guardJwtConfig['algorithm'] ?? $this->config->get('authentication.jwt.algorithm');

        if (!is_string($algorithm)) {

            $message = "JWT `algorithm` for guard [{$guard}] is missing or not a string: set"
                . ' `authentication.jwt.algorithm` or the guard\'s `jwt.algorithm` override.';

            throw new InvalidJwtConfigurationException($message);
        }

        return $algorithm;
    }

    /**
     * Build a `JwtKeyring` from the `keys` map and `active_kid`, preferring the
     * per-guard override of each and falling back to the package-wide defaults.
     *
     * @param  array<string, mixed>  $guardJwtConfig
     * @param  string  $algorithm
     * @return \SineMacula\Laravel\Authentication\Jwt\JwtKeyring
     *
     * @throws \SineMacula\Laravel\Authentication\Jwt\InvalidJwtConfigurationException
     */
    private function buildKeyring(#[\SensitiveParameter] array $guardJwtConfig, string $algorithm): JwtKeyring
    {
        $rawKeys = $guardJwtConfig['keys'] ?? $this->config->get('authentication.jwt.keys');

        if (!is_array($rawKeys)) {

            $message = 'JWT keys must be a kid -> secret map. Set'
                . ' `authentication.jwt.keys` (or the guard\'s `jwt.keys`'
                . ' override) to an array of at least one entry.';

            throw new InvalidJwtConfigurationException($message);
        }

        return JwtKeyring::fromKeyMap(
            $this->coerceKeysConfig($rawKeys),
            $this->resolveActiveKid($guardJwtConfig),
            $algorithm,
        );
    }

    /**
     * Resolve the active kid, preferring the per-guard override and falling
     * back to the package-wide default.
     *
     * A guard override that is absent or `null` falls back to the package-wide
     * kid. A purely numeric kid written as an integer (e.g.
     * `'active_kid' => 2026`) resolves to its string form, matching how
     * `JwtKeyring` looks up numeric kids. Any other non-string value, at either
     * level, fails closed instead of falling back.
     *
     * @param  array<string, mixed>  $guardJwtConfig
     * @return string
     *
     * @throws \SineMacula\Laravel\Authentication\Jwt\InvalidJwtConfigurationException
     */
    private function resolveActiveKid(#[\SensitiveParameter] array $guardJwtConfig): string
    {
        $activeKid = $guardJwtConfig['active_kid'] ?? $this->config->get('authentication.jwt.active_kid');

        if (is_int($activeKid)) {
            return (string) $activeKid;
        }

        if (!is_string($activeKid)) {

            $message = 'JWT active kid is missing or not a string or integer.'
                . ' Set `authentication.jwt.active_kid` (or the guard\'s'
                . ' `jwt.active_kid` override) to a kid in the key map.';

            throw new InvalidJwtConfigurationException($message);
        }

        return $activeKid;
    }

    /**
     * Validate the raw JWT key map and return a strictly-typed `kid -> secret`
     * array.
     *
     * Kids are not checked here: PHP stores a purely numeric kid such as
     * `'2026'` as an integer array key, which `JwtKeyring` accepts and looks up
     * by its string form, so the keyring is the single place kids are
     * validated.
     *
     * @param  array<array-key, mixed>  $rawKeys
     * @return array<array-key, string>
     *
     * @throws \SineMacula\Laravel\Authentication\Jwt\InvalidJwtConfigurationException
     */
    private function coerceKeysConfig(#[\SensitiveParameter] array $rawKeys): array
    {
        $coerced = [];

        foreach ($rawKeys as $kid => $material) {

            if (!is_string($material)) {

                $message = "JWT key '{$kid}' in `authentication.jwt.keys`"
                    . ' is not a string. Every kid must map to a non-empty string'
                    . ' secret - check the env var backing this entry is set.';

                throw new InvalidJwtConfigurationException($message);
            }

            $coerced[$kid] = $material;
        }

        return $coerced;
    }

    /**
     * Resolve an integer JWT config value: a per-guard override that is present
     * and not `null` wins, otherwise the package value.
     *
     * The value must be an integer, or a string of digits with no padding or
     * fraction (what `env()` returns), within the key's range. Anything else,
     * including a value missing at both levels, fails closed rather than
     * falling back.
     *
     * @param  string  $guard
     * @param  array<string, mixed>  $guardJwtConfig
     * @param  string  $key
     * @param  int  $min
     * @param  int  $max
     * @return int
     *
     * @throws \SineMacula\Laravel\Authentication\Jwt\InvalidJwtConfigurationException
     */
    private function resolveJwtInteger(string $guard, #[\SensitiveParameter] array $guardJwtConfig, string $key, int $min, int $max): int
    {
        $value   = $guardJwtConfig[$key] ?? $this->config->get("authentication.jwt.{$key}");
        $integer = self::toInteger($value);

        if ($integer === null || $integer < $min || $integer > $max) {

            $message = "JWT `{$key}` for guard [{$guard}] must be an integer from {$min} to {$max}:"
                . " set `authentication.jwt.{$key}` or the guard's `jwt.{$key}` override.";

            throw new InvalidJwtConfigurationException($message);
        }

        return $integer;
    }

    /**
     * Read an integer, or the canonical string form of one (no padding,
     * fraction, or leading zero), as an integer. A signed value is read as
     * negative, which every key's range rejects.
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
     * Resolve a nullable string JWT config value (`issuer` / `audience`): a
     * per-guard override that is present wins, `null` included, so a guard can
     * turn off a check the package value sets; otherwise the package value. An
     * empty string is normalised to `null`. Any other type, at either level,
     * fails closed: read as `null`, it would silently turn the check off.
     *
     * @param  string  $guard
     * @param  array<string, mixed>  $guardJwtConfig
     * @param  string  $key
     * @return ?string
     *
     * @throws \SineMacula\Laravel\Authentication\Jwt\InvalidJwtConfigurationException
     */
    private function resolveJwtNullableString(string $guard, #[\SensitiveParameter] array $guardJwtConfig, string $key): ?string
    {
        $value = array_key_exists($key, $guardJwtConfig)
            ? $guardJwtConfig[$key]
            : $this->config->get("authentication.jwt.{$key}");

        if ($value !== null && !is_string($value)) {

            $message = "JWT `{$key}` for guard [{$guard}] must be a string or null:"
                . " set `authentication.jwt.{$key}` or the guard's `jwt.{$key}` override.";

            throw new InvalidJwtConfigurationException($message);
        }

        return $value === '' ? null : $value;
    }

    /**
     * Resolve the container's PSR-3 logger if bound, otherwise return `null` so
     * the JWT service falls back to its `NullLogger`.
     *
     * @return ?\Psr\Log\LoggerInterface
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function resolveOptionalLogger(): ?LoggerInterface
    {
        if (!$this->app->bound(LoggerInterface::class)) {
            return null;
        }

        return $this->app->make(LoggerInterface::class);
    }
}
