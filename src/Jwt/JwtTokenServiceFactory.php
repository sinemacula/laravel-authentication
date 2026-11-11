<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Jwt;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use Psr\Log\LoggerInterface;
use SineMacula\Laravel\Authentication\Config\IntegerSetting;

/**
 * Builds and keeps each guard's `JwtTokenService` from its `jwt` config layered
 * over the package's `authentication.jwt` values.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class JwtTokenServiceFactory
{
    /** @var int Largest accepted clock-skew leeway, in seconds. */
    private const int MAX_LEEWAY_SECONDS = 300;

    /** @var array<string, \SineMacula\Laravel\Authentication\Jwt\JwtTokenService> Memoised services keyed by guard name. */
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

        return new JwtTokenService(
            $this->buildKeyring($guardJwtConfig, $algorithm),
            $guard,
            $this->resolveLifetimes($guard, $guardJwtConfig),
            $this->resolveJwtInteger($guard, $guardJwtConfig, 'leeway_seconds', 0, self::MAX_LEEWAY_SECONDS),
            $this->resolveJwtRequiredString($guard, $guardJwtConfig, 'issuer'),
            $this->resolveJwtRequiredString($guard, $guardJwtConfig, 'audience'),
            $this->resolveOptionalLogger(),
        );
    }

    /**
     * Resolve the guard's `jwt` overrides, failing closed on a value that is
     * not an array or `null`.
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
            $this->resolveAbsoluteTtl($guard, $guardJwtConfig),
            $this->resolveJwtInteger($guard, $guardJwtConfig, 'refresh_grace_seconds', 0, TokenLifetimes::MAX_GRACE_SECONDS),
        );
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
     * Resolve the signing algorithm, preferring the per-guard override.
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
     * Resolve the active kid, preferring the per-guard override; an integer kid
     * resolves to its string form.
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
     * array; `JwtKeyring` validates the kids.
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
     * Resolve an integer JWT config value within its range, preferring the
     * per-guard override.
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
        $integer = IntegerSetting::parse($value);

        if ($integer === null || $integer < $min || $integer > $max) {

            $message = "JWT `{$key}` for guard [{$guard}] must be an integer from {$min} to {$max}:"
                . " set `authentication.jwt.{$key}` or the guard's `jwt.{$key}` override.";

            throw new InvalidJwtConfigurationException($message);
        }

        return $integer;
    }

    /**
     * Resolve the absolute session lifetime, preferring the per-guard override;
     * an explicit `null` means no absolute limit.
     *
     * @param  string  $guard
     * @param  array<string, mixed>  $guardJwtConfig
     * @return ?int
     *
     * @throws \SineMacula\Laravel\Authentication\Jwt\InvalidJwtConfigurationException
     */
    private function resolveAbsoluteTtl(string $guard, #[\SensitiveParameter] array $guardJwtConfig): ?int
    {
        $key     = 'refresh_absolute_ttl_minutes';
        $package = $this->config->get('authentication.jwt');
        $present = array_key_exists($key, $guardJwtConfig) || (is_array($package) && array_key_exists($key, $package));
        $value   = array_key_exists($key, $guardJwtConfig) ? $guardJwtConfig[$key] : $this->config->get("authentication.jwt.{$key}");
        $integer = IntegerSetting::parse($value);

        if ($present && $value === null) {
            return null;
        }

        if ($integer === null || $integer < TokenLifetimes::MIN_TTL_MINUTES || $integer > TokenLifetimes::MAX_REFRESH_TTL_MINUTES) {

            $message = "JWT `{$key}` for guard [{$guard}] must be null (no absolute limit) or an integer from"
                . ' ' . TokenLifetimes::MIN_TTL_MINUTES . ' to ' . TokenLifetimes::MAX_REFRESH_TTL_MINUTES
                . ": set `authentication.jwt.{$key}` or the guard's `jwt.{$key}` override.";

            throw new InvalidJwtConfigurationException($message);
        }

        return $integer;
    }

    /**
     * Resolve a required non-empty string JWT config value, preferring the
     * per-guard override.
     *
     * @param  string  $guard
     * @param  array<string, mixed>  $guardJwtConfig
     * @param  string  $key
     * @return string
     *
     * @throws \SineMacula\Laravel\Authentication\Jwt\InvalidJwtConfigurationException
     */
    private function resolveJwtRequiredString(string $guard, #[\SensitiveParameter] array $guardJwtConfig, string $key): string
    {
        $value = array_key_exists($key, $guardJwtConfig)
            ? $guardJwtConfig[$key]
            : $this->config->get("authentication.jwt.{$key}");

        if (!is_string($value) || $value === '') {

            $message = "JWT `{$key}` for guard [{$guard}] is required: set `authentication.jwt.{$key}`"
                . ' (AUTHENTICATION_JWT_' . strtoupper($key) . ") or the guard's `jwt.{$key}` override.";

            throw new InvalidJwtConfigurationException($message);
        }

        return $value;
    }

    /**
     * Resolve the container's PSR-3 logger, or `null` when none is bound.
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
