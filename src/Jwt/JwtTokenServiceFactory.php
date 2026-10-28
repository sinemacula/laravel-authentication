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
 * `authentication.jwt.*` defaults so issuance and verification share the same
 * guard-local signing material and claim policy.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class JwtTokenServiceFactory
{
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
        $guardConfig = $this->guardConfig($guard);

        $guardJwtConfig = is_array($guardConfig['jwt'] ?? null) ? $guardConfig['jwt'] : [];
        $algorithm      = $this->resolveJwtString($guardJwtConfig, 'algorithm', 'HS256');

        return new JwtTokenService(
            $this->buildKeyring($guardJwtConfig, $algorithm),
            $guard,
            $this->resolveJwtInteger($guardJwtConfig, 'access_ttl_minutes', 15),
            $this->resolveJwtInteger($guardJwtConfig, 'refresh_ttl_minutes', 60 * 24 * 30),
            $this->resolveJwtInteger($guardJwtConfig, 'leeway_seconds', 30),
            $this->resolveJwtNullableString($guardJwtConfig, 'issuer'),
            $this->resolveJwtNullableString($guardJwtConfig, 'audience'),
            $this->resolveOptionalLogger(),
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
     * Resolve a string JWT config value, preferring the per-guard override and
     * falling back to the package-wide default.
     *
     * @param  array<string, mixed>  $guardJwtConfig
     * @param  string  $key
     * @param  string  $default
     * @return string
     */
    private function resolveJwtString(#[\SensitiveParameter] array $guardJwtConfig, string $key, string $default): string
    {
        if (isset($guardJwtConfig[$key]) && is_string($guardJwtConfig[$key])) {
            return $guardJwtConfig[$key];
        }

        return $this->config->string("authentication.jwt.{$key}", $default);
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
     * Resolve an integer JWT config value, preferring the per-guard override
     * and falling back to the package-wide default.
     *
     * @param  array<string, mixed>  $guardJwtConfig
     * @param  string  $key
     * @param  int  $default
     * @return int
     */
    private function resolveJwtInteger(#[\SensitiveParameter] array $guardJwtConfig, string $key, int $default): int
    {
        if (isset($guardJwtConfig[$key]) && is_int($guardJwtConfig[$key])) {
            return $guardJwtConfig[$key];
        }

        return $this->config->integer("authentication.jwt.{$key}", $default);
    }

    /**
     * Resolve a nullable string JWT config value (`issuer` / `audience`),
     * preferring the per-guard override and falling back to the package
     * default. Empty strings are normalised to `null`.
     *
     * @param  array<string, mixed>  $guardJwtConfig
     * @param  string  $key
     * @return ?string
     */
    private function resolveJwtNullableString(#[\SensitiveParameter] array $guardJwtConfig, string $key): ?string
    {
        if (array_key_exists($key, $guardJwtConfig)) {

            $value = $guardJwtConfig[$key];

            return is_string($value) && $value !== '' ? $value : null;
        }

        /** @var ?string $value */
        $value = $this->config->get("authentication.jwt.{$key}");

        return is_string($value) && $value !== '' ? $value : null;
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
