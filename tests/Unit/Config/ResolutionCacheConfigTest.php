<?php

declare(strict_types = 1);

namespace Tests\Unit\Config;

use Illuminate\Config\Repository as ConfigRepository;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Config\ResolutionCacheConfig;

/**
 * Unit tests for the ResolutionCacheConfig runtime configuration resolver.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ResolutionCacheConfig::class)]
final class ResolutionCacheConfigTest extends TestCase
{
    /**
     * `store()` returns null when no store is configured.
     *
     * @return void
     */
    public function testStoreReturnsNullWhenNotConfigured(): void
    {
        $config = $this->makeConfig([]);

        self::assertNull($config->store());
    }

    /**
     * `store()` returns null when the configured store is an empty string.
     *
     * @return void
     */
    public function testStoreReturnsNullWhenConfiguredAsEmptyString(): void
    {
        $config = $this->makeConfig([
            'authentication.resolution_cache.store' => '',
        ]);

        self::assertNull($config->store());
    }

    /**
     * `store()` returns the configured store name when set.
     *
     * @return void
     */
    public function testStoreReturnsConfiguredStoreName(): void
    {
        $config = $this->makeConfig([
            'authentication.resolution_cache.store' => 'redis',
        ]);

        self::assertSame('redis', $config->store());
    }

    /**
     * `store()` returns null when the config repository throws.
     *
     * @return void
     */
    public function testStoreReturnsNullWhenConfigThrows(): void
    {
        $config = $this->makeThrowingConfig();

        self::assertNull($config->store());
    }

    /**
     * `jwtIdentityTtlSeconds()` returns the configured TTL.
     *
     * @return void
     */
    public function testJwtIdentityTtlSecondsReturnsConfiguredValue(): void
    {
        $config = $this->makeConfig([
            'authentication.resolution_cache.jwt.identity_ttl_seconds' => 30,
        ]);

        self::assertSame(30, $config->jwtIdentityTtlSeconds());
    }

    /**
     * `jwtIdentityTtlSeconds()` returns the default when not configured.
     *
     * @return void
     */
    public function testJwtIdentityTtlSecondsReturnsDefaultWhenNotConfigured(): void
    {
        $config = $this->makeConfig([]);

        self::assertSame(
            ResolutionCacheConfig::DEFAULT_JWT_IDENTITY_TTL_SECONDS,
            $config->jwtIdentityTtlSeconds(),
        );
    }

    /**
     * `jwtIdentityTtlSeconds()` clamps negative values to zero.
     *
     * @return void
     */
    public function testJwtIdentityTtlSecondsClamsNegativeToZero(): void
    {
        $config = $this->makeConfig([
            'authentication.resolution_cache.jwt.identity_ttl_seconds' => -10,
        ]);

        self::assertSame(0, $config->jwtIdentityTtlSeconds());
    }

    /**
     * `jwtIdentityTtlSeconds()` returns the default when the config
     * repository throws.
     *
     * @return void
     */
    public function testJwtIdentityTtlSecondsReturnsDefaultWhenConfigThrows(): void
    {
        $config = $this->makeThrowingConfig();

        self::assertSame(
            ResolutionCacheConfig::DEFAULT_JWT_IDENTITY_TTL_SECONDS,
            $config->jwtIdentityTtlSeconds(),
        );
    }

    /**
     * `jwtPrincipalTtlSeconds()` returns the configured TTL.
     *
     * @return void
     */
    public function testJwtPrincipalTtlSecondsReturnsConfiguredValue(): void
    {
        $config = $this->makeConfig([
            'authentication.resolution_cache.jwt.principal_ttl_seconds' => 60,
        ]);

        self::assertSame(60, $config->jwtPrincipalTtlSeconds());
    }

    /**
     * `jwtPrincipalTtlSeconds()` returns the default when not configured.
     *
     * @return void
     */
    public function testJwtPrincipalTtlSecondsReturnsDefaultWhenNotConfigured(): void
    {
        $config = $this->makeConfig([]);

        self::assertSame(
            ResolutionCacheConfig::DEFAULT_JWT_PRINCIPAL_TTL_SECONDS,
            $config->jwtPrincipalTtlSeconds(),
        );
    }

    /**
     * `jwtPrincipalTtlSeconds()` clamps negative values to zero.
     *
     * @return void
     */
    public function testJwtPrincipalTtlSecondsClamsNegativeToZero(): void
    {
        $config = $this->makeConfig([
            'authentication.resolution_cache.jwt.principal_ttl_seconds' => -5,
        ]);

        self::assertSame(0, $config->jwtPrincipalTtlSeconds());
    }

    /**
     * `jwtPrincipalTtlSeconds()` returns the default when the config
     * repository throws.
     *
     * @return void
     */
    public function testJwtPrincipalTtlSecondsReturnsDefaultWhenConfigThrows(): void
    {
        $config = $this->makeThrowingConfig();

        self::assertSame(
            ResolutionCacheConfig::DEFAULT_JWT_PRINCIPAL_TTL_SECONDS,
            $config->jwtPrincipalTtlSeconds(),
        );
    }

    /**
     * Build a ResolutionCacheConfig backed by a real config repository
     * seeded with the supplied values.
     *
     * @param  array<string, mixed>  $values
     * @return \SineMacula\Laravel\Authentication\Config\ResolutionCacheConfig
     */
    private function makeConfig(array $values): ResolutionCacheConfig
    {
        $repository = new ConfigRepository($values);

        return new ResolutionCacheConfig(static fn (): ConfigRepository => $repository);
    }

    /**
     * Build a ResolutionCacheConfig whose config resolver throws on every
     * call to exercise the catch branches.
     *
     * @return \SineMacula\Laravel\Authentication\Config\ResolutionCacheConfig
     */
    private function makeThrowingConfig(): ResolutionCacheConfig
    {
        return new ResolutionCacheConfig(static function (): ConfigRepository {
            throw new \RuntimeException('config unavailable');
        });
    }
}
