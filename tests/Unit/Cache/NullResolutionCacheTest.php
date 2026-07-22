<?php

declare(strict_types = 1);

namespace Tests\Unit\Cache;

use Illuminate\Contracts\Auth\Authenticatable;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Cache\NullResolutionCache;

/**
 * Unit tests for the NullResolutionCache no-op implementation.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(NullResolutionCache::class)]
final class NullResolutionCacheTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    /** @var string Stub provider model class for all cache tests. */
    private const string PROVIDER_MODEL = 'App\Models\User';

    /**
     * `rememberJwtIdentity()` delegates to the resolver and returns its result
     * when the resolver returns an Authenticatable.
     *
     * @return void
     */
    public function testRememberJwtIdentityReturnsResolverResult(): void
    {
        $cache = new NullResolutionCache;

        /** @var \Illuminate\Contracts\Auth\Authenticatable&\Mockery\MockInterface $user */
        $user = \Mockery::mock(Authenticatable::class);

        $result = $cache->rememberJwtIdentity(
            'api',
            self::PROVIDER_MODEL,
            1,
            static fn (): Authenticatable => $user,
        );

        self::assertSame($user, $result);
    }

    /**
     * `rememberJwtIdentity()` returns null when the resolver returns null.
     *
     * @return void
     */
    public function testRememberJwtIdentityReturnsNullWhenResolverReturnsNull(): void
    {
        $cache = new NullResolutionCache;

        $result = $cache->rememberJwtIdentity(
            'api',
            self::PROVIDER_MODEL,
            1,
            static fn (): ?Authenticatable => null,
        );

        self::assertNull($result);
    }

    /**
     * `rememberJwtIdentity()` returns null when the resolver returns a
     * non-Authenticatable value.
     *
     * @return void
     */
    public function testRememberJwtIdentityReturnsNullForNonAuthenticatable(): void
    {
        $cache = new NullResolutionCache;

        $result = $cache->rememberJwtIdentity(
            'api',
            self::PROVIDER_MODEL,
            1,
            static fn (): string => 'not-authenticatable', // @phpstan-ignore return.type
        );

        self::assertNull($result);
    }

    /**
     * `forgetJwtIdentity()` is a no-op that completes without error.
     *
     * @return void
     */
    public function testForgetJwtIdentityIsNoOp(): void
    {
        $cache = new NullResolutionCache;

        $cache->forgetJwtIdentity('api', self::PROVIDER_MODEL, 1);

        self::assertTrue(true, 'forgetJwtIdentity completed without error.');
    }
}
