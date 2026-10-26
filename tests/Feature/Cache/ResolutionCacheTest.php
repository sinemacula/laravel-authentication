<?php

declare(strict_types = 1);

namespace Tests\Feature\Cache;

use Illuminate\Contracts\Cache\Factory;
use Illuminate\Contracts\Cache\Repository;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Cache\StoreBackedResolutionCache;
use SineMacula\Laravel\Authentication\Config\ResolutionCacheConfig;
use SineMacula\Laravel\Authentication\Contracts\ResolutionCache;
use Tests\TestCase;
use Tests\Unit\Stubs\StubPrincipal;

/**
 * Feature tests for the shared bearer-resolution cache store operations.
 *
 * Covers `StoreBackedResolutionCache` read, write, TTL, clone, and
 * error-handling paths. Eviction and invalidator tests live in
 * `ResolutionCacheEvictionTest`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(StoreBackedResolutionCache::class)]
final class ResolutionCacheTest extends TestCase
{
    /**
     * Provision the shared identity table used by the cache tests.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        Schema::create('stub_principals', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('email')->unique();
            $blueprint->string('password');
            $blueprint->boolean('is_active')->default(true);
            $blueprint->timestamps();
        });

        Cache::store()->clear();
    }

    /**
     * Drop the shared identity table.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Cache::store()->clear();
        Schema::dropIfExists('stub_principals');

        parent::tearDown();
    }

    /**
     * Guard names must partition the shared bearer identity cache so one
     * guard's warm hit does not satisfy another guard's first read.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testBearerIdentityCacheIsScopedPerGuard(): void
    {
        $cache = app(ResolutionCache::class);

        self::assertInstanceOf(StoreBackedResolutionCache::class, $cache);

        $identity = $this->seedIdentity();
        $calls    = 0;

        $first = $cache->rememberJwtIdentity(
            'staff',
            StubPrincipal::class,
            $identity->getAuthIdentifier(),
            function () use (&$calls, $identity): StubPrincipal {
                $calls++;

                return $identity;
            },
        );

        $second = $cache->rememberJwtIdentity(
            'staff',
            StubPrincipal::class,
            $identity->getAuthIdentifier(),
            function () use (&$calls, $identity): StubPrincipal {
                $calls++;

                return $identity;
            },
        );

        $customerCalls = 0;

        $third = $cache->rememberJwtIdentity(
            'customer',
            StubPrincipal::class,
            $identity->getAuthIdentifier(),
            function () use (&$customerCalls, $identity): StubPrincipal {
                $customerCalls++;

                return $identity;
            },
        );

        self::assertInstanceOf(StubPrincipal::class, $first);
        self::assertInstanceOf(StubPrincipal::class, $second);
        self::assertInstanceOf(StubPrincipal::class, $third);
        self::assertSame(1, $calls);
        self::assertSame(1, $customerCalls);
        self::assertNotSame($first, $second);
    }

    /**
     * Cached identity clones have their relations stripped so eager-loaded
     * relation graphs do not leak across requests. Mutation guard: pins the
     * `$clone->unsetRelations()` call inside `cloneIdentity()`.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testCachedIdentityCloneHasNoRelations(): void
    {
        $cache = app(ResolutionCache::class);

        self::assertInstanceOf(StoreBackedResolutionCache::class, $cache);

        $identity = $this->seedIdentity('relations@example.test');

        // Manually set a relation so we can verify it gets stripped.
        $identity->setRelation('fakeRelation', collect(['foo']));

        self::assertTrue($identity->relationLoaded('fakeRelation'));

        // First call: stores the identity into the cache.
        $cache->rememberJwtIdentity(
            'staff',
            StubPrincipal::class,
            $identity->getAuthIdentifier(),
            fn (): StubPrincipal => $identity,
        );

        // Second call: returns from cache.
        $cached = $cache->rememberJwtIdentity(
            'staff',
            StubPrincipal::class,
            $identity->getAuthIdentifier(),
            fn (): StubPrincipal => $identity,
        );

        self::assertInstanceOf(StubPrincipal::class, $cached);

        /** @var \Tests\Unit\Stubs\StubPrincipal $cachedPrincipal */
        $cachedPrincipal = $cached;
        self::assertEmpty($cachedPrincipal->getRelations());
    }

    /**
     * When the cache contains a non-Identity/Model value (e.g. a corrupted
     * entry), `loadCachedIdentity` forgets the key and falls back to the live
     * resolver. Mutation guard: pins the `$cached !== null` cleanup branch and
     * the `forgetKey()` call.
     *
     * The resolver returns `null` so `storeResolvedIdentity` skips writing,
     * making the cleanup the only operation that removes the corrupted entry.
     *
     * @return void
     *
     * @throws \Psr\SimpleCache\InvalidArgumentException
     */
    public function testCacheCleanupOnTypeMismatch(): void
    {
        $cache = app(ResolutionCache::class);

        self::assertInstanceOf(StoreBackedResolutionCache::class, $cache);

        // Build the cache key the same way StoreBackedResolutionCache does:
        // ltrim leading backslash, replace remaining backslashes with dots.
        $providerSegment = str_replace('\\', '.', ltrim(StubPrincipal::class, '\\'));
        $cacheKey        = sprintf(
            'sm.auth.resolution.v1.jwt.staff.identity.%s.%s',
            $providerSegment,
            '999',
        );

        // Inject a non-Identity value directly into the cache store.
        Cache::store()->put($cacheKey, 'not-an-identity-instance', 60);

        $calls = 0;

        // Return null so `storeResolvedIdentity` does not overwrite the key.
        // The cleanup branch is the only thing that removes the corrupted
        // entry.
        $result = $cache->rememberJwtIdentity(
            'staff',
            StubPrincipal::class,
            999,
            function () use (&$calls): ?StubPrincipal {
                $calls++;

                return null;
            },
        );

        self::assertSame(1, $calls);
        self::assertNull($result);

        // The corrupted entry should have been removed by the cleanup branch,
        // and null resolved means nothing was re-stored.
        self::assertNull(Cache::store()->get($cacheKey));
    }

    /**
     * `forgetJwtIdentity()` short-circuits when the identifier cannot be
     * normalized to a string. Pins the `$normalizedIdentifier === null`
     * early-return in `StoreBackedResolutionCache::forgetJwtIdentity()`.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testForgetJwtIdentityShortCircuitsForNullIdentifier(): void
    {
        $cache = app(ResolutionCache::class);

        self::assertInstanceOf(StoreBackedResolutionCache::class, $cache);

        // An array identifier cannot be coerced to string, so the method
        // returns early. No exception means the short-circuit succeeded.
        $cache->forgetJwtIdentity('staff', StubPrincipal::class, []);

        self::assertTrue(true, 'forgetJwtIdentity returned without error for null identifier.');
    }

    /**
     * `rememberJwtIdentity()` falls back to the resolver when the cache store
     * throws during a read. Pins the catch branch in `loadCachedIdentity()`.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testRememberJwtIdentityFallsBackWhenCacheStoreThrowsOnRead(): void
    {
        $identity = $this->seedIdentity('store-throw-read@example.test');

        // Replace the cache store with one that throws on get().
        $throwingStore = \Mockery::mock(Repository::class);
        $throwingStore->shouldReceive('get')
            ->andThrow(new \RuntimeException('cache read failed'));
        $throwingStore->shouldReceive('put')
            ->andReturnTrue();

        $throwingFactory = \Mockery::mock(Factory::class);
        $throwingFactory->shouldReceive('store')
            ->andReturn($throwingStore);

        $config = app(ResolutionCacheConfig::class);

        $cache = new StoreBackedResolutionCache($throwingFactory, $config);

        $calls  = 0;
        $result = $cache->rememberJwtIdentity(
            'staff',
            StubPrincipal::class,
            $identity->getAuthIdentifier(),
            function () use (&$calls, $identity): StubPrincipal {
                $calls++;

                return $identity;
            },
        );

        self::assertSame(1, $calls, 'Resolver should be called when cache read throws.');
        self::assertInstanceOf(StubPrincipal::class, $result);
    }

    /**
     * `forgetKey()` swallows exceptions from the cache store. Pins the catch
     * branch in `StoreBackedResolutionCache::forgetKey()`.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testForgetKeySwallowsCacheStoreExceptions(): void
    {
        $throwingStore = \Mockery::mock(Repository::class);
        $throwingStore->shouldReceive('forget')
            ->andThrow(new \RuntimeException('cache forget failed'));

        $throwingFactory = \Mockery::mock(Factory::class);
        $throwingFactory->shouldReceive('store')
            ->andReturn($throwingStore);

        $config = app(ResolutionCacheConfig::class);

        $cache = new StoreBackedResolutionCache($throwingFactory, $config);

        // forgetJwtIdentity calls forgetKey internally. No exception means the
        // catch branch swallowed the error.
        $cache->forgetJwtIdentity('staff', StubPrincipal::class, 1);

        self::assertTrue(true, 'forgetKey swallowed the cache store exception.');
    }

    /**
     * `storeResolvedIdentity()` swallows exceptions from the cache store write.
     * Pins the catch branch in
     * `StoreBackedResolutionCache::storeResolvedIdentity()`.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testStoreResolvedIdentitySwallowsCacheStoreWriteExceptions(): void
    {
        $identity = $this->seedIdentity('store-throw-write@example.test');

        $throwingStore = \Mockery::mock(Repository::class);
        $throwingStore->shouldReceive('get')
            ->andReturnNull();
        $throwingStore->shouldReceive('put')
            ->andThrow(new \RuntimeException('cache write failed'));

        $throwingFactory = \Mockery::mock(Factory::class);
        $throwingFactory->shouldReceive('store')
            ->andReturn($throwingStore);

        $config = app(ResolutionCacheConfig::class);

        $cache = new StoreBackedResolutionCache($throwingFactory, $config);

        $result = $cache->rememberJwtIdentity(
            'staff',
            StubPrincipal::class,
            $identity->getAuthIdentifier(),
            fn (): StubPrincipal => $identity,
        );

        self::assertInstanceOf(StubPrincipal::class, $result);
    }

    /**
     * `rememberJwtIdentity()` skips the cache lookup when the identity TTL is
     * zero. Pins the `: null` else branch of the ternary in
     * `rememberJwtIdentity()`.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testRememberJwtIdentitySkipsCacheWhenTtlIsZero(): void
    {
        // Override the TTL to 0, disabling caching.
        config()->set('authentication.resolution_cache.jwt.identity_ttl_seconds', 0);

        $cache = app(ResolutionCache::class);

        self::assertInstanceOf(StoreBackedResolutionCache::class, $cache);

        $calls  = 0;
        $result = $cache->rememberJwtIdentity(
            'staff',
            StubPrincipal::class,
            1,
            function () use (&$calls): ?StubPrincipal {
                $calls++;

                return null;
            },
        );

        self::assertSame(1, $calls, 'Resolver must run when TTL is zero.');
        self::assertNull($result);

        // Restore the TTL for subsequent tests.
        config()->set('authentication.resolution_cache.jwt.identity_ttl_seconds', 15);
    }

    /**
     * `rememberJwtIdentity()` returns a cached hit when available. Pins the
     * `$cached !== null` return path inside `rememberJwtIdentity()`.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testRememberJwtIdentityReturnsCacheHit(): void
    {
        $cache = app(ResolutionCache::class);

        self::assertInstanceOf(StoreBackedResolutionCache::class, $cache);

        $identity = $this->seedIdentity('cachehit@example.test');

        // First call: resolver runs and stores.
        $cache->rememberJwtIdentity(
            'staff',
            StubPrincipal::class,
            $identity->getAuthIdentifier(),
            fn (): StubPrincipal => $identity,
        );

        // Second call: resolver must NOT run, cache hit returned.
        $resolverCalled = false;

        $result = $cache->rememberJwtIdentity(
            'staff',
            StubPrincipal::class,
            $identity->getAuthIdentifier(),
            function () use (&$resolverCalled, $identity): StubPrincipal {
                $resolverCalled = true;

                return $identity;
            },
        );

        self::assertFalse($resolverCalled, 'Resolver should not run for a cache hit.');
        self::assertInstanceOf(StubPrincipal::class, $result);
    }

    /**
     * Configure the shared JWT/basic guards used by the cache tests.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        config()->set('cache.default', 'array');

        config()->set('auth.guards.staff', [
            'driver'   => 'jwt',
            'provider' => 'identities',
        ]);

        config()->set('auth.guards.customer', [
            'driver'   => 'jwt',
            'provider' => 'identities',
        ]);

        config()->set('auth.guards.cli', [
            'driver'   => 'basic',
            'provider' => 'identities',
        ]);

        config()->set('auth.providers.identities', [
            'driver' => 'model',
            'model'  => StubPrincipal::class,
        ]);

        config()->set('authentication.resolution_cache.jwt.identity_ttl_seconds', 15);
    }

    /**
     * Persist and return an active identity row.
     *
     * @param  string  $email
     * @return \Tests\Unit\Stubs\StubPrincipal
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function seedIdentity(string $email = 'cache@example.test'): StubPrincipal
    {
        $hasher = app(Hasher::class);

        $identity            = new StubPrincipal;
        $identity->email     = $email;
        $identity->password  = $hasher->make('correct horse battery staple');
        $identity->is_active = true;
        $identity->save();

        return $identity;
    }
}
