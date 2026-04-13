<?php

declare(strict_types = 1);

namespace Tests\Feature\Cache;

use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Cache\ResolutionCache;
use SineMacula\Laravel\Authentication\Cache\ResolutionCacheInvalidator;
use SineMacula\Laravel\Authentication\Cache\StoreBackedResolutionCache;
use Tests\TestCase;
use Tests\Unit\Stubs\StubPrincipal;

/**
 * Feature tests for the shared bearer-resolution cache services.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(StoreBackedResolutionCache::class)]
#[CoversClass(ResolutionCacheInvalidator::class)]
final class ResolutionCacheTest extends TestCase
{
    /**
     * Provision the shared identity table used by the cache tests.
     *
     * @return void
     */
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

        Cache::store()->flush();
    }

    /**
     * Drop the shared identity table.
     *
     * @return void
     */
    protected function tearDown(): void
    {
        Cache::store()->flush();
        Schema::dropIfExists('stub_principals');

        parent::tearDown();
    }

    /**
     * Guard names must partition the shared bearer identity cache so one
     * guard's warm hit does not satisfy another guard's first read.
     *
     * @return void
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
     * Explicit invalidation must clear every matching JWT guard entry for the
     * identity so subsequent reads fall back to the live provider.
     *
     * @return void
     */
    public function testForgetIdentityRemovesCachedEntriesForMatchingJwtGuards(): void
    {
        $cache       = app(ResolutionCache::class);
        $invalidator = app(ResolutionCacheInvalidator::class);
        $identity    = $this->seedIdentity('invalidate@example.test');

        self::assertInstanceOf(StoreBackedResolutionCache::class, $cache);
        self::assertInstanceOf(ResolutionCacheInvalidator::class, $invalidator);

        $staffCalls    = 0;
        $customerCalls = 0;

        $cache->rememberJwtIdentity(
            'staff',
            StubPrincipal::class,
            $identity->getAuthIdentifier(),
            function () use (&$staffCalls, $identity): StubPrincipal {
                $staffCalls++;

                return $identity;
            },
        );

        $cache->rememberJwtIdentity(
            'customer',
            StubPrincipal::class,
            $identity->getAuthIdentifier(),
            function () use (&$customerCalls, $identity): StubPrincipal {
                $customerCalls++;

                return $identity;
            },
        );

        $invalidator->forgetIdentity($identity);

        $cache->rememberJwtIdentity(
            'staff',
            StubPrincipal::class,
            $identity->getAuthIdentifier(),
            function () use (&$staffCalls, $identity): StubPrincipal {
                $staffCalls++;

                return $identity;
            },
        );

        $cache->rememberJwtIdentity(
            'customer',
            StubPrincipal::class,
            $identity->getAuthIdentifier(),
            function () use (&$customerCalls, $identity): StubPrincipal {
                $customerCalls++;

                return $identity;
            },
        );

        self::assertSame(2, $staffCalls);
        self::assertSame(2, $customerCalls);
    }

    /**
     * Cached identity clones have their relations stripped so eager-loaded
     * relation graphs do not leak across requests. Mutation guard: pins the
     * `$clone->unsetRelations()` call inside `cloneIdentity()`.
     *
     * @return void
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
     * resolver. Mutation guard: pins the `$cached !== null` cleanup branch
     * and the `forgetKey()` call.
     *
     * The resolver returns `null` so `storeResolvedIdentity` skips writing,
     * making the cleanup the only operation that removes the corrupted entry.
     *
     * @return void
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

        // The corrupted entry should have been removed by the cleanup
        // branch, and null resolved means nothing was re-stored.
        self::assertNull(Cache::store()->get($cacheKey));
    }

    /**
     * When the `forgetIdentity()` method is called with an explicit identifier,
     * it uses that identifier instead of `getAuthIdentifier()`. Mutation
     * guard: pins the coalesce order `$identifier ??
     * $identity->getAuthIdentifier()`.
     *
     * @return void
     */
    public function testForgetIdentityUsesExplicitIdentifierOverDefault(): void
    {
        $cache       = app(ResolutionCache::class);
        $invalidator = app(ResolutionCacheInvalidator::class);
        $identity    = $this->seedIdentity('coalesce@example.test');

        self::assertInstanceOf(StoreBackedResolutionCache::class, $cache);
        self::assertInstanceOf(ResolutionCacheInvalidator::class, $invalidator);

        $defaultId  = $identity->getAuthIdentifier();
        $explicitId = 99999;

        // Warm the cache under the explicit identifier.
        $cache->rememberJwtIdentity(
            'staff',
            StubPrincipal::class,
            $explicitId,
            fn (): StubPrincipal => $identity,
        );

        // Also warm the cache under the default identifier.
        $cache->rememberJwtIdentity(
            'staff',
            StubPrincipal::class,
            $defaultId,
            fn (): StubPrincipal => $identity,
        );

        // Invalidate using the explicit identifier only.
        $invalidator->forgetIdentity($identity, $explicitId);

        // The explicit-id entry should be gone.
        $explicitCalls = 0;

        $cache->rememberJwtIdentity(
            'staff',
            StubPrincipal::class,
            $explicitId,
            function () use (&$explicitCalls, $identity): StubPrincipal {
                $explicitCalls++;

                return $identity;
            },
        );

        self::assertSame(1, $explicitCalls, 'Explicit identifier entry should have been forgotten.');

        // The default-id entry should still be cached.
        $defaultCalls = 0;

        $cache->rememberJwtIdentity(
            'staff',
            StubPrincipal::class,
            $defaultId,
            function () use (&$defaultCalls, $identity): StubPrincipal {
                $defaultCalls++;

                return $identity;
            },
        );

        self::assertSame(0, $defaultCalls, 'Default identifier entry should still be cached.');
    }

    /**
     * A non-jwt guard (e.g. basic) is skipped by the invalidator so its cache
     * entries are never touched by `forgetIdentity()`. Mutation guard: pins
     * the `$driver !== 'jwt'` arm in `providerModelClassForJwtGuard()`.
     *
     * @return void
     */
    public function testForgetIdentitySkipsNonJwtGuards(): void
    {
        $cache       = app(ResolutionCache::class);
        $invalidator = app(ResolutionCacheInvalidator::class);
        $identity    = $this->seedIdentity('nonjwt@example.test');

        self::assertInstanceOf(StoreBackedResolutionCache::class, $cache);
        self::assertInstanceOf(ResolutionCacheInvalidator::class, $invalidator);

        // Warm the cache under the "cli" (basic) guard's namespace by
        // writing directly - basic guards don't use the cache, but this
        // verifies the invalidator never touches non-jwt entries.
        $providerSegment = str_replace('\\', '.', ltrim(StubPrincipal::class, '\\'));
        $cliKey          = sprintf(
            'sm.auth.resolution.v1.jwt.cli.identity.%s.%s',
            $providerSegment,
            $identity->getAuthIdentifier(),
        );

        Cache::store()->put($cliKey, $identity, 60);

        // Invalidate all JWT entries for this identity.
        $invalidator->forgetIdentity($identity);

        // The cli entry must still be there because the invalidator skipped
        // the non-jwt "cli" guard.
        self::assertNotNull(Cache::store()->get($cliKey));
    }

    /**
     * A guard with a non-model provider driver (e.g. `database`) is skipped
     * by the invalidator. Mutation guard: pins the `$providerDriver !==
     * 'model'` arm in `providerModelClassForJwtGuard()`.
     *
     * @return void
     */
    public function testForgetIdentitySkipsNonModelProviderDriverGuards(): void
    {
        // Add a jwt guard backed by a database provider (non-model).
        config()->set('auth.guards.api-db', [
            'driver'   => 'jwt',
            'provider' => 'db-identities',
        ]);

        config()->set('auth.providers.db-identities', [
            'driver' => 'database',
            'table'  => 'users',
        ]);

        $cache       = app(ResolutionCache::class);
        $invalidator = app(ResolutionCacheInvalidator::class);
        $identity    = $this->seedIdentity('dbprovider@example.test');

        self::assertInstanceOf(StoreBackedResolutionCache::class, $cache);
        self::assertInstanceOf(ResolutionCacheInvalidator::class, $invalidator);

        // Plant a cache entry under the api-db guard namespace.
        $providerSegment = str_replace('\\', '.', ltrim(StubPrincipal::class, '\\'));
        $dbKey           = sprintf(
            'sm.auth.resolution.v1.jwt.api-db.identity.%s.%s',
            $providerSegment,
            $identity->getAuthIdentifier(),
        );

        Cache::store()->put($dbKey, $identity, 60);

        $invalidator->forgetIdentity($identity);

        // The entry must remain because the provider driver is not "model".
        self::assertNotNull(Cache::store()->get($dbKey));
    }

    /**
     * A guard whose provider name is missing or empty is skipped by the
     * invalidator. Mutation guard: pins the `!is_string($providerName) ||
     * $providerName === ''` arms in `providerModelClassForJwtGuard()`.
     *
     * @return void
     */
    public function testForgetIdentitySkipsGuardWithMissingOrEmptyProvider(): void
    {
        config()->set('auth.guards.no-provider', [
            'driver' => 'jwt',
        ]);

        config()->set('auth.guards.empty-provider', [
            'driver'   => 'jwt',
            'provider' => '',
        ]);

        $invalidator = app(ResolutionCacheInvalidator::class);
        $identity    = $this->seedIdentity('noprovider@example.test');

        self::assertInstanceOf(ResolutionCacheInvalidator::class, $invalidator);

        // Should not throw even with misconfigured guards.
        $invalidator->forgetIdentity($identity);

        // If we got here without an exception, the guards were skipped.
        self::assertTrue(true);
    }

    /**
     * A guard whose provider model is an empty string is skipped by the
     * invalidator. Mutation guard: pins the `$providerModelClass === ''` arm
     * in `providerModelClassForJwtGuard()`.
     *
     * @return void
     */
    public function testForgetIdentitySkipsGuardWithEmptyModelClass(): void
    {
        config()->set('auth.guards.empty-model', [
            'driver'   => 'jwt',
            'provider' => 'empty-model-provider',
        ]);

        config()->set('auth.providers.empty-model-provider', [
            'driver' => 'model',
            'model'  => '',
        ]);

        $invalidator = app(ResolutionCacheInvalidator::class);
        $identity    = $this->seedIdentity('emptymodel@example.test');

        self::assertInstanceOf(ResolutionCacheInvalidator::class, $invalidator);

        // Warm a JWT cache entry for the "staff" guard.
        $cache      = app(ResolutionCache::class);
        $staffCalls = 0;

        $cache->rememberJwtIdentity(
            'staff',
            StubPrincipal::class,
            $identity->getAuthIdentifier(),
            function () use (&$staffCalls, $identity): StubPrincipal {
                $staffCalls++;

                return $identity;
            },
        );

        // Invalidate - the empty-model guard should be skipped, but the
        // valid staff guard should still be invalidated.
        $invalidator->forgetIdentity($identity);

        $cache->rememberJwtIdentity(
            'staff',
            StubPrincipal::class,
            $identity->getAuthIdentifier(),
            function () use (&$staffCalls, $identity): StubPrincipal {
                $staffCalls++;

                return $identity;
            },
        );

        self::assertSame(2, $staffCalls);
    }

    /**
     * Configure the shared JWT/basic guards used by the cache tests.
     *
     * @param  mixed  $app
     * @return void
     */
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
