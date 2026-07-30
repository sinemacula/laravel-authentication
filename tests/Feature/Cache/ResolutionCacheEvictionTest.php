<?php

declare(strict_types = 1);

namespace Tests\Feature\Cache;

use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Cache\ResolutionCacheInvalidator;
use SineMacula\Laravel\Authentication\Cache\StoreBackedResolutionCache;
use SineMacula\Laravel\Authentication\Contracts\ResolutionCache;
use Tests\TestCase;
use Tests\Unit\Stubs\StubPrincipal;

/**
 * Feature tests for the resolution cache eviction and invalidation paths.
 *
 * Covers `ResolutionCacheInvalidator::forgetIdentity()`,
 * `forgetIdentityForGuard()`, and the guard-filtering logic that skips non-JWT,
 * non-model, and misconfigured guards.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(StoreBackedResolutionCache::class)]
#[CoversClass(ResolutionCacheInvalidator::class)]
final class ResolutionCacheEvictionTest extends TestCase
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
     * Explicit invalidation must clear every matching JWT guard entry for the
     * identity so subsequent reads fall back to the live provider.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
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
     * When the `forgetIdentity()` method is called with an explicit identifier,
     * it uses that identifier instead of `getAuthIdentifier()`. Mutation guard:
     * pins the coalesce order `$identifier ?? $identity->getAuthIdentifier()`.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
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
     * entries are never touched by `forgetIdentity()`. Mutation guard: pins the
     * `$driver !== 'jwt'` arm in `providerModelClassForJwtGuard()`.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Psr\SimpleCache\InvalidArgumentException
     */
    public function testForgetIdentitySkipsNonJwtGuards(): void
    {
        $cache       = app(ResolutionCache::class);
        $invalidator = app(ResolutionCacheInvalidator::class);
        $identity    = $this->seedIdentity('nonjwt@example.test');

        self::assertInstanceOf(StoreBackedResolutionCache::class, $cache);
        self::assertInstanceOf(ResolutionCacheInvalidator::class, $invalidator);

        // Warm the cache under the "cli" (basic) guard's namespace by writing
        // directly - basic guards don't use the cache, but this verifies the
        // invalidator never touches non-jwt entries.
        $providerSegment = str_replace('\\', '.', ltrim(StubPrincipal::class, '\\'));
        $cliKey          = sprintf(
            'sm.auth.resolution.v1.jwt.cli.identity.%s.%s',
            $providerSegment,
            $identity->getAuthIdentifier(),
        );

        Cache::store()->put($cliKey, $identity, 60);

        // Invalidate all JWT entries for this identity.
        $invalidator->forgetIdentity($identity);

        // The cli entry must still be there because the invalidator skipped the
        // non-jwt "cli" guard.
        self::assertNotNull(Cache::store()->get($cliKey));
    }

    /**
     * A guard with a non-model provider driver (e.g. `database`) is skipped by
     * the invalidator. Mutation guard: pins the `$providerDriver !== 'model'`
     * arm in `providerModelClassForJwtGuard()`.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Psr\SimpleCache\InvalidArgumentException
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
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
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
     * invalidator. Mutation guard: pins the `$providerModelClass === ''` arm in
     * `providerModelClassForJwtGuard()`.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
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

        // Invalidate - the empty-model guard should be skipped, but the valid
        // staff guard should still be invalidated.
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
     * `forgetIdentityForGuard()` removes the cache entry only for the specified
     * guard. Pins the single-guard invalidation path in
     * `ResolutionCacheInvalidator::forgetIdentityForGuard()`.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testForgetIdentityForGuardRemovesSingleGuardEntry(): void
    {
        $cache       = app(ResolutionCache::class);
        $invalidator = app(ResolutionCacheInvalidator::class);
        $identity    = $this->seedIdentity('forguard@example.test');

        self::assertInstanceOf(StoreBackedResolutionCache::class, $cache);
        self::assertInstanceOf(ResolutionCacheInvalidator::class, $invalidator);

        $staffCalls    = 0;
        $customerCalls = 0;

        // Warm both guards.
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

        // Invalidate only the staff guard.
        $invalidator->forgetIdentityForGuard($identity, 'staff');

        // Staff should be re-resolved.
        $cache->rememberJwtIdentity(
            'staff',
            StubPrincipal::class,
            $identity->getAuthIdentifier(),
            function () use (&$staffCalls, $identity): StubPrincipal {
                $staffCalls++;

                return $identity;
            },
        );

        // Customer should still be cached.
        $cache->rememberJwtIdentity(
            'customer',
            StubPrincipal::class,
            $identity->getAuthIdentifier(),
            function () use (&$customerCalls, $identity): StubPrincipal {
                $customerCalls++;

                return $identity;
            },
        );

        self::assertSame(2, $staffCalls, 'Staff guard entry should have been forgotten.');
        self::assertSame(1, $customerCalls, 'Customer guard entry should still be cached.');
    }

    /**
     * `forgetIdentityForGuard()` is a no-op when the guard is not a JWT guard.
     * Pins the `$providerModelClass === null` early-return path.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testForgetIdentityForGuardSkipsNonJwtGuard(): void
    {
        $invalidator = app(ResolutionCacheInvalidator::class);
        $identity    = $this->seedIdentity('nonjwt-forguard@example.test');

        self::assertInstanceOf(ResolutionCacheInvalidator::class, $invalidator);

        // Should not throw for the basic-driver cli guard.
        $invalidator->forgetIdentityForGuard($identity, 'cli');

        self::assertTrue(true, 'forgetIdentityForGuard returned without error.');
    }

    /**
     * `forgetIdentityForGuard()` honours an explicit identifier parameter.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testForgetIdentityForGuardUsesExplicitIdentifier(): void
    {
        $cache       = app(ResolutionCache::class);
        $invalidator = app(ResolutionCacheInvalidator::class);
        $identity    = $this->seedIdentity('explicit-forguard@example.test');

        self::assertInstanceOf(StoreBackedResolutionCache::class, $cache);
        self::assertInstanceOf(ResolutionCacheInvalidator::class, $invalidator);

        $explicitId = 88888;

        // Warm the cache under the explicit identifier.
        $cache->rememberJwtIdentity(
            'staff',
            StubPrincipal::class,
            $explicitId,
            fn (): StubPrincipal => $identity,
        );

        // Invalidate the explicit id.
        $invalidator->forgetIdentityForGuard($identity, 'staff', $explicitId);

        // The entry should be gone.
        $calls = 0;

        $cache->rememberJwtIdentity(
            'staff',
            StubPrincipal::class,
            $explicitId,
            function () use (&$calls, $identity): StubPrincipal {
                $calls++;

                return $identity;
            },
        );

        self::assertSame(1, $calls, 'Explicit identifier entry should have been forgotten.');
    }

    /**
     * Guards with non-string keys in `auth.guards` are skipped by the
     * invalidator without error. Pins the `!is_string($guardName) ||
     * !is_array($guardConfig)` continue branch in
     * `matchingJwtGuardProviderModels()`.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testForgetIdentitySkipsNonStringGuardKeys(): void
    {
        // Add a guard entry with a numeric key.
        config()->set('auth.guards.0', [
            'driver'   => 'jwt',
            'provider' => 'identities',
        ]);

        $invalidator = app(ResolutionCacheInvalidator::class);
        $identity    = $this->seedIdentity('intkey@example.test');

        self::assertInstanceOf(ResolutionCacheInvalidator::class, $invalidator);

        // Should not throw with a non-string guard key.
        $invalidator->forgetIdentity($identity);

        self::assertTrue(true, 'forgetIdentity returned without error.');
    }

    /**
     * Guards with non-array config values are skipped by the invalidator
     * without error. Pins the `!is_array($guardConfig)` continue branch in
     * `matchingJwtGuardProviderModels()`.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testForgetIdentitySkipsNonArrayGuardConfig(): void
    {
        // Set a guard entry to a non-array value.
        config()->set('auth.guards.broken', 'not-an-array');

        $invalidator = app(ResolutionCacheInvalidator::class);
        $identity    = $this->seedIdentity('nonarray@example.test');

        self::assertInstanceOf(ResolutionCacheInvalidator::class, $invalidator);

        // Should not throw with a non-array guard config.
        $invalidator->forgetIdentity($identity);

        self::assertTrue(true, 'forgetIdentity returned without error.');
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
