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
