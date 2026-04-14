<?php

declare(strict_types = 1);

namespace Benchmarks\Support;

use Carbon\Carbon;
use Firebase\JWT\JWT;
use Illuminate\Cache\ArrayStore;
use Illuminate\Cache\Repository as CacheRepository;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Container\Container;
use Illuminate\Contracts\Cache\Factory as CacheFactory;
use Illuminate\Contracts\Cache\Repository;
use Illuminate\Contracts\Events\Dispatcher as DispatcherContract;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Events\Dispatcher;
use Illuminate\Hashing\BcryptHasher;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Facade;
use Illuminate\Support\Timebox;
use SineMacula\Laravel\Authentication\Cache\ResolutionCache;
use SineMacula\Laravel\Authentication\Cache\StoreBackedResolutionCache;
use SineMacula\Laravel\Authentication\Config\ResolutionCacheConfig;
use SineMacula\Laravel\Authentication\Events\DeviceAuthenticated;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenService;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenExchange;
use SineMacula\Laravel\Authentication\Listeners\UpdateDeviceTimestamp;
use SineMacula\Laravel\Authentication\Models\Device;
use SineMacula\Laravel\Authentication\Providers\ModelProvider;
use SineMacula\Laravel\Authentication\Resolvers\DefaultPrincipalResolver;
use Tests\Integration\Fixtures\Coexist2dIdentity;
use Tests\Integration\Fixtures\Coexist3dIdentity;
use Tests\Integration\Fixtures\Coexist3dPrincipal;
use Tests\Integration\Fixtures\IntegrationIdentity;
use Tests\Integration\Fixtures\TenantAware3dIdentity;
use Tests\Integration\Fixtures\TenantAware3dPrincipal;
use Tests\Integration\Fixtures\TenantAware3dTenant;
use Tests\Performance\Fixtures\PerformanceAccessOnlyIdentity;

/**
 * Runtime benchmark fixtures for JwtGuard bearer-auth hot paths.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class JwtGuardBenchHarness
{
    /** @var string HS256 signing secret for benchmark tokens. */
    private const string SECRET = 'benchmark-secret-key-with-at-least-32-bytes!';

    /** @var string Shared benchmark password. */
    private const string PASSWORD = 'correct horse battery staple';

    /** @var string Access-only 2D identity email. */
    private const string ACCESS_ONLY_EMAIL = 'bench-access-only@example.test';

    /** @var string Coexistence 2D identity email. */
    private const string COEXIST_TWO_D_EMAIL = 'bench-coexist-2d@example.test';

    /** @var string Device-bearing identity email. */
    private const string DEVICE_EMAIL = 'bench-device@example.test';

    /** @var string 3D identity email. */
    private const string THREE_D_EMAIL = 'bench-3d@example.test';

    /** @var string Tenant-aware 3D identity email. */
    private const string TENANT_THREE_D_EMAIL = 'bench-tenant-3d@example.test';

    /** @var int Number of mutable write-path tokens to pre-seed. */
    private const int TOKEN_POOL_SIZE = 128;

    /** @var \SineMacula\Laravel\Authentication\Jwt\JwtTokenService */
    private readonly JwtTokenService $tokens;

    /** @var \SineMacula\Laravel\Authentication\Providers\ModelProvider */
    private readonly ModelProvider $accessOnlyProvider;

    /** @var \SineMacula\Laravel\Authentication\Providers\ModelProvider */
    private readonly ModelProvider $coexistTwoDProvider;

    /** @var \SineMacula\Laravel\Authentication\Providers\ModelProvider */
    private readonly ModelProvider $deviceProvider;

    /** @var \SineMacula\Laravel\Authentication\Providers\ModelProvider */
    private readonly ModelProvider $threeDProvider;

    /** @var \SineMacula\Laravel\Authentication\Providers\ModelProvider */
    private readonly ModelProvider $tenantAwareThreeDProvider;

    /** @var \SineMacula\Laravel\Authentication\Resolvers\DefaultPrincipalResolver */
    private readonly DefaultPrincipalResolver $resolver;

    /** @var \Illuminate\Contracts\Events\Dispatcher */
    private readonly DispatcherContract $events;

    /** @var \Illuminate\Support\Timebox */
    private readonly Timebox $timebox;

    /** @var \SineMacula\Laravel\Authentication\Cache\ResolutionCache */
    private readonly ResolutionCache $warmResolutionCache;

    /** @var string 2D access-only bearer token. */
    private string $accessOnlyToken;

    /** @var string Coexist 2D bearer token. */
    private string $coexistTwoDToken;

    /** @var string Device bearer with fresh timestamp. */
    private string $deviceFreshToken;

    /** @var string 3D bearer token. */
    private string $threeDToken;

    /** @var string Tenant-aware 3D bearer token. */
    private string $tenantAwareThreeDToken;

    /** @var string Tenant-aware secondary bearer token. */
    private string $tenantAwareSecondaryToken;

    /** @var list<string> */
    private array $deviceWriteTokens = [];

    /** @var int Current index into the write-token pool. */
    private int $deviceWriteIndex = 0;

    /** @var bool */
    private bool $accessOnlyWarmCachePrimed = false;

    /** @var bool */
    private bool $tenantAwareWarmCachePrimed = false;

    /**
     * Seed the bearer-auth benchmark fixtures.
     */
    public function __construct()
    {
        BenchDatabase::boot();

        $now = Carbon::createStrict(2026, 4, 10, 12, 0, 0);
        Carbon::setTestNow($now);
        JWT::$timestamp = $now->getTimestamp();

        $config = new ConfigRepository([
            'authentication' => [
                'device' => [
                    'model'                      => Device::class,
                    'table'                      => 'devices',
                    'refresh_key_column'         => 'refresh_key',
                    'last_seen_throttle_seconds' => 60,
                ],
                'timebox' => [
                    'credentials_microseconds' => 400000,
                ],
                'resolution_cache' => [
                    'jwt' => [
                        'identity_ttl_seconds' => 15,
                    ],
                ],
            ],
        ]);

        $container = new Container;
        $container->instance('config', $config);
        Facade::setFacadeApplication($container);

        $this->resolver = new DefaultPrincipalResolver;
        $this->events   = new Dispatcher($container);
        $this->events->setTransactionManagerResolver(static fn (): null => null);
        $this->events->listen(
            DeviceAuthenticated::class,
            new UpdateDeviceTimestamp,
        );

        $hasher = new BcryptHasher;

        $this->tokens              = new JwtTokenService(self::SECRET, 'HS256', 15, 60 * 24 * 30);
        $this->timebox             = new Timebox;
        $this->warmResolutionCache = new StoreBackedResolutionCache(
            new class (new CacheRepository(new ArrayStore)) implements CacheFactory {
                /**
                 * Constructor.
                 *
                 * @param  \Illuminate\Cache\Repository  $repository
                 */
                public function __construct(
                    private readonly CacheRepository $repository,
                ) {}

                /**
                 * @param  string|null  $name
                 * @return \Illuminate\Contracts\Cache\Repository
                 */
                #[\Override]
                public function store($name = null): Repository
                {
                    unset($name);

                    return $this->repository;
                }
            },
            new ResolutionCacheConfig(
                static fn (): ConfigRepository => $config,
            ),
        );

        $this->accessOnlyProvider        = new ModelProvider($hasher, PerformanceAccessOnlyIdentity::class);
        $this->coexistTwoDProvider       = new ModelProvider($hasher, Coexist2dIdentity::class);
        $this->deviceProvider            = new ModelProvider($hasher, IntegrationIdentity::class);
        $this->threeDProvider            = new ModelProvider($hasher, Coexist3dIdentity::class);
        $this->tenantAwareThreeDProvider = new ModelProvider($hasher, TenantAware3dIdentity::class);

        $this->createSchema();
        $this->seedAccessOnlyFixture($hasher);
        $this->seedCoexistenceTwoDimensionalFixture($hasher);
        $this->seedDeviceFixtures($hasher);
        $this->seedThreeDimensionalFixtures($hasher);
        $this->seedTenantAwareThreeDimensionalFixtures($hasher);
    }

    /**
     * Benchmark the 2D bearer path with no device hint.
     *
     * @return void
     */
    public function runAccessOnlyBearer(): void
    {
        $guard = $this->makeGuard(
            'access_only',
            $this->accessOnlyProvider,
            $this->makeBearerRequest('/bench/jwt/access-only', $this->accessOnlyToken),
        );

        $guard->user();
    }

    /**
     * Benchmark the warm access-only bearer path with the shared identity cache
     * already primed.
     *
     * @return void
     */
    public function runAccessOnlyBearerWarmIdentityCache(): void
    {
        $this->primeAccessOnlyWarmCache();

        $guard = $this->makeGuard(
            'access_only',
            $this->accessOnlyProvider,
            $this->makeBearerRequest('/bench/jwt/access-only-warm', $this->accessOnlyToken),
            $this->warmResolutionCache,
        );

        $guard->user();
    }

    /**
     * Benchmark the device-bearing bearer path when the listener should skip
     * the debounced timestamp write.
     *
     * @return void
     */
    public function runDeviceBearerNoWrite(): void
    {
        $guard = $this->makeGuard(
            'device_api',
            $this->deviceProvider,
            $this->makeBearerRequest('/bench/jwt/device-fresh', $this->deviceFreshToken),
        );

        $guard->user();
    }

    /**
     * Benchmark the device-bearing bearer path when the listener must persist
     * `last_logged_in_at`.
     *
     * @return void
     */
    public function runDeviceBearerWithWrite(): void
    {
        $token = $this->deviceWriteTokens[$this->deviceWriteIndex % count($this->deviceWriteTokens)];
        $this->deviceWriteIndex++;

        $guard = $this->makeGuard(
            'device_api',
            $this->deviceProvider,
            $this->makeBearerRequest('/bench/jwt/device-write', $token),
        );

        $guard->user();
    }

    /**
     * Benchmark the 3D principal-resolution bearer path.
     *
     * @return void
     */
    public function runThreeDimensionalBearer(): void
    {
        $guard = $this->makeGuard(
            'api_3d',
            $this->threeDProvider,
            $this->makeBearerRequest('/bench/jwt/3d', $this->threeDToken),
        );

        $guard->user();
    }

    /**
     * Benchmark the tenant-aware 3D bearer path including tenant access.
     *
     * @return void
     */
    public function runThreeDimensionalBearerTenantAccess(): void
    {
        $guard = $this->makeGuard(
            'tenant_api_3d',
            $this->tenantAwareThreeDProvider,
            $this->makeBearerRequest('/bench/jwt/tenant-3d', $this->tenantAwareThreeDToken),
        );

        $guard->user();
        $guard->principal()?->getIdentity();
        $guard->tenant();
        $guard->type();
    }

    /**
     * Benchmark the tenant-aware 3D bearer path for a non-default tenant hint.
     *
     * @return void
     */
    public function runThreeDimensionalBearerSecondaryTenantAccess(): void
    {
        $guard = $this->makeGuard(
            'tenant_api_3d',
            $this->tenantAwareThreeDProvider,
            $this->makeBearerRequest('/bench/jwt/tenant-3d-secondary', $this->tenantAwareSecondaryToken),
        );

        $guard->user();
        $guard->principal()?->getIdentity();
        $guard->tenant();
        $guard->type();
    }

    /**
     * Benchmark the warm tenant-aware 3D bearer path including tenant access.
     *
     * @return void
     */
    public function runThreeDimensionalBearerTenantAccessWarmIdentityCache(): void
    {
        $this->primeTenantAwareWarmCache();

        $guard = $this->makeGuard(
            'tenant_api_3d',
            $this->tenantAwareThreeDProvider,
            $this->makeBearerRequest('/bench/jwt/tenant-3d-warm', $this->tenantAwareThreeDToken),
            $this->warmResolutionCache,
        );

        $guard->user();
        $guard->principal()?->getIdentity();
        $guard->tenant();
        $guard->type();
    }

    /**
     * Benchmark sequential authentication through distinct 2D and 3D guards.
     *
     * @return void
     */
    public function runGuardCoexistenceBearer(): void
    {
        $twoDimensionalGuard = $this->makeGuard(
            'api_2d',
            $this->coexistTwoDProvider,
            $this->makeBearerRequest('/bench/jwt/coexist-2d', $this->coexistTwoDToken),
        );

        $twoDimensionalGuard->user();
        $twoDimensionalGuard->principal(); // @phpstan-ignore method.resultUnused

        $threeDimensionalGuard = $this->makeGuard(
            'api_3d',
            $this->threeDProvider,
            $this->makeBearerRequest('/bench/jwt/coexist-3d', $this->threeDToken),
        );

        $threeDimensionalGuard->user();
        $threeDimensionalGuard->principal(); // @phpstan-ignore method.resultUnused
    }

    /**
     * Create the shared tables once.
     *
     * @return void
     */
    private function createSchema(): void
    {
        $schema = BenchDatabase::schema();

        if (!$schema->hasTable('access_only_identities')) {
            $schema->create('access_only_identities', static function (Blueprint $blueprint): void {
                $blueprint->id();
                $blueprint->string('email')->unique();
                $blueprint->string('password');
                $blueprint->timestamps();
            });
        }

        if (!$schema->hasTable('integration_identities')) {
            $schema->create('integration_identities', static function (Blueprint $blueprint): void {
                $blueprint->increments('id');
                $blueprint->string('email')->unique();
                $blueprint->string('password');
                $blueprint->boolean('is_active')->default(true);
                $blueprint->timestamps();
            });
        }

        if (!$schema->hasTable('coexist_2d_identities')) {
            $schema->create('coexist_2d_identities', static function (Blueprint $blueprint): void {
                $blueprint->increments('id');
                $blueprint->string('email')->unique();
                $blueprint->string('password');
                $blueprint->boolean('is_active')->default(true);
                $blueprint->timestamps();
            });
        }

        if (!$schema->hasTable('coexist_3d_identities')) {
            $schema->create('coexist_3d_identities', static function (Blueprint $blueprint): void {
                $blueprint->increments('id');
                $blueprint->string('email')->unique();
                $blueprint->string('password');
                $blueprint->boolean('is_active')->default(true);
                $blueprint->timestamps();
            });
        }

        if (!$schema->hasTable('coexist_3d_principals')) {
            $schema->create('coexist_3d_principals', static function (Blueprint $blueprint): void {
                $blueprint->increments('id');
                $blueprint->unsignedInteger('identity_id');
                $blueprint->string('name');
                $blueprint->boolean('is_active')->default(true);
                $blueprint->timestamps();
            });
        }

        if (!$schema->hasTable('tenant_aware_3d_identities')) {
            $schema->create('tenant_aware_3d_identities', static function (Blueprint $blueprint): void {
                $blueprint->increments('id');
                $blueprint->string('email')->unique();
                $blueprint->string('password');
                $blueprint->boolean('is_active')->default(true);
                $blueprint->timestamps();
            });
        }

        if (!$schema->hasTable('tenant_aware_3d_tenants')) {
            $schema->create('tenant_aware_3d_tenants', static function (Blueprint $blueprint): void {
                $blueprint->increments('id');
                $blueprint->string('name');
                $blueprint->string('type');
                $blueprint->timestamps();
            });
        }

        if (!$schema->hasTable('tenant_aware_3d_principals')) {
            $schema->create('tenant_aware_3d_principals', static function (Blueprint $blueprint): void {
                $blueprint->increments('id');
                $blueprint->unsignedInteger('identity_id');
                $blueprint->unsignedInteger('tenant_id');
                $blueprint->string('name');
                $blueprint->boolean('is_active')->default(true);
                $blueprint->timestamps();
            });
        }

        if (!$schema->hasTable('devices')) {
            $schema->create('devices', static function (Blueprint $blueprint): void {
                $blueprint->uuid('id')->primary();
                $blueprint->string('authenticatable_type');
                $blueprint->string('authenticatable_id');
                $blueprint->index(['authenticatable_type', 'authenticatable_id']);
                $blueprint->string('os');
                $blueprint->string('refresh_key', 64)->nullable()->index();
                $blueprint->timestamp('revoked_at')->nullable();
                $blueprint->timestamp('last_logged_in_at')->nullable();
                $blueprint->timestamp('last_mfa_verified_at')->nullable();
                $blueprint->timestamps();
            });
        }
    }

    /**
     * Seed the no-device 2D bearer fixture.
     *
     * @param  \Illuminate\Contracts\Hashing\Hasher  $hasher
     * @return void
     */
    private function seedAccessOnlyFixture(Hasher $hasher): void
    {
        $identity = PerformanceAccessOnlyIdentity::query()->first();

        if (!$identity instanceof PerformanceAccessOnlyIdentity) {

            $identity = new PerformanceAccessOnlyIdentity;
            $identity->forceFill([
                'email'    => self::ACCESS_ONLY_EMAIL,
                'password' => $hasher->make(self::PASSWORD),
            ]);
            $identity->save();
        }

        $this->accessOnlyToken = $this->tokens->issueAccessToken($identity, $identity, null);
    }

    /**
     * Seed the 2D coexistence bearer fixture.
     *
     * @param  \Illuminate\Contracts\Hashing\Hasher  $hasher
     * @return void
     */
    private function seedCoexistenceTwoDimensionalFixture(Hasher $hasher): void
    {
        $identity = Coexist2dIdentity::query()->first();

        if (!$identity instanceof Coexist2dIdentity) {

            $identity = new Coexist2dIdentity;
            $identity->forceFill([
                'email'     => self::COEXIST_TWO_D_EMAIL,
                'password'  => $hasher->make(self::PASSWORD),
                'is_active' => true,
            ]);
            $identity->save();
        }

        $this->coexistTwoDToken = $this->tokens->issueAccessToken($identity, $identity, null);
    }

    /**
     * Seed the device-backed bearer fixtures.
     *
     * @param  \Illuminate\Contracts\Hashing\Hasher  $hasher
     * @return void
     */
    private function seedDeviceFixtures(Hasher $hasher): void
    {
        $identity = IntegrationIdentity::query()->first();

        if (!$identity instanceof IntegrationIdentity) {

            $identity            = new IntegrationIdentity;
            $identity->email     = self::DEVICE_EMAIL;
            $identity->password  = $hasher->make(self::PASSWORD);
            $identity->is_active = true;
            $identity->save();
        }

        $freshDevice = Device::query()->where('os', 'bench-device-fresh')->first();

        /** @var string $identityId */
        $identityId = $identity->getKey();

        if (!$freshDevice instanceof Device) {
            $freshDevice = new Device;
            $freshDevice->forceFill([
                'authenticatable_type' => IntegrationIdentity::class,
                'authenticatable_id'   => $identityId,
                'os'                   => 'bench-device-fresh',
                'last_logged_in_at'    => Carbon::now(),
            ])->save();
        }

        $this->deviceFreshToken = $this->tokens->issueAccessToken($identity, $identity, $freshDevice);

        if ($this->deviceWriteTokens !== []) {
            return;
        }

        for ($index = 0; $index < self::TOKEN_POOL_SIZE; $index++) {

            $device = new Device;
            $device->forceFill([
                'authenticatable_type' => IntegrationIdentity::class,
                'authenticatable_id'   => $identityId,
                'os'                   => 'bench-device-write-' . $index,
                'last_logged_in_at'    => null,
            ])->save();

            $this->deviceWriteTokens[] = $this->tokens->issueAccessToken($identity, $identity, $device);
        }
    }

    /**
     * Seed the 3D bearer fixture.
     *
     * @param  \Illuminate\Contracts\Hashing\Hasher  $hasher
     * @return void
     */
    private function seedThreeDimensionalFixtures(Hasher $hasher): void
    {
        $identity = Coexist3dIdentity::query()->first();

        if (!$identity instanceof Coexist3dIdentity) {

            $identity            = new Coexist3dIdentity;
            $identity->email     = self::THREE_D_EMAIL;
            $identity->password  = $hasher->make(self::PASSWORD);
            $identity->is_active = true;
            $identity->save();
        }

        $principal = Coexist3dPrincipal::query()->where('identity_id', $identity->getKey())->first();

        if (!$principal instanceof Coexist3dPrincipal) {

            $identityKey = $identity->getKey();

            if (!is_int($identityKey)) {
                throw new \LogicException('Expected Coexist3dIdentity primary key to be an integer.');
            }

            $principal              = new Coexist3dPrincipal;
            $principal->identity_id = $identityKey;
            $principal->name        = 'bench-3d-principal';
            $principal->is_active   = true;
            $principal->save();
        }

        $this->threeDToken = $this->tokens->issueAccessToken($identity, $principal, null);
    }

    /**
     * Seed the tenant-aware 3D bearer fixture.
     *
     * @param  \Illuminate\Contracts\Hashing\Hasher  $hasher
     * @return void
     */
    private function seedTenantAwareThreeDimensionalFixtures(Hasher $hasher): void
    {
        $identity = TenantAware3dIdentity::query()->first();

        if (!$identity instanceof TenantAware3dIdentity) {

            $identity            = new TenantAware3dIdentity;
            $identity->email     = self::TENANT_THREE_D_EMAIL;
            $identity->password  = $hasher->make(self::PASSWORD);
            $identity->is_active = true;
            $identity->save();
        }

        $tenant = TenantAware3dTenant::query()->first();

        if (!$tenant instanceof TenantAware3dTenant) {

            $tenant       = new TenantAware3dTenant;
            $tenant->name = 'Bench Tenant Staff';
            $tenant->type = 'staff';
            $tenant->save();
        }

        $principal = TenantAware3dPrincipal::query()
            ->where('identity_id', $identity->getKey())
            ->where('name', 'bench-tenant-3d-principal')
            ->first();

        if (!$principal instanceof TenantAware3dPrincipal) {

            /** @var int $identityKey */
            $identityKey = $identity->getKey();
            /** @var int $tenantKey */
            $tenantKey = $tenant->getKey();

            $principal              = new TenantAware3dPrincipal;
            $principal->identity_id = $identityKey;
            $principal->tenant_id   = $tenantKey;
            $principal->name        = 'bench-tenant-3d-principal';
            $principal->is_active   = true;
            $principal->save();
        }

        $secondaryTenant = TenantAware3dTenant::query()
            ->where('name', 'Bench Tenant Customer')
            ->first();

        if (!$secondaryTenant instanceof TenantAware3dTenant) {

            $secondaryTenant       = new TenantAware3dTenant;
            $secondaryTenant->name = 'Bench Tenant Customer';
            $secondaryTenant->type = 'customer';
            $secondaryTenant->save();
        }

        $secondaryPrincipal = TenantAware3dPrincipal::query()
            ->where('identity_id', $identity->getKey())
            ->where('name', 'bench-tenant-3d-secondary-principal')
            ->first();

        if (!$secondaryPrincipal instanceof TenantAware3dPrincipal) {

            /** @var int $identityKey */
            $identityKey = $identity->getKey();
            /** @var int $secondaryTenantKey */
            $secondaryTenantKey = $secondaryTenant->getKey();

            $secondaryPrincipal              = new TenantAware3dPrincipal;
            $secondaryPrincipal->identity_id = $identityKey;
            $secondaryPrincipal->tenant_id   = $secondaryTenantKey;
            $secondaryPrincipal->name        = 'bench-tenant-3d-secondary-principal';
            $secondaryPrincipal->is_active   = true;
            $secondaryPrincipal->save();
        }

        $this->tenantAwareThreeDToken    = $this->tokens->issueAccessToken($identity, $principal, null);
        $this->tenantAwareSecondaryToken = $this->tokens->issueAccessToken($identity, $secondaryPrincipal, null);
    }

    /**
     * Instantiate a fresh JwtGuard for the supplied request.
     *
     * @param  string  $name
     * @param  \SineMacula\Laravel\Authentication\Providers\ModelProvider  $provider
     * @param  \Illuminate\Http\Request  $request
     * @param  ?\SineMacula\Laravel\Authentication\Cache\ResolutionCache  $resolutionCache
     * @return \SineMacula\Laravel\Authentication\Guards\JwtGuard
     */
    private function makeGuard(string $name, ModelProvider $provider, Request $request, ?ResolutionCache $resolutionCache = null): JwtGuard
    {
        $exchange = new RefreshTokenExchange(
            $this->tokens,
            BenchDatabase::connectionResolver(),
            $this->events,
            $this->resolver,
            $name,
        );

        return new JwtGuard(
            $name,
            $provider,
            $this->resolver,
            $this->events,
            $request,
            $this->timebox,
            $this->tokens,
            $exchange,
            $resolutionCache,
        );
    }

    /**
     * Build a real Request carrying a bearer token.
     *
     * @param  string  $path
     * @param  string  $token
     * @return \Illuminate\Http\Request
     */
    private function makeBearerRequest(string $path, #[\SensitiveParameter] string $token): Request
    {
        return Request::create($path, 'GET', [], [], [], [
            'HTTP_AUTHORIZATION' => 'Bearer ' . $token,
        ]);
    }

    /**
     * Prime the warm cache used by the access-only bearer benchmark.
     *
     * @return void
     */
    private function primeAccessOnlyWarmCache(): void
    {
        if ($this->accessOnlyWarmCachePrimed) {
            return;
        }

        $this->makeGuard(
            'access_only',
            $this->accessOnlyProvider,
            $this->makeBearerRequest('/bench/jwt/access-only-cache-prime', $this->accessOnlyToken),
            $this->warmResolutionCache,
        )->user();

        $this->accessOnlyWarmCachePrimed = true;
    }

    /**
     * Prime the warm cache used by the tenant-aware bearer benchmark.
     *
     * @return void
     */
    private function primeTenantAwareWarmCache(): void
    {
        if ($this->tenantAwareWarmCachePrimed) {
            return;
        }

        $this->makeGuard(
            'tenant_api_3d',
            $this->tenantAwareThreeDProvider,
            $this->makeBearerRequest('/bench/jwt/tenant-3d-cache-prime', $this->tenantAwareThreeDToken),
            $this->warmResolutionCache,
        )->user();

        $this->tenantAwareWarmCachePrimed = true;
    }
}
