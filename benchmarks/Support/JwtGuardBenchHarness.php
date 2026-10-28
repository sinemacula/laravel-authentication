<?php

declare(strict_types = 1);

namespace Benchmarks\Support;

use Carbon\Carbon;
use Firebase\JWT\JWT;
use Illuminate\Container\Container;
use Illuminate\Contracts\Events\Dispatcher as DispatcherContract;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Events\Dispatcher;
use Illuminate\Hashing\BcryptHasher;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Facade;
use Illuminate\Support\Timebox;
use SineMacula\Laravel\Authentication\Events\DeviceAuthenticated;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Jwt\JwtKeyring;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenService;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenExchange;
use SineMacula\Laravel\Authentication\Jwt\TokenLifetimes;
use SineMacula\Laravel\Authentication\Listeners\RecordDeviceUsage;
use SineMacula\Laravel\Authentication\Models\Device;
use SineMacula\Laravel\Authentication\Providers\ModelProvider;
use SineMacula\Laravel\Authentication\Resolvers\DefaultPrincipalResolver;
use SineMacula\Laravel\Authentication\Sessions\SessionService;
use Tests\Integration\Fixtures\Coexist2dIdentity;
use Tests\Integration\Fixtures\Coexist3dIdentity;
use Tests\Integration\Fixtures\Coexist3dPrincipal;
use Tests\Integration\Fixtures\IntegrationIdentity;
use Tests\Integration\Fixtures\TenantAware3dIdentity;
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

    /** @var string Path of the requests the set-up check sends. */
    private const string CHECK_PATH = '/bench/check';

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

    /** @var string 2D access-only bearer token. */
    private string $accessOnlyToken;

    /** @var string Coexist 2D bearer token. */
    private string $coexistTwoDToken;

    /** @var string Device bearer with fresh timestamp; empty until seeded, which the set-up check refuses. */
    private string $deviceFreshToken = '';

    /** @var string 3D bearer token. */
    private string $threeDToken;

    /** @var string Tenant-aware 3D bearer token. */
    private string $tenantAwareThreeDToken;

    /** @var string Tenant-aware secondary bearer token. */
    private string $tenantAwareSecondaryToken;

    /** @var list<string> */
    private array $deviceWriteTokens = [];

    /** @var string Device bearer token, outside the write pool, whose device has never been used, for the set-up check. */
    private string $deviceWriteCheckToken = '';

    /** @var int Current index into the write-token pool. */
    private int $deviceWriteIndex = 0;

    /**
     * Seed the bearer-auth benchmark fixtures, and check that each path reaches
     * the outcome it measures.
     *
     * @throws \LogicException
     * @throws \Random\RandomException
     */
    public function __construct()
    {
        BenchDatabase::boot();

        $now = Carbon::createStrict(2026, 4, 10, 12, 0, 0);
        Carbon::setTestNow($now);
        JWT::$timestamp = $now->getTimestamp();

        $config = JwtBenchSetup::config();

        $container = new Container;
        $container->instance('config', $config);
        Facade::setFacadeApplication($container);

        $this->resolver = new DefaultPrincipalResolver;
        $this->events   = new Dispatcher($container);
        $this->events->setTransactionManagerResolver(static fn (): null => null);
        $this->events->listen(
            DeviceAuthenticated::class,
            new RecordDeviceUsage,
        );

        $hasher = new BcryptHasher;

        $this->tokens = new JwtTokenService(
            JwtKeyring::fromKeyMap(['bench' => self::SECRET], 'bench', 'HS256'),
            'api',
            new TokenLifetimes(15, 60 * 24 * 30, 60 * 24 * 180, 30),
            30,
        );
        $this->timebox = new Timebox;

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

        $this->assertEachPathReachesItsOutcome();
    }

    /**
     * Benchmark the 2D bearer path with no device hint.
     *
     * @return void
     */
    public function runAccessOnlyBearer(): void
    {
        $this->bearer('access_only', $this->accessOnlyProvider, '/bench/jwt/access-only', $this->accessOnlyToken);
    }

    /**
     * Benchmark the device-bearing bearer path when the listener should skip
     * the debounced timestamp write.
     *
     * @return void
     */
    public function runDeviceBearerNoWrite(): void
    {
        $this->bearer('device_api', $this->deviceProvider, '/bench/jwt/device-fresh', $this->deviceFreshToken);
    }

    /**
     * Benchmark the device-bearing bearer path when the listener must persist
     * `last_used_at`.
     *
     * @return void
     */
    public function runDeviceBearerWithWrite(): void
    {
        $token = $this->deviceWriteTokens[$this->deviceWriteIndex % count($this->deviceWriteTokens)];
        $this->deviceWriteIndex++;

        $this->bearer('device_api', $this->deviceProvider, '/bench/jwt/device-write', $token);
    }

    /**
     * Benchmark the 3D principal-resolution bearer path.
     *
     * @return void
     */
    public function runThreeDimensionalBearer(): void
    {
        $this->bearer('api_3d', $this->threeDProvider, '/bench/jwt/3d', $this->threeDToken);
    }

    /**
     * Benchmark the tenant-aware 3D bearer path including tenant access.
     *
     * @return void
     */
    public function runThreeDimensionalBearerTenantAccess(): void
    {
        $guard = $this->bearer('tenant_api_3d', $this->tenantAwareThreeDProvider, '/bench/jwt/tenant-3d', $this->tenantAwareThreeDToken);

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
        $guard = $this->bearer('tenant_api_3d', $this->tenantAwareThreeDProvider, '/bench/jwt/tenant-3d-secondary', $this->tenantAwareSecondaryToken);

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
        $this->bearer('api_2d', $this->coexistTwoDProvider, '/bench/jwt/coexist-2d', $this->coexistTwoDToken)->principal(); // @phpstan-ignore method.resultUnused
        $this->bearer('api_3d', $this->threeDProvider, '/bench/jwt/coexist-3d', $this->threeDToken)->principal(); // @phpstan-ignore method.resultUnused
    }

    /**
     * Create the benchmark schema when missing.
     *
     * @return void
     */
    private function createSchema(): void
    {
        BenchSchema::ensureAccessOnlyIdentityTable();

        foreach (['integration_identities', 'coexist_2d_identities', 'coexist_3d_identities', 'tenant_aware_3d_identities'] as $table) {
            BenchSchema::ensureIdentityTable($table);
        }

        BenchSchema::ensureCoexistPrincipalTable();
        BenchSchema::ensureTenantTables();
        BenchSchema::ensureDeviceTable();
    }

    /**
     * Seed the no-device 2D bearer fixture.
     *
     * @param  \Illuminate\Contracts\Hashing\Hasher  $hasher
     * @return void
     *
     * @throws \Random\RandomException
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
     *
     * @throws \Random\RandomException
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
     *
     * @throws \Random\RandomException
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

        $freshDevice = Device::query()->where('client_name', 'bench-device-fresh')->first();

        /** @var string $identityId */
        $identityId = $identity->getKey();

        if (!$freshDevice instanceof Device) {
            $freshDevice = new Device;
            $freshDevice->forceFill([
                ...BenchSchema::signedIn('device_api'),
                'authenticatable_type' => IntegrationIdentity::class,
                'authenticatable_id'   => $identityId,
                'principal_type'       => $identity->getMorphClass(),
                'principal_id'         => $identityId,
                'client_name'          => 'bench-device-fresh',
                'last_used_at'         => Carbon::now(),
            ])->save();
        }

        $this->deviceFreshToken = $this->tokens->issueAccessToken($identity, $identity, $freshDevice);

        if ($this->deviceWriteTokens !== []) {
            return;
        }

        $checkDevice = new Device;
        $checkDevice->forceFill([
            ...BenchSchema::signedIn('device_api'),
            'authenticatable_type' => IntegrationIdentity::class,
            'authenticatable_id'   => $identityId,
            'principal_type'       => $identity->getMorphClass(),
            'principal_id'         => $identityId,
            'client_name'          => 'bench-device-write-check',
            'last_used_at'         => null,
        ])->save();

        $this->deviceWriteCheckToken = $this->tokens->issueAccessToken($identity, $identity, $checkDevice);

        for ($index = 0; $index < self::TOKEN_POOL_SIZE; $index++) {

            $device = new Device;
            $device->forceFill([
                ...BenchSchema::signedIn('device_api'),
                'authenticatable_type' => IntegrationIdentity::class,
                'authenticatable_id'   => $identityId,
                'principal_type'       => $identity->getMorphClass(),
                'principal_id'         => $identityId,
                'client_name'          => 'bench-device-write-' . $index,
                'last_used_at'         => null,
            ])->save();

            $this->deviceWriteTokens[] = $this->tokens->issueAccessToken($identity, $identity, $device);
        }
    }

    /**
     * Seed the 3D bearer fixture.
     *
     * @param  \Illuminate\Contracts\Hashing\Hasher  $hasher
     * @return void
     *
     * @throws \Random\RandomException
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

            /** @var int $identityKey */
            $identityKey = $identity->getKey();

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
     *
     * @throws \Random\RandomException
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

        $principal = TenantFixtures::seedTenantPrincipal(
            $identity,
            TenantFixtures::seedTenant('Bench Tenant Staff', 'staff'),
            'bench-tenant-3d-principal',
        );

        $secondaryPrincipal = TenantFixtures::seedTenantPrincipal(
            $identity,
            TenantFixtures::seedTenant('Bench Tenant Customer', 'customer'),
            'bench-tenant-3d-secondary-principal',
        );

        $this->tenantAwareThreeDToken    = $this->tokens->issueAccessToken($identity, $principal, null);
        $this->tenantAwareSecondaryToken = $this->tokens->issueAccessToken($identity, $secondaryPrincipal, null);
    }

    /**
     * Run each benchmarked path once and throw unless it reaches the outcome
     * its name describes: every bearer authenticates, a device bearer binds its
     * device, writing its last use only on the path that measures the write, a
     * 3D bearer binds its principal, and a tenant-aware one its tenant. The
     * write path runs on a device of its own, outside the benchmark's pool.
     *
     * @return void
     *
     * @throws \LogicException
     */
    private function assertEachPathReachesItsOutcome(): void
    {
        BenchOutcome::assert('access-only bearer', $this->bearer('access_only', $this->accessOnlyProvider, self::CHECK_PATH, $this->accessOnlyToken)->hasUser());
        BenchOutcome::assert('2D coexistence bearer', $this->bearer('api_2d', $this->coexistTwoDProvider, self::CHECK_PATH, $this->coexistTwoDToken)->hasUser());
        BenchOutcome::assert('3D bearer', $this->bearer('api_3d', $this->threeDProvider, self::CHECK_PATH, $this->threeDToken)->principal() instanceof Coexist3dPrincipal);

        foreach ([$this->tenantAwareThreeDToken, $this->tenantAwareSecondaryToken] as $token) {
            BenchOutcome::assert('tenant-aware 3D bearer', $this->bearer('tenant_api_3d', $this->tenantAwareThreeDProvider, self::CHECK_PATH, $token)->tenant() !== null);
        }

        $devicePaths = [
            'device bearer without a write' => [$this->deviceFreshToken, false],
            'device bearer with a write'    => [$this->deviceWriteCheckToken, true],
        ];

        foreach ($devicePaths as $path => [$token, $writes]) {

            $bound      = false;
            $statements = BenchOutcome::statementsOf(function () use ($token, &$bound): void {
                $bound = $this->bearer('device_api', $this->deviceProvider, self::CHECK_PATH, $token)->device() !== null;
            });

            $wrote = array_filter($statements, static fn (string $statement): bool => str_starts_with($statement, 'update')) !== [];

            BenchOutcome::assert($path, $bound && $wrote === $writes);
        }
    }

    /**
     * Authenticate a bearer request through a fresh guard and return the guard.
     *
     * @param  string  $name
     * @param  \SineMacula\Laravel\Authentication\Providers\ModelProvider  $provider
     * @param  string  $path
     * @param  string  $token
     * @return \SineMacula\Laravel\Authentication\Guards\JwtGuard
     */
    private function bearer(string $name, ModelProvider $provider, string $path, #[\SensitiveParameter] string $token): JwtGuard
    {
        $guard = $this->makeGuard($name, $provider, $this->makeBearerRequest($path, $token));

        $guard->user();

        return $guard;
    }

    /**
     * Instantiate a fresh JwtGuard for the supplied request.
     *
     * @param  string  $name
     * @param  \SineMacula\Laravel\Authentication\Providers\ModelProvider  $provider
     * @param  \Illuminate\Http\Request  $request
     * @return \SineMacula\Laravel\Authentication\Guards\JwtGuard
     */
    private function makeGuard(string $name, ModelProvider $provider, Request $request): JwtGuard
    {
        $exchange = new RefreshTokenExchange(
            $this->tokens,
            $provider,
            BenchDatabase::connectionResolver(),
            static fn (): null => null,
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
            fn (JwtGuard $guard, \Closure $timebox): SessionService => new SessionService(
                $guard,
                $timebox,
                $this->tokens,
                new Container,
                BenchDatabase::connectionResolver(),
                static fn (): null => null,
            ),
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
}
