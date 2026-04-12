<?php

declare(strict_types = 1);

namespace Benchmarks\Support;

// phpcs:disable Squiz.Commenting.VariableComment.Missing, Squiz.Commenting.FunctionComment.MissingReturn

use Carbon\Carbon;
use Firebase\JWT\JWT;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Container\Container;
use Illuminate\Contracts\Events\Dispatcher as DispatcherContract;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Events\Dispatcher;
use Illuminate\Hashing\BcryptHasher;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Facade;
use Illuminate\Support\Timebox;
use SineMacula\Laravel\Authentication\Events\DeviceAuthenticated;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenService;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenExchange;
use SineMacula\Laravel\Authentication\Listeners\UpdateDeviceTimestamp;
use SineMacula\Laravel\Authentication\Models\Device;
use SineMacula\Laravel\Authentication\Providers\ModelProvider;
use SineMacula\Laravel\Authentication\Resolvers\DefaultPrincipalResolver;
use Tests\Integration\Fixtures\Coexist3dIdentity;
use Tests\Integration\Fixtures\Coexist3dPrincipal;
use Tests\Integration\Fixtures\IntegrationIdentity;
use Tests\Performance\Fixtures\PerformanceAccessOnlyIdentity;

/**
 * Runtime benchmark fixtures for JwtGuard bearer-auth hot
 * paths.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Ltd
 */
final class JwtGuardBenchHarness
{
    private const string SECRET            = 'benchmark-secret-key-with-at-least-32-bytes!';
    private const string PASSWORD          = 'correct horse battery staple';
    private const string ACCESS_ONLY_EMAIL = 'bench-access-only@example.test';
    private const string DEVICE_EMAIL      = 'bench-device@example.test';
    private const string THREE_D_EMAIL     = 'bench-3d@example.test';

    /** @var int Number of mutable write-path tokens to pre-seed. */
    private const int TOKEN_POOL_SIZE = 128;

    /** @var \SineMacula\Laravel\Authentication\Jwt\JwtTokenService */
    private readonly JwtTokenService $tokens;

    /** @var \SineMacula\Laravel\Authentication\Providers\ModelProvider */
    private readonly ModelProvider $accessOnlyProvider;

    /** @var \SineMacula\Laravel\Authentication\Providers\ModelProvider */
    private readonly ModelProvider $deviceProvider;

    /** @var \SineMacula\Laravel\Authentication\Providers\ModelProvider */
    private readonly ModelProvider $threeDProvider;

    /** @var \SineMacula\Laravel\Authentication\Resolvers\DefaultPrincipalResolver */
    private readonly DefaultPrincipalResolver $resolver;

    /** @var \Illuminate\Contracts\Events\Dispatcher */
    private readonly DispatcherContract $events;

    /** @var \Illuminate\Support\Timebox */
    private readonly Timebox $timebox;

    /** @var string 2D access-only bearer token. */
    private string $accessOnlyToken;

    /** @var string Device bearer with fresh timestamp. */
    private string $deviceFreshToken;

    /** @var string 3D bearer token. */
    private string $threeDToken;

    /** @var list<string> */
    private array $deviceWriteTokens = [];

    /** @var int Current index into the write-token pool. */
    private int $deviceWriteIndex = 0;

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

        $this->tokens  = new JwtTokenService(self::SECRET, 'HS256', 15, 60 * 24 * 30);
        $this->timebox = new Timebox;

        $this->accessOnlyProvider = new ModelProvider($hasher, PerformanceAccessOnlyIdentity::class);
        $this->deviceProvider     = new ModelProvider($hasher, IntegrationIdentity::class);
        $this->threeDProvider     = new ModelProvider($hasher, Coexist3dIdentity::class);

        $this->createSchema();
        $this->seedAccessOnlyFixture($hasher);
        $this->seedDeviceFixtures($hasher);
        $this->seedThreeDimensionalFixtures($hasher);
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

        if (!$freshDevice instanceof Device) {
            $freshDevice = new Device;
            $freshDevice->forceFill([
                'authenticatable_type' => IntegrationIdentity::class,
                'authenticatable_id'   => (string) $identity->getKey(), // @phpstan-ignore cast.string
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
                'authenticatable_id'   => (string) $identity->getKey(), // @phpstan-ignore cast.string
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
