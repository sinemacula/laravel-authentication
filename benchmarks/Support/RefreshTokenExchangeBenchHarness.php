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
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenHasher;
use SineMacula\Laravel\Authentication\Listeners\UpdateDeviceTimestamp;
use SineMacula\Laravel\Authentication\Models\Device;
use SineMacula\Laravel\Authentication\Providers\ModelProvider;
use SineMacula\Laravel\Authentication\Resolvers\DefaultPrincipalResolver;
use Tests\Unit\Stubs\StubPrincipal;

/**
 * Runtime benchmark fixtures for refresh-token exchanges.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Ltd
 */
final class RefreshTokenExchangeBenchHarness
{
    private const string SECRET   = 'benchmark-refresh-secret-key-with-at-least-32-bytes!';
    private const string EMAIL    = 'bench-refresh@example.test';
    private const string PASSWORD = 'correct horse battery staple';

    /** @var int Number of mutable success-path tokens to pre-seed. */
    private const int TOKEN_POOL_SIZE = 128;

    /** @var \SineMacula\Laravel\Authentication\Jwt\JwtTokenService */
    private readonly JwtTokenService $tokens;

    /** @var \SineMacula\Laravel\Authentication\Providers\ModelProvider */
    private readonly ModelProvider $provider;

    /** @var \SineMacula\Laravel\Authentication\Resolvers\DefaultPrincipalResolver */
    private readonly DefaultPrincipalResolver $resolver;

    /** @var \Illuminate\Contracts\Events\Dispatcher */
    private readonly DispatcherContract $events;

    /** @var \Illuminate\Support\Timebox */
    private readonly Timebox $timebox;

    /** @var string Token targeting a nonexistent device. */
    private string $unknownDeviceToken;

    /** @var string Token with a mismatched rotation ID. */
    private string $rotationMismatchToken;

    /** @var list<string> */
    private array $successTokens = [];

    /** @var int Current index into the success-token pool. */
    private int $successIndex = 0;

    /**
     * Seed the refresh benchmark fixtures.
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

        $this->tokens   = new JwtTokenService(self::SECRET, 'HS256', 15, 60 * 24 * 30);
        $this->provider = new ModelProvider($hasher, StubPrincipal::class);
        $this->timebox  = new Timebox;

        $this->createSchema();
        $this->seedFixtures($hasher);
    }

    /**
     * Benchmark refresh success.
     *
     * @return void
     */
    public function runRefreshSuccess(): void
    {
        $token = $this->successTokens[$this->successIndex % count($this->successTokens)];
        $this->successIndex++;

        $this->makeGuard()->refresh($token);
    }

    /**
     * Benchmark the unknown-device failure path.
     *
     * @return void
     */
    public function runUnknownDeviceFailure(): void
    {
        $this->makeGuard()->refresh($this->unknownDeviceToken);
    }

    /**
     * Benchmark the rotation-mismatch failure path.
     *
     * @return void
     */
    public function runRotationMismatchFailure(): void
    {
        $this->makeGuard()->refresh($this->rotationMismatchToken);
    }

    /**
     * Create the shared tables once.
     *
     * @return void
     */
    private function createSchema(): void
    {
        $schema = BenchDatabase::schema();

        if (!$schema->hasTable('stub_principals')) {
            $schema->create('stub_principals', static function (Blueprint $blueprint): void {
                $blueprint->increments('id');
                $blueprint->string('email')->unique();
                $blueprint->string('password');
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
     * Seed success and failure fixtures.
     *
     * @param  \Illuminate\Contracts\Hashing\Hasher  $hasher
     * @return void
     */
    private function seedFixtures(Hasher $hasher): void
    {
        $identity = StubPrincipal::query()->first();

        if (!$identity instanceof StubPrincipal) {
            $identity            = new StubPrincipal;
            $identity->email     = self::EMAIL;
            $identity->password  = $hasher->make(self::PASSWORD);
            $identity->is_active = true;
            $identity->save();
        }

        if ($this->successTokens === []) {
            for ($index = 0; $index < self::TOKEN_POOL_SIZE; $index++) {
                $rotationId = 'bench-refresh-success-' . $index;

                $device = new Device;
                $device->forceFill([
                    'authenticatable_type' => StubPrincipal::class,
                    'authenticatable_id'   => (string) $identity->getKey(), // @phpstan-ignore cast.string
                    'os'                   => 'bench-refresh-success-' . $index,
                    'refresh_key'          => RefreshTokenHasher::hash($rotationId),
                    'last_logged_in_at'    => Carbon::now(),
                ])->save();

                $this->successTokens[] = $this->tokens->issueRefreshToken($device, $rotationId, $identity);
            }
        }

        $missingDevice = new Device;
        $missingDevice->forceFill(['id' => 'bench-missing-device']);
        $this->unknownDeviceToken = $this->tokens->issueRefreshToken($missingDevice, 'bench-missing-device-rotation');

        $mismatchDevice = Device::query()->where('os', 'bench-refresh-mismatch')->first();

        if (!$mismatchDevice instanceof Device) {
            $mismatchDevice = new Device;
            $mismatchDevice->forceFill([
                'authenticatable_type' => StubPrincipal::class,
                'authenticatable_id'   => (string) $identity->getKey(), // @phpstan-ignore cast.string
                'os'                   => 'bench-refresh-mismatch',
                'refresh_key'          => RefreshTokenHasher::hash('stored-rotation-id'),
            ])->save();
        }

        $this->rotationMismatchToken = $this->tokens->issueRefreshToken($mismatchDevice, 'tampered-rotation-id');
    }

    /**
     * Instantiate a fresh JwtGuard for refresh benchmarking.
     *
     * @return \SineMacula\Laravel\Authentication\Guards\JwtGuard
     */
    private function makeGuard(): JwtGuard
    {
        $exchange = new RefreshTokenExchange(
            $this->tokens,
            BenchDatabase::connectionResolver(),
            $this->events,
            $this->resolver,
            'api',
        );

        return new JwtGuard(
            'api',
            $this->provider,
            $this->resolver,
            $this->events,
            Request::create('/bench/refresh', 'POST'),
            $this->timebox,
            $this->tokens,
            $exchange,
        );
    }
}
