<?php

declare(strict_types = 1);

namespace Tests\Integration\Config;

use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Database\ConnectionResolverInterface;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Timebox;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\AuthenticationServiceProvider;
use SineMacula\Laravel\Authentication\Contracts\EloquentDevice;
use SineMacula\Laravel\Authentication\Facades\Auth as PackageAuth;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Http\RefreshTokenTransport;
use SineMacula\Laravel\Authentication\Jwt\RefreshResult;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenExchange;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenHasher;
use SineMacula\Laravel\Authentication\Models\Device;
use SineMacula\Laravel\Authentication\Runtime\GuardContext;
use SineMacula\Laravel\Authentication\Sessions\SessionService;
use Tests\Concerns\InteractsWithDevices;
use Tests\TestCase;
use Tests\Unit\Stubs\StubLookupIdentityProvider;
use Tests\Unit\Stubs\StubPrincipal;
use Tests\Unit\Stubs\StubTwoDPrincipalResolver;

/**
 * Integration test for the Device model override via package config.
 *
 * Verifies that overriding `config('authentication.device.model')` with a
 * custom `Device` subclass and `device.table` with a custom table name causes
 * the model, the shipped migration body, and the JWT guard's device-hydration
 * path to route through the override.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuthenticationServiceProvider::class)]
#[CoversClass(Device::class)]
#[CoversClass(RefreshTokenExchange::class)]
final class DeviceModelOverrideTest extends TestCase
{
    use InteractsWithDevices;

    /** @var class-string<\SineMacula\Laravel\Authentication\Models\Device> */
    private string $customModel;

    /**
     * Configure the custom device model class and table name, then replay the
     * shipped migration body inline against the in-memory connection so the
     * custom table exists for the test, and run the shipped rate limits
     * migration, whose table the refresh exchange counts failures in.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $anonymous = new class extends Device {};

        /** @var class-string<\SineMacula\Laravel\Authentication\Models\Device> $class */
        $class = $anonymous::class;

        $this->customModel = $class;

        config()->set('authentication.device.model', $this->customModel);
        config()->set('authentication.device.table', 'custom_devices');

        self::createDeviceTable('custom_devices');

        (include __DIR__ . '/../../../database/migrations/2026_04_06_000002_create_rate_limits_table.php')->up();

        Schema::create('stub_principals', static function (Blueprint $blueprint): void {
            $blueprint->id();
            $blueprint->boolean('is_active')->default(true);
            $blueprint->timestamps();
        });
    }

    /**
     * Drop the custom tables on tear-down so each test starts clean.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Schema::dropIfExists('custom_devices');
        Schema::dropIfExists('stub_principals');
        Schema::dropIfExists('rate_limits');

        parent::tearDown();
    }

    /**
     * Instantiating the custom subclass yields a model whose table matches the
     * configured `device.table` value.
     *
     * @return void
     */
    public function testCustomTableNameAppliesToDeviceModel(): void
    {
        $model = new $this->customModel;

        self::assertSame('custom_devices', $model->getTable());
        self::assertInstanceOf(EloquentDevice::class, $model);
    }

    /**
     * The shipped migration body creates the custom table (not the default
     * `devices` table) when `device.table` is overridden.
     *
     * @return void
     */
    public function testCustomTableNameAppliesToShippedMigration(): void
    {
        self::assertTrue(Schema::hasTable('custom_devices'));
        self::assertFalse(Schema::hasTable('devices'));
    }

    /**
     * Invoking `JwtGuard::refresh()` with a refresh token whose `did` claim
     * points at a row in the custom table returns a refreshed access token
     * sourced from the overridden model class, binding an instance of that
     * class as the active device.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testGuardResolvesDeviceThroughCustomModelClass(): void
    {
        $principal = new StubPrincipal;
        $principal->forceFill(['is_active' => true])->save();

        $plainRotationId = 'plain-rotation-id';

        /** @var \SineMacula\Laravel\Authentication\Models\Device $device */
        $device = new $this->customModel;
        $device->forceFill([
            ...self::liveSession('custom-jwt', $principal),
            'authenticatable_type' => StubPrincipal::class,
            'authenticatable_id'   => (string) $principal->getKey(), // @phpstan-ignore cast.string
            'refresh_key'          => RefreshTokenHasher::hash($plainRotationId),
        ])->save();

        $jwtService = PackageAuth::jwt('custom-jwt');

        $refreshToken = $jwtService->issueRefreshToken($device, $plainRotationId);

        $guard = $this->makeJwtGuard();

        $result = $guard->refresh($refreshToken);

        self::assertInstanceOf(RefreshResult::class, $result);
        self::assertNotSame('', $result->accessToken);
        self::assertNotSame('', $result->refreshToken);
        self::assertInstanceOf($this->customModel, $guard->device());
    }

    /**
     * Skip the parent's default `devices` migration so this test can verify
     * that the custom-table override is the only `devices`-shaped table on the
     * connection (TAC: `Schema::hasTable('devices') === false`).
     *
     * @return void
     */
    #[\Override]
    protected function defineDatabaseMigrations(): void {}

    /**
     * Register the manual `custom-jwt` guard config used by the guard-scoped
     * `Auth::jwt('custom-jwt')` issuance surface in this test.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        config()->set('auth.guards.custom-jwt', [
            'driver'   => 'jwt',
            'provider' => 'principals',
        ]);

        config()->set('auth.providers.principals', [
            'driver' => 'model',
            'model'  => StubPrincipal::class,
        ]);
    }

    /**
     * Build a `JwtGuard` wired against a stub identity provider that echoes a
     * persisted `StubPrincipal` for any identifier lookup, and a resolver that
     * treats the identity as its own principal (2D mode).
     *
     * @return \SineMacula\Laravel\Authentication\Guards\JwtGuard
     */
    private function makeJwtGuard(): JwtGuard
    {
        $provider = new StubLookupIdentityProvider;
        $resolver = new StubTwoDPrincipalResolver;
        $tokens   = PackageAuth::jwt('custom-jwt');
        $events   = app(Dispatcher::class);

        return new JwtGuard(
            'custom-jwt',
            $provider,
            $resolver,
            $events,
            app('request'),
            app(Timebox::class),
            $tokens,
            static fn (GuardContext $context): RefreshTokenExchange => new RefreshTokenExchange(
                $tokens,
                $context,
                app(ConnectionResolverInterface::class),
                static fn (): mixed => app('db.transactions'),
            ),
            static fn (JwtGuard $guard, \Closure $timebox): SessionService => new SessionService(
                $guard,
                $timebox,
                $tokens,
                app(),
                app(ConnectionResolverInterface::class),
                static fn (): mixed => app('db.transactions'),
            ),
            static fn (): RefreshTokenTransport => RefreshTokenTransport::forGuard('custom-jwt', config()),
        );
    }
}
