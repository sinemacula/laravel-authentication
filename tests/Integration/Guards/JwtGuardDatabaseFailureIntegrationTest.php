<?php

declare(strict_types = 1);

namespace Tests\Integration\Guards;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\QueryException;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\AuthManager;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenExchange;
use Tests\Integration\Fixtures\UnreachableDevice;
use Tests\Integration\Fixtures\UnreachableDeviceIdentity;
use Tests\TestCase;

/**
 * A database that cannot be reached surfaces as a server error on refresh and
 * on bearer requests, not as an unknown device.
 *
 * The device model lives on a connection whose database does not exist, so the
 * device lookup fails while connecting, and an outage must not read as an
 * unknown device (a silent sign-out, or a 401 for every request).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RefreshTokenExchange::class)]
#[CoversClass(JwtGuard::class)]
final class JwtGuardDatabaseFailureIntegrationTest extends TestCase
{
    /** @var string Connection whose database cannot be opened. */
    private const string UNREACHABLE_CONNECTION = 'unreachable';

    /** @var string Well-formed id of the device the token names. */
    private const string DEVICE_ID = '0190f1d2-7c4e-7a3b-9f10-2b3c4d5e6f70';

    /**
     * Create the identity table.
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
            $blueprint->timestamps();
        });
    }

    /**
     * Drop the identity table.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Schema::dropIfExists('stub_principals');

        parent::tearDown();
    }

    /**
     * The connection failure propagates out of `refresh()` as a
     * `QueryException` naming the unreachable connection.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testRefreshPropagatesAConnectionFailureDuringDeviceLookup(): void
    {
        config()->set('authentication.device.model', UnreachableDevice::class);

        $device = new UnreachableDevice;
        $device->forceFill(['id' => self::DEVICE_ID]);

        $refreshToken = $this->authManager()->jwt('api')->issueRefreshToken($device, 'rotation-id');

        app()->instance('request', Request::create('/refresh', 'POST'));

        $guard = $this->authManager()->guard('api');

        assert($guard instanceof JwtGuard);

        $this->expectException(QueryException::class);
        $this->expectExceptionMessage('Connection: ' . self::UNREACHABLE_CONNECTION);

        $guard->refresh($refreshToken);
    }

    /**
     * A bearer request whose `did` lookup cannot connect answers with a server
     * error carrying the connection failure, not a 401.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testBearerAnswersAConnectionFailureDuringDeviceLookupWithAServerError(): void
    {
        $identity = new UnreachableDeviceIdentity;
        $identity->forceFill(['email' => 'outage@example.test', 'password' => 'irrelevant'])->save();

        $device = new UnreachableDevice;
        $device->forceFill(['id' => self::DEVICE_ID]);

        $token = $this->authManager()->jwt('api')->issueAccessToken($identity, $identity, $device);

        Route::middleware('auth:api')->get('/me', static fn (): string => 'ok');

        $response = $this->withHeaders(['Authorization' => 'Bearer ' . $token])->getJson('/me');

        $response->assertInternalServerError();

        self::assertInstanceOf(QueryException::class, $response->exception);
        self::assertStringContainsString('Connection: ' . self::UNREACHABLE_CONNECTION, $response->exception->getMessage());
    }

    /**
     * Configure the `api` guard and a connection whose database file does not
     * exist.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        /** @var \Illuminate\Config\Repository $config */
        $config = app(ConfigRepository::class);

        $config->set('database.connections.' . self::UNREACHABLE_CONNECTION, [
            'driver'   => 'sqlite',
            'database' => sys_get_temp_dir() . '/laravel-authentication-missing/auth.sqlite',
            'prefix'   => '',
        ]);

        $config->set('auth.guards.api', [
            'driver'   => 'jwt',
            'provider' => 'identities',
        ]);

        $config->set('auth.providers.identities', [
            'driver' => 'model',
            'model'  => UnreachableDeviceIdentity::class,
        ]);
    }

    /**
     * Resolve the package auth manager with no cached guards.
     *
     * @return \SineMacula\Laravel\Authentication\AuthManager
     */
    private function authManager(): AuthManager
    {
        $manager = app('auth');

        assert($manager instanceof AuthManager);

        $manager->forgetGuards();

        return $manager;
    }
}
