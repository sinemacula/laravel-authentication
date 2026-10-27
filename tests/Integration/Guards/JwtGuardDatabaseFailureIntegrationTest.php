<?php

declare(strict_types = 1);

namespace Tests\Integration\Guards;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\QueryException;
use Illuminate\Http\Request;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\AuthManager;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenExchange;
use SineMacula\Laravel\Authentication\Models\Device;
use Tests\TestCase;
use Tests\Unit\Stubs\StubPrincipal;

/**
 * Regression test: a database that cannot be reached surfaces as a server error
 * on refresh, not as an unknown device.
 *
 * The configured device model lives on a connection whose database does not
 * exist, so the device lookup fails while connecting. Before the fix the
 * exchange caught the resulting `QueryException` and answered `device_unknown`,
 * turning an outage into a silent sign-out.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RefreshTokenExchange::class)]
final class JwtGuardDatabaseFailureIntegrationTest extends TestCase
{
    /** @var string Connection whose database cannot be opened. */
    private const string UNREACHABLE_CONNECTION = 'unreachable';

    /** @var string Well-formed id of the device the refresh token names. */
    private const string DEVICE_ID = '0190f1d2-7c4e-7a3b-9f10-2b3c4d5e6f70';

    /**
     * The connection failure propagates out of `refresh()` as a
     * `QueryException` naming the unreachable connection. Before the fix the
     * exchange returned `null` with `device_unknown`, so the expectation fails
     * against it.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testRefreshPropagatesAConnectionFailureDuringDeviceLookup(): void
    {
        $unreachable = new class extends Device {
            /** @var string|\UnitEnum|null The connection name for the model. */
            protected $connection = 'unreachable';
        };

        config()->set('authentication.device.model', $unreachable::class);

        $device = $unreachable->newInstance();
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
            'model'  => StubPrincipal::class,
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
