<?php

declare(strict_types = 1);

namespace Tests\Performance;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Models\Device;
use SineMacula\Laravel\Authentication\Facades\Auth as PackageAuth;
use Tests\Integration\Fixtures\Coexist3dIdentity;
use Tests\Integration\Fixtures\Coexist3dPrincipal;
use Tests\Integration\Fixtures\IntegrationIdentity;
use Tests\Performance\Fixtures\PerformanceAccessOnlyIdentity;

/**
 * Query-budget contracts for the main JwtGuard bearer-auth success paths.
 *
 * @internal
 */
#[CoversClass(JwtGuard::class)]
final class JwtGuardQueryBudgetTest extends PerformanceContractTestCase
{
    private const string ACCESS_ONLY_GUARD = 'access_only';

    private const string DEVICE_GUARD = 'device_api';

    private const string THREE_D_GUARD = 'api_3d';

    /**
     * Provision the fixture tables used by the three guard variants.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        Schema::create('access_only_identities', static function (Blueprint $blueprint): void {
            $blueprint->id();
            $blueprint->string('email')->unique();
            $blueprint->string('password');
            $blueprint->timestamps();
        });

        Schema::create('integration_identities', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('email')->unique();
            $blueprint->string('password');
            $blueprint->boolean('is_active')->default(true);
            $blueprint->timestamps();
        });

        Schema::create('coexist_3d_identities', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('email')->unique();
            $blueprint->string('password');
            $blueprint->boolean('is_active')->default(true);
            $blueprint->timestamps();
        });

        Schema::create('coexist_3d_principals', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->unsignedInteger('identity_id');
            $blueprint->string('name');
            $blueprint->boolean('is_active')->default(true);
            $blueprint->timestamps();
        });
    }

    /**
     * Release the fixture tables.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Schema::dropIfExists('coexist_3d_principals');
        Schema::dropIfExists('coexist_3d_identities');
        Schema::dropIfExists('integration_identities');
        Schema::dropIfExists('access_only_identities');

        parent::tearDown();
    }

    /**
     * A 2D bearer token with no usable device hint should only rehydrate the
     * identity row.
     *
     * @return void
     */
    public function testAccessOnlyBearerPathUsesSingleReadAndNoWrites(): void
    {
        $identity = $this->seedAccessOnlyIdentity();
        $token = PackageAuth::jwt(self::ACCESS_ONLY_GUARD)->issueAccessToken($identity, $identity, null);

        $this->bindRequestWithBearer('/perf/access-only', $token);

        $guard = $this->freshJwtGuard(self::ACCESS_ONLY_GUARD);

        $result = $this->assertQueryBudget(1, 0, static function () use ($guard): bool {
            $authenticated = $guard->check();
            $guard->principal();
            $guard->device();

            return $authenticated;
        });

        self::assertTrue($result);
    }

    /**
     * A bearer token with a valid device hint and a fresh last-seen timestamp
     * should do the identity read plus the device read, but no update.
     *
     * @return void
     */
    public function testBearerPathWithDeviceHintAndFreshTimestampUsesTwoReadsAndNoWrites(): void
    {
        $identity = $this->seedIntegrationIdentity('device-fresh@example.test');

        $device = new Device;
        $device->forceFill([
            'authenticatable_type' => IntegrationIdentity::class,
            'authenticatable_id'   => (string) $identity->getKey(), // @phpstan-ignore cast.string
            'os'                   => 'ios',
            'refresh_key'          => null,
            'last_logged_in_at'    => $this->now,
        ])->save();

        $token = PackageAuth::jwt(self::DEVICE_GUARD)->issueAccessToken($identity, $identity, $device);

        $this->bindRequestWithBearer('/perf/device-fresh', $token);

        $guard = $this->freshJwtGuard(self::DEVICE_GUARD);

        $result = $this->assertQueryBudget(2, 0, static function () use ($guard): bool {
            $authenticated = $guard->check();
            $guard->device();

            return $authenticated;
        });

        self::assertTrue($result);
    }

    /**
     * A stale or missing last-seen timestamp should add exactly one write to
     * the mandatory identity + device reads.
     *
     * @return void
     */
    public function testBearerPathWithDeviceHintAndStaleTimestampUsesTwoReadsAndOneWrite(): void
    {
        $identity = $this->seedIntegrationIdentity('device-stale@example.test');

        $device = new Device;
        $device->forceFill([
            'authenticatable_type' => IntegrationIdentity::class,
            'authenticatable_id'   => (string) $identity->getKey(), // @phpstan-ignore cast.string
            'os'                   => 'ios',
            'refresh_key'          => null,
            'last_logged_in_at'    => null,
        ])->save();

        $token = PackageAuth::jwt(self::DEVICE_GUARD)->issueAccessToken($identity, $identity, $device);

        $this->bindRequestWithBearer('/perf/device-stale', $token);

        $guard = $this->freshJwtGuard(self::DEVICE_GUARD);

        $result = $this->assertQueryBudget(2, 1, static function () use ($guard): bool {
            $authenticated = $guard->check();
            $guard->device();

            return $authenticated;
        });

        self::assertTrue($result);
    }

    /**
     * In 3D mode the bearer path should add one principal-resolution read on
     * top of the identity rehydration read.
     *
     * @return void
     */
    public function testThreeDimensionalBearerPathUsesTwoReadsAndNoWrites(): void
    {
        [$identity, $principal] = $this->seedThreeDimensionalFixtures();

        $token = PackageAuth::jwt(self::THREE_D_GUARD)->issueAccessToken($identity, $principal, null);

        $this->bindRequestWithBearer('/perf/3d', $token);

        $guard = $this->freshJwtGuard(self::THREE_D_GUARD);

        $result = $this->assertQueryBudget(2, 0, static function () use ($guard): bool {
            $authenticated = $guard->check();
            $guard->principal();

            return $authenticated;
        });

        self::assertTrue($result);
    }

    /**
     * Configure the three JWT guards used by this test.
     *
     * @param  mixed  $app
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        assert($app instanceof Application);

        /** @var \Illuminate\Config\Repository $config */
        $config = $app->make(ConfigRepository::class);

        $config->set('auth.defaults.guard', self::DEVICE_GUARD);

        $config->set('auth.guards.' . self::ACCESS_ONLY_GUARD, [
            'driver'   => 'jwt',
            'provider' => 'access_only_identities',
        ]);

        $config->set('auth.guards.' . self::DEVICE_GUARD, [
            'driver'   => 'jwt',
            'provider' => 'integration_identities',
        ]);

        $config->set('auth.guards.' . self::THREE_D_GUARD, [
            'driver'   => 'jwt',
            'provider' => 'coexist_3d_identities',
        ]);

        $config->set('auth.providers.access_only_identities', [
            'driver' => 'model',
            'model'  => PerformanceAccessOnlyIdentity::class,
        ]);

        $config->set('auth.providers.integration_identities', [
            'driver' => 'model',
            'model'  => IntegrationIdentity::class,
        ]);

        $config->set('auth.providers.coexist_3d_identities', [
            'driver' => 'model',
            'model'  => Coexist3dIdentity::class,
        ]);

        $config->set('authentication.device.last_seen_throttle_seconds', 60);
    }

    /**
     * Persist a 2D access-only identity.
     *
     * @return \Tests\Performance\Fixtures\PerformanceAccessOnlyIdentity
     */
    private function seedAccessOnlyIdentity(): PerformanceAccessOnlyIdentity
    {
        $hasher = app(Hasher::class);

        $identity = new PerformanceAccessOnlyIdentity;
        $identity->email = 'access-only-performance@example.test';
        $identity->password = $hasher->make('correct horse battery staple');
        $identity->save();

        return $identity;
    }

    /**
     * Persist a 2D identity that also owns devices.
     *
     * @param  string  $email
     * @return \Tests\Integration\Fixtures\IntegrationIdentity
     */
    private function seedIntegrationIdentity(string $email): IntegrationIdentity
    {
        $hasher = app(Hasher::class);

        $identity = new IntegrationIdentity;
        $identity->email = $email;
        $identity->password = $hasher->make('correct horse battery staple');
        $identity->is_active = true;
        $identity->save();

        return $identity;
    }

    /**
     * Persist and return one 3D identity plus its active principal.
     *
     * @return array{0: \Tests\Integration\Fixtures\Coexist3dIdentity, 1: \Tests\Integration\Fixtures\Coexist3dPrincipal}
     */
    private function seedThreeDimensionalFixtures(): array
    {
        $hasher = app(Hasher::class);

        $identity = new Coexist3dIdentity;
        $identity->email = 'three-dimensional-performance@example.test';
        $identity->password = $hasher->make('correct horse battery staple');
        $identity->is_active = true;
        $identity->save();

        $principal = new Coexist3dPrincipal;
        $principal->identity_id = $identity->getKey();
        $principal->name = 'performance-actor';
        $principal->is_active = true;
        $principal->save();

        return [$identity, $principal];
    }
}
