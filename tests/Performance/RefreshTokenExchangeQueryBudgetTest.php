<?php

declare(strict_types = 1);

namespace Tests\Performance;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Facades\Auth as PackageAuth;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenHasher;
use SineMacula\Laravel\Authentication\Models\Device;
use Tests\Unit\Stubs\StubPrincipal;

/**
 * Query-budget contracts for the refresh-token exchange hot paths.
 *
 * @internal
 */
#[CoversClass(JwtGuard::class)]
final class RefreshTokenExchangeQueryBudgetTest extends PerformanceContractTestCase
{
    private const string GUARD = 'api';

    /**
     * Provision the identity table used by the refresh fixtures.
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
    }

    /**
     * Release the fixture table.
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
     * Refresh success should do the device lookup and authenticatable
     * hydration, then one CAS write. The timestamp write is suppressed here by
     * seeding `last_logged_in_at` inside the throttle window.
     *
     * @return void
     */
    public function testRefreshSuccessUsesTwoReadsAndOneWrite(): void
    {
        $identity = $this->seedIdentity();
        $rotationId = 'refresh-success-rotation-id';

        $device = new Device;
        $device->forceFill([
            'authenticatable_type' => StubPrincipal::class,
            'authenticatable_id'   => (string) $identity->getKey(), // @phpstan-ignore cast.string
            'os'                   => 'ios',
            'refresh_key'          => RefreshTokenHasher::hash($rotationId),
            'last_logged_in_at'    => $this->now,
        ])->save();

        $token = PackageAuth::jwt(self::GUARD)->issueRefreshToken($device, $rotationId, $identity);
        $guard = $this->freshJwtGuard(self::GUARD);

        $result = $this->assertQueryBudget(2, 1, static fn () => $guard->refresh($token));

        self::assertNotNull($result);
    }

    /**
     * Unknown-device refresh failures should stop at the first device lookup.
     *
     * @return void
     */
    public function testUnknownDeviceRefreshFailureUsesOneReadAndNoWrites(): void
    {
        $missingDevice = new Device;
        $missingDevice->forceFill(['id' => 'missing-device-id']);

        $token = PackageAuth::jwt(self::GUARD)->issueRefreshToken($missingDevice, 'missing-device-rotation');

        $guard = $this->freshJwtGuard(self::GUARD);

        $result = $this->assertQueryBudget(1, 0, static fn () => $guard->refresh($token));

        self::assertNull($result);
    }

    /**
     * Rotation-mismatch refresh failures should do the device lookup but avoid
     * authenticatable hydration and writes.
     *
     * @return void
     */
    public function testRotationMismatchRefreshFailureUsesOneReadAndNoWrites(): void
    {
        $identity = $this->seedIdentity();

        $device = new Device;
        $device->forceFill([
            'authenticatable_type' => StubPrincipal::class,
            'authenticatable_id'   => (string) $identity->getKey(), // @phpstan-ignore cast.string
            'os'                   => 'ios',
            'refresh_key'          => RefreshTokenHasher::hash('stored-rotation-id'),
        ])->save();

        $token = PackageAuth::jwt(self::GUARD)->issueRefreshToken($device, 'tampered-rotation-id');
        $guard = $this->freshJwtGuard(self::GUARD);

        $result = $this->assertQueryBudget(1, 0, static fn () => $guard->refresh($token));

        self::assertNull($result);
    }

    /**
     * Configure the single JWT guard used by this test.
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

        $config->set('auth.defaults.guard', self::GUARD);

        $config->set('auth.guards.' . self::GUARD, [
            'driver'   => 'jwt',
            'provider' => 'identities',
        ]);

        $config->set('auth.providers.identities', [
            'driver' => 'model',
            'model'  => StubPrincipal::class,
        ]);

        $config->set('authentication.device.last_seen_throttle_seconds', 60);
    }

    /**
     * Persist and return an active identity that is also the acting principal.
     *
     * @return \Tests\Unit\Stubs\StubPrincipal
     */
    private function seedIdentity(): StubPrincipal
    {
        $identity = new StubPrincipal;
        $identity->email = 'refresh-performance@example.test';
        $identity->password = password_hash('correct horse battery staple', PASSWORD_BCRYPT);
        $identity->is_active = true;
        $identity->save();

        return $identity;
    }
}
