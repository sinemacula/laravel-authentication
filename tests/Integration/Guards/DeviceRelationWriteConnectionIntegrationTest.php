<?php

declare(strict_types = 1);

namespace Tests\Integration\Guards;

use Carbon\Carbon;
use Firebase\JWT\JWT;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Database\DatabaseManager;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\QueryException;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Authentication\AuthManager;
use SineMacula\Laravel\Authentication\Guards\Concerns\VerifiesPinnedContext;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Models\Device;
use Tests\Concerns\InteractsWithDevices;
use Tests\Concerns\InteractsWithLaggingReplica;
use Tests\Integration\Fixtures\GrantedDevicesIdentity;
use Tests\TestCase;

/**
 * Proves that an identity's `devices()` relation is built on the write
 * connection, so a relation that queries while it is built cannot narrow the
 * device lookup from a lagging replica.
 *
 * The default connection is a read/write split whose replica lags behind the
 * primary. The identity's relation permits only the devices a `device_grants`
 * row names; withdrawing a grant on the primary while the replica still holds
 * it must stop the device authenticating.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(JwtGuard::class)]
#[CoversTrait(VerifiesPinnedContext::class)]
final class DeviceRelationWriteConnectionIntegrationTest extends TestCase
{
    use InteractsWithDevices, InteractsWithLaggingReplica;

    /** @var string Plaintext password of the seeded identity. */
    private const string PASSWORD = 'correct horse battery staple';

    /** @var array{email: string, password: string} Credentials of the seeded identity. */
    private const array CREDENTIALS = ['email' => 'granted@example.test', 'password' => self::PASSWORD];

    /**
     * Freeze the clocks and create the identity table on the primary and the
     * replica.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $now = Carbon::createStrict(2026, 4, 6, 12, 0, 0);

        Carbon::setTestNow($now);

        JWT::$timestamp = $now->getTimestamp();

        $this->createOnPrimaryAndReplica('stub_principals', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('email')->unique();
            $blueprint->string('password');
            $blueprint->timestamps();
        });
    }

    /**
     * Release the frozen clocks and remove the temporary database files.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Carbon::setTestNow();

        JWT::$timestamp = null;

        parent::tearDown();

        $this->removeLaggingReplicaFiles();
    }

    /**
     * A bearer token naming a device whose grant is withdrawn on the primary,
     * while the replica still holds the grant, stops authenticating.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testBearerRejectsDeviceWhoseGrantIsWithdrawnOnThePrimaryWhileTheReplicaLags(): void
    {
        [$identity, $device] = $this->seedGrantedDevice();

        $token   = $this->authManager()->jwt('api')->issueAccessToken($identity, $identity, $device);
        $request = Request::create('/me', 'GET', server: ['HTTP_AUTHORIZATION' => 'Bearer ' . $token]);

        self::assertTrue($identity->is($this->guardForRequest($request)->user()));

        $this->withdrawGrant($device);

        self::assertNull($this->guardForRequest($request)->user());
    }

    /**
     * Pinning on `attempt()` a device whose grant is withdrawn on the primary,
     * while the replica still holds the grant, fails the attempt.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAttemptRejectsPinnedDeviceWhoseGrantIsWithdrawnOnThePrimaryWhileTheReplicaLags(): void
    {
        [, $device] = $this->seedGrantedDevice();

        self::assertTrue($this->guardForRequest(Request::create('/sign-in', 'POST'))->attempt(self::CREDENTIALS, null, $device));

        $this->withdrawGrant($device);

        $guard = $this->guardForRequest(Request::create('/sign-in', 'POST'));

        self::assertFalse($guard->attempt(self::CREDENTIALS, null, $device));
        self::assertFalse($guard->hasUser());
    }

    /**
     * A relation whose query fails on the writer while it is built propagates
     * the error, and afterwards reads go back to the replica through the
     * original connection resolver.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testBearerRestoresReplicaReadsWhenBuildingTheRelationFails(): void
    {
        $identity = $this->seedIdentity();
        $device   = $this->seedDevice($identity);

        Schema::connection(self::REPLICA_CONNECTION)->create('device_grants', static function (Blueprint $blueprint): void {
            $blueprint->unsignedInteger('identity_id');
            $blueprint->uuid('device_id');
        });

        $resolver = Model::getConnectionResolver();
        $token    = $this->authManager()->jwt('api')->issueAccessToken($identity, $identity, $device);

        try {
            $this->guardForRequest(Request::create('/me', 'GET', server: ['HTTP_AUTHORIZATION' => 'Bearer ' . $token]))->user();

            self::fail('Building the relation should have failed on the writer.');
        } catch (\Throwable $exception) {
            self::assertInstanceOf(QueryException::class, $exception);
            self::assertStringContainsString('device_grants', $exception->getMessage());
        }

        self::assertSame($resolver, Model::getConnectionResolver());
        self::assertInstanceOf(DatabaseManager::class, $resolver);
        self::assertSame(0, DB::connection(self::SPLIT_CONNECTION)->table('stub_principals')->count());
    }

    /**
     * Configure the lagging split connection and the JWT guard over the
     * identity whose relation reads its grants.
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

        $this->configureLaggingReplica($config);

        $config->set('auth.guards.api', ['driver' => 'jwt', 'provider' => 'identities']);
        $config->set('auth.providers.identities', ['driver' => 'model', 'model' => GrantedDevicesIdentity::class]);

        // Failed attempts wait out the timebox; keep it short.
        $config->set('authentication.timebox.credentials_microseconds', 1);
    }

    /**
     * Create the package tables on the primary and the replica instead of
     * migrating the default connection.
     *
     * @return void
     */
    #[\Override]
    protected function defineDatabaseMigrations(): void
    {
        $this->migratePackageTablesOnPrimaryAndReplica();
    }

    /**
     * Seed an identity and a device on the primary and the replica, with a
     * grant for the device on both.
     *
     * @return array{0: \Tests\Integration\Fixtures\GrantedDevicesIdentity, 1: \SineMacula\Laravel\Authentication\Models\Device}
     */
    private function seedGrantedDevice(): array
    {
        $this->createOnPrimaryAndReplica('device_grants', static function (Blueprint $blueprint): void {
            $blueprint->unsignedInteger('identity_id');
            $blueprint->uuid('device_id');
        });

        $identity = $this->seedIdentity();
        $device   = $this->seedDevice($identity);

        $this->copyRowToReplica('stub_principals', $identity->getKey());
        $this->copyRowToReplica('devices', $device->getKey());

        foreach ([self::PRIMARY_CONNECTION, self::REPLICA_CONNECTION] as $connection) {
            DB::connection($connection)->table('device_grants')->insert([
                'identity_id' => $identity->getKey(),
                'device_id'   => $device->getKey(),
            ]);
        }

        return [$identity, $device];
    }

    /**
     * Write an identity through the split connection, so it exists on the
     * primary only.
     *
     * @return \Tests\Integration\Fixtures\GrantedDevicesIdentity
     */
    private function seedIdentity(): GrantedDevicesIdentity
    {
        $identity = new GrantedDevicesIdentity;
        $identity->forceFill([
            'email'    => self::CREDENTIALS['email'],
            'password' => app(Hasher::class)->make(self::PASSWORD),
        ])->save();

        return $identity;
    }

    /**
     * Write a device for the identity through the split connection, so it
     * exists on the primary only.
     *
     * @param  \Tests\Integration\Fixtures\GrantedDevicesIdentity  $identity
     * @return \SineMacula\Laravel\Authentication\Models\Device
     */
    private function seedDevice(GrantedDevicesIdentity $identity): Device
    {
        $device = new Device;
        $device->forceFill([
            ...self::liveSession(),
            'authenticatable_type' => GrantedDevicesIdentity::class,
            'authenticatable_id'   => (string) $identity->getKey(), // @phpstan-ignore cast.string
            'principal_type'       => $identity->getMorphClass(),
            'principal_id'         => (string) $identity->getKey(), // @phpstan-ignore cast.string
        ])->save();

        return $device;
    }

    /**
     * Withdraw the device's grant through the split connection, so the replica
     * still holds it.
     *
     * @param  \SineMacula\Laravel\Authentication\Models\Device  $device
     * @return void
     */
    private function withdrawGrant(Device $device): void
    {
        DB::connection(self::SPLIT_CONNECTION)->table('device_grants')->where('device_id', $device->getKey())->delete();
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

    /**
     * Resolve a fresh JWT guard bound to the supplied request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \SineMacula\Laravel\Authentication\Guards\JwtGuard
     */
    private function guardForRequest(Request $request): JwtGuard
    {
        app()->instance('request', $request);

        $guard = $this->authManager()->guard('api');

        assert($guard instanceof JwtGuard);

        return $guard;
    }
}
