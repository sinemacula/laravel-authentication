<?php

declare(strict_types = 1);

namespace Tests\Integration\Guards;

use Carbon\Carbon;
use Firebase\JWT\JWT;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\AuthManager;
use SineMacula\Laravel\Authentication\Contracts\PrincipalResolver;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenExchange;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenHasher;
use SineMacula\Laravel\Authentication\Models\Device;
use SineMacula\Laravel\Authentication\Providers\ModelProvider;
use SineMacula\Laravel\Authentication\Resolvers\DefaultPrincipalResolver;
use Tests\Concerns\InteractsWithLaggingReplica;
use Tests\Integration\Fixtures\Coexist3dIdentity;
use Tests\Integration\Fixtures\Coexist3dPrincipal;
use Tests\Integration\Fixtures\TenantAware3dIdentity;
use Tests\Integration\Fixtures\TenantAware3dPrincipal;
use Tests\Integration\Fixtures\TenantAware3dTenant;
use Tests\TestCase;
use Tests\Unit\Stubs\StubPrincipal;

/**
 * Proves that every read deciding authentication goes to the write connection.
 *
 * The default connection is a read/write split whose replica lags behind the
 * primary: rows written during the test exist on the primary only. A lookup
 * served by the replica would therefore reject the request, so each passing
 * assertion shows the identity, device, refresh digest, or principal was read
 * from the writer.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(JwtGuard::class)]
#[CoversClass(RefreshTokenExchange::class)]
#[CoversClass(ModelProvider::class)]
#[CoversClass(DefaultPrincipalResolver::class)]
final class JwtGuardWriteConnectionIntegrationTest extends TestCase
{
    use InteractsWithLaggingReplica;

    /** @var string Plaintext rotation id stored on the seeded device. */
    private const string ROTATION_ID = 'stored-rotation-id';

    /**
     * Freeze the clocks and create the identity and principal tables on the
     * primary and the replica.
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
            $blueprint->boolean('is_active')->default(true);
            $blueprint->timestamps();
        });

        $this->createOnPrimaryAndReplica('coexist_3d_identities', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('email')->unique();
            $blueprint->string('password');
            $blueprint->boolean('is_active')->default(true);
            $blueprint->timestamps();
        });

        $this->createOnPrimaryAndReplica('coexist_3d_principals', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->unsignedInteger('identity_id');
            $blueprint->string('name');
            $blueprint->boolean('is_active')->default(true);
            $blueprint->timestamps();
        });

        $this->createTenantAwareTables();
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
     * A bearer token for an identity and device that exist only on the primary
     * authenticates and binds both, so the identity and device lookups read the
     * writer.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testBearerReadsIdentityAndDeviceFromTheWriteConnection(): void
    {
        $identity = $this->seedIdentity();
        $device   = $this->seedDevice($identity);

        $token = $this->authManager()->jwt('api')->issueAccessToken($identity, $identity, $device);

        $guard = $this->guardForRequest(Request::create('/me', 'GET', server: ['HTTP_AUTHORIZATION' => 'Bearer ' . $token]));

        self::assertTrue($identity->is($guard->user()));
        self::assertSame($device->getKey(), $guard->device()?->getDeviceIdentifier());
    }

    /**
     * A device revoked on the primary while the replica still shows it live
     * rejects the bearer token: the revocation is read from the writer.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testBearerRejectsDeviceRevokedOnThePrimaryWhileTheReplicaLags(): void
    {
        $identity = $this->seedIdentity();
        $device   = $this->seedDevice($identity);

        $this->copyRowToReplica('stub_principals', $identity->getKey());
        $this->copyRowToReplica('devices', $device->getKey());

        Device::query()->whereKey($device->getKey())->update(['revoked_at' => Carbon::now()]);

        $token = $this->authManager()->jwt('api')->issueAccessToken($identity, $identity, $device);

        $guard = $this->guardForRequest(Request::create('/me', 'GET', server: ['HTTP_AUTHORIZATION' => 'Bearer ' . $token]));

        self::assertNull($guard->user());
    }

    /**
     * A refresh for a device whose digest exists only on the primary rotates
     * successfully, so the device and owner lookups read the writer.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testRefreshReadsDeviceAndIdentityFromTheWriteConnection(): void
    {
        $identity = $this->seedIdentity();
        $device   = $this->seedDevice($identity);

        $refreshToken = $this->authManager()->jwt('api')->issueRefreshToken($device, self::ROTATION_ID, $identity);

        $guard = $this->guardForRequest(Request::create('/refresh', 'POST'));

        self::assertNotNull($guard->refresh($refreshToken));
        self::assertTrue($identity->is($guard->user()));
    }

    /**
     * The model provider finds an identity by credentials when the row exists
     * only on the primary.
     *
     * @return void
     */
    public function testModelProviderReadsCredentialsFromTheWriteConnection(): void
    {
        $identity = $this->seedIdentity();

        $provider = new ModelProvider(app(Hasher::class), StubPrincipal::class);

        self::assertTrue($identity->is($provider->retrieveByCredentials(['email' => 'writer@example.test'])));
    }

    /**
     * The default resolver finds a 3D principal that exists only on the primary
     * through the identity's own `resolveDefaultPrincipal()` hook and through
     * the hinted `principals()->find()` lookup.
     *
     * @return void
     */
    public function testDefaultResolverReadsPrincipalsFromTheWriteConnection(): void
    {
        $identity = new Coexist3dIdentity;
        $identity->forceFill([
            'email'    => 'writer-3d@example.test',
            'password' => 'hashed',
        ])->save();

        $principal = new Coexist3dPrincipal;
        $principal->forceFill([
            'identity_id' => $identity->getKey(),
            'name'        => 'membership',
        ])->save();

        $resolver = app(PrincipalResolver::class);

        self::assertTrue($principal->is($resolver->resolve($identity)));
        self::assertTrue($principal->is($resolver->resolve($identity, $principal->getKey())));
    }

    /**
     * The default resolver runs the identity's `resolveHintedPrincipal()` hook
     * with reads pinned to the writer: the principal comes back with the tenant
     * the hook joins, which the fallback `principals()->find()` lookup would
     * not attach.
     *
     * @return void
     */
    public function testDefaultResolverRunsTheHintedPrincipalHookOnTheWriteConnection(): void
    {
        $identity = new TenantAware3dIdentity;
        $identity->forceFill([
            'email'    => 'writer-tenant@example.test',
            'password' => 'hashed',
        ])->save();

        $tenant = new TenantAware3dTenant;
        $tenant->forceFill([
            'name' => 'Tenant',
            'type' => 'customer',
        ])->save();

        $principal = new TenantAware3dPrincipal;
        $principal->forceFill([
            'identity_id' => $identity->getKey(),
            'tenant_id'   => $tenant->getKey(),
            'name'        => 'membership',
        ])->save();

        $resolved = app(PrincipalResolver::class)->resolve($identity, $principal->getKey());

        self::assertInstanceOf(TenantAware3dPrincipal::class, $resolved);
        self::assertEquals($principal->getKey(), $resolved->getKey());
        self::assertTrue($resolved->relationLoaded('tenant'));
    }

    /**
     * Configure the `api` guard over the lagging split connection.
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
     * Create the devices table on the primary and the replica instead of
     * migrating the default connection.
     *
     * @return void
     */
    #[\Override]
    protected function defineDatabaseMigrations(): void
    {
        $this->migrateDevicesOnPrimaryAndReplica();
    }

    /**
     * Create the tenant-aware 3D fixture tables on the primary and the replica.
     *
     * @return void
     */
    private function createTenantAwareTables(): void
    {
        $this->createOnPrimaryAndReplica('tenant_aware_3d_identities', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('email')->unique();
            $blueprint->string('password');
            $blueprint->boolean('is_active')->default(true);
            $blueprint->timestamps();
        });

        $this->createOnPrimaryAndReplica('tenant_aware_3d_tenants', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('name');
            $blueprint->string('type');
            $blueprint->timestamps();
        });

        $this->createOnPrimaryAndReplica('tenant_aware_3d_principals', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->unsignedInteger('identity_id');
            $blueprint->unsignedInteger('tenant_id');
            $blueprint->string('name');
            $blueprint->boolean('is_active')->default(true);
            $blueprint->timestamps();
        });
    }

    /**
     * Write an identity through the split connection, so it exists on the
     * primary only.
     *
     * @return \Tests\Unit\Stubs\StubPrincipal
     */
    private function seedIdentity(): StubPrincipal
    {
        $identity = new StubPrincipal;
        $identity->forceFill([
            'email'    => 'writer@example.test',
            'password' => 'hashed',
        ])->save();

        return $identity;
    }

    /**
     * Write a device with a refresh digest for the identity through the split
     * connection, so it exists on the primary only.
     *
     * @param  \Tests\Unit\Stubs\StubPrincipal  $identity
     * @return \SineMacula\Laravel\Authentication\Models\Device
     */
    private function seedDevice(StubPrincipal $identity): Device
    {
        $device = new Device;
        $device->forceFill([
            'authenticatable_type' => StubPrincipal::class,
            'authenticatable_id'   => (string) $identity->getKey(), // @phpstan-ignore cast.string
            'os'                   => 'ios',
            'refresh_key'          => RefreshTokenHasher::hash(self::ROTATION_ID),
        ])->save();

        return $device;
    }

    /**
     * Copy a row as it stands on the primary into the replica, so the replica
     * holds that version until the test changes the primary again.
     *
     * @param  string  $table
     * @param  mixed  $key
     * @return void
     */
    private function copyRowToReplica(string $table, mixed $key): void
    {
        $row = DB::connection(self::PRIMARY_CONNECTION)->table($table)->where('id', $key)->first();

        self::assertNotNull($row);

        DB::connection(self::REPLICA_CONNECTION)->table($table)->insert((array) $row);
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
     * Resolve a fresh `api` guard bound to the supplied request.
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
