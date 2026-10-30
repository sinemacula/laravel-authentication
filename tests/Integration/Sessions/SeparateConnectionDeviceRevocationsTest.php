<?php

declare(strict_types = 1);

namespace Tests\Integration\Sessions;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Query\Builder;
use Illuminate\Database\QueryException;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Events\DeviceRevoked;
use SineMacula\Laravel\Authentication\Events\Enums\RevocationReason;
use SineMacula\Laravel\Authentication\Events\SignedOutEverywhere;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Sessions\DeviceRevocations;
use Tests\Concerns\InteractsWithDevices;
use Tests\Integration\Fixtures\SeparateConnectionCutoffIdentity;
use Tests\Integration\Fixtures\SeparateConnectionDevice;
use Tests\TestCase;

/**
 * End-to-end tests of a bulk revocation whose devices and pending sign-ins live
 * on their own connection, in a renamed pending table, apart from the identity
 * on the default connection: the identity's cutoff moves on its connection
 * first, then its devices and pending sign-ins end in one transaction on the
 * device connection, reported once that commits, and a failure there leaves the
 * cutoff moved and every device live.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DeviceRevocations::class)]
final class SeparateConnectionDeviceRevocationsTest extends TestCase
{
    use InteractsWithDevices;

    /** @var string The renamed pending sign-ins table, on the device connection. */
    private const string PENDING_TABLE = 'staff_pending';

    /** @var string The frozen time every revocation happens at. */
    private const string NOW = '2027-01-15 10:00:00';

    /** @var \ArrayObject<int, string> Names of the revocation events, in dispatch order. */
    private \ArrayObject $dispatched;

    /**
     * Freeze the clock, create the identity table on the default connection and
     * the device and pending tables on the device connection, and record the
     * revocation events. The storage connection is set to the device connection
     * once the shipped migrations have run on the default one, so the tests'
     * own tables stand in for them there.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        config()->set('authentication.storage.connection', SeparateConnectionDevice::CONNECTION);

        CarbonImmutable::setTestNow(CarbonImmutable::parse(self::NOW));

        Schema::create('cutoff_identities', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('email');
            $blueprint->string('password');
            $blueprint->dateTime('tokens_valid_after', 0)->nullable();
            $blueprint->timestamps();
        });

        self::createDeviceTable('devices', 'id', SeparateConnectionDevice::CONNECTION);

        Schema::connection(SeparateConnectionDevice::CONNECTION)->create(self::PENDING_TABLE, static function (Blueprint $blueprint): void {
            $blueprint->uuid('id')->primary();
            $blueprint->string('authenticatable_type');
            $blueprint->string('authenticatable_id');
            $blueprint->string('principal_type')->nullable();
            $blueprint->string('principal_id')->nullable();
        });

        $this->dispatched = new \ArrayObject;

        $dispatched = $this->dispatched;

        Event::listen([DeviceRevoked::class, SignedOutEverywhere::class], static function (object $event) use ($dispatched): void {
            $dispatched->append(class_basename($event));
        });
    }

    /**
     * Release the clock and drop the identity table.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        CarbonImmutable::setTestNow();

        Schema::dropIfExists('cutoff_identities');

        parent::tearDown();
    }

    /**
     * The devices and the renamed table's pending sign-ins on the device
     * connection end, the same table on the default connection is untouched,
     * and the reports come at once while only the identity's connection has a
     * transaction open, which rolling back neither undoes nor withdraws.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheDeviceConnectionHoldsTheRevocation(): void
    {
        $identity = $this->seedIdentity();

        $this->seedDevice($identity);
        $this->seedDevice($identity);
        $this->seedPending($identity);

        DB::table(self::PENDING_TABLE)->insert($this->defaultPendingRow($identity));

        DB::beginTransaction();

        self::assertSame(2, Auth::sessions('api')->passwordReset($identity));
        self::assertSame(['DeviceRevoked', 'DeviceRevoked', 'SignedOutEverywhere'], $this->dispatched->getArrayCopy());

        DB::rollBack();

        self::assertSame(2, $this->devices()->where('revoked_reason', 'password_reset')->count());
        self::assertSame(0, $this->pendings()->count());
        self::assertSame(1, DB::table(self::PENDING_TABLE)->count());
    }

    /**
     * Inside a transaction on the device connection the revocation is reported
     * only when that transaction commits, and a rollback there undoes the
     * devices and pending sign-ins and reports nothing, while the identity's
     * cutoff, written on its own connection, stays moved.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheReportsWaitForTheDeviceConnectionsCommit(): void
    {
        $identity   = $this->seedIdentity();
        $connection = DB::connection(SeparateConnectionDevice::CONNECTION);

        $this->seedDevice($identity);
        $this->seedPending($identity);

        $connection->beginTransaction();

        self::assertSame(1, Auth::sessions('api')->revokeDevices($identity, RevocationReason::REVOKED));
        self::assertSame([], $this->dispatched->getArrayCopy());

        $connection->rollBack();

        self::assertSame([], $this->dispatched->getArrayCopy());
        self::assertSame(0, $this->devices()->whereNotNull('revoked_at')->count());
        self::assertSame(1, $this->pendings()->count());
        self::assertSame(self::NOW, $identity->fresh()?->getTokensValidAfter()?->format('Y-m-d H:i:s'));

        $connection->beginTransaction();

        self::assertSame(1, Auth::sessions('api')->revokeDevices($identity, RevocationReason::REVOKED));

        $connection->commit();

        self::assertSame(['DeviceRevoked', 'SignedOutEverywhere'], $this->dispatched->getArrayCopy());
        self::assertSame(0, $this->pendings()->count());
    }

    /**
     * A failure in the device transaction after devices were revoked rolls
     * every one of them back and propagates, and leaves the identity's cutoff
     * moved: more is cut off, never less.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFailingDeviceTransactionLeavesTheCutoffMovedAndTheDevicesLive(): void
    {
        $identity = $this->seedIdentity();

        $this->seedDevice($identity);
        $this->seedDevice($identity);

        Schema::connection(SeparateConnectionDevice::CONNECTION)->drop(self::PENDING_TABLE);

        try {
            Auth::sessions('api')->passwordChanged($identity);
            self::fail('The failing pending delete was not reported.');
        } catch (QueryException $exception) {
            self::assertStringContainsString(self::PENDING_TABLE, $exception->getMessage());
        }

        self::assertSame(0, $this->devices()->whereNotNull('revoked_at')->count());
        self::assertSame([], $this->dispatched->getArrayCopy());
        self::assertSame(self::NOW, $identity->fresh()?->getTokensValidAfter()?->format('Y-m-d H:i:s'));
    }

    /**
     * Keep the devices and pending sign-ins on their own connection, in a
     * renamed pending table, and configure the `api` guard.
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

        $config = $app->make(ConfigRepository::class);

        $config->set('database.connections.' . SeparateConnectionDevice::CONNECTION, ['driver' => 'sqlite', 'database' => ':memory:', 'prefix' => '']);
        $config->set('authentication.device.model', SeparateConnectionDevice::class);
        $config->set('authentication.sign_in.pending_table', self::PENDING_TABLE);
        $config->set('auth.defaults.guard', 'api');
        $config->set('auth.providers.identities', ['driver' => 'model', 'model' => SeparateConnectionCutoffIdentity::class]);
        $config->set('auth.guards.api', ['driver' => 'jwt', 'provider' => 'identities']);
    }

    /**
     * Persist an identity that records no cutoff yet.
     *
     * @return \Tests\Integration\Fixtures\SeparateConnectionCutoffIdentity
     */
    private function seedIdentity(): SeparateConnectionCutoffIdentity
    {
        return SeparateConnectionCutoffIdentity::query()->create(['email' => 'ada@example.test', 'password' => 'unused']);
    }

    /**
     * Persist a live device of the identity on the device connection.
     *
     * @param  \Tests\Integration\Fixtures\SeparateConnectionCutoffIdentity  $identity
     * @return void
     */
    private function seedDevice(SeparateConnectionCutoffIdentity $identity): void
    {
        $device = new SeparateConnectionDevice;
        $device->forceFill([
            ...self::liveSession('api', $identity),
            'authenticatable_type' => $identity->getMorphClass(),
            'authenticatable_id'   => (string) $identity->id,
        ])->save();
    }

    /**
     * Persist a pending sign-in of the identity in the renamed table on the
     * device connection.
     *
     * @param  \Tests\Integration\Fixtures\SeparateConnectionCutoffIdentity  $identity
     * @return void
     */
    private function seedPending(SeparateConnectionCutoffIdentity $identity): void
    {
        $this->pendings()->insert([
            'id'                   => (string) Str::uuid7(),
            'authenticatable_type' => $identity->getMorphClass(),
            'authenticatable_id'   => (string) $identity->id,
        ]);
    }

    /**
     * A pending sign-in row of the identity for the renamed table on the
     * default connection, which the revocation must not touch.
     *
     * @param  \Tests\Integration\Fixtures\SeparateConnectionCutoffIdentity  $identity
     * @return array<string, string>
     */
    private function defaultPendingRow(SeparateConnectionCutoffIdentity $identity): array
    {
        return [
            'id'                   => (string) Str::uuid7(),
            'token_digest'         => str_repeat('a', 64),
            'purpose'              => 'additional_factor',
            'guard'                => 'api',
            'sign_in_method'       => 'password',
            'authenticatable_type' => $identity->getMorphClass(),
            'authenticatable_id'   => (string) $identity->id,
            'expires_at'           => '2027-01-15 10:05:00',
        ];
    }

    /**
     * The devices table on the device connection.
     *
     * @return \Illuminate\Database\Query\Builder
     */
    private function devices(): Builder
    {
        return DB::connection(SeparateConnectionDevice::CONNECTION)->table('devices');
    }

    /**
     * The renamed pending table on the device connection.
     *
     * @return \Illuminate\Database\Query\Builder
     */
    private function pendings(): Builder
    {
        return DB::connection(SeparateConnectionDevice::CONNECTION)->table(self::PENDING_TABLE);
    }
}
