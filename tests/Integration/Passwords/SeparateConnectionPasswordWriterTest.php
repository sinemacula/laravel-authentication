<?php

declare(strict_types = 1);

namespace Tests\Integration\Passwords;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Events\DeviceRevoked;
use SineMacula\Laravel\Authentication\Events\PasswordSet;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Passwords\Enums\PasswordFlow;
use SineMacula\Laravel\Authentication\Passwords\PasswordWriter;
use Tests\Concerns\InteractsWithDevices;
use Tests\Integration\Fixtures\SeparateConnectionCutoffIdentity;
use Tests\Integration\Fixtures\SeparateConnectionDevice;
use Tests\TestCase;

/**
 * Integration tests of setting a password for an identity on the default
 * connection whose devices live on a connection of their own: the identity's
 * transaction holds the hash and the cutoff, the devices' commits inside it,
 * and a failure after that leaves the devices revoked and the password as it
 * was, so more is ended, never less.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PasswordWriter::class)]
final class SeparateConnectionPasswordWriterTest extends TestCase
{
    use InteractsWithDevices;

    /** @var string The frozen time every write happens at. */
    private const string NOW = '2027-01-15 10:00:00';

    /** @var string The password the identity starts with. */
    private const string OLD_PASSWORD = 'the old passphrase';

    /**
     * Freeze the clock and create the identity table on the default connection
     * and the device, pending and codes tables on the device connection, which
     * is made the storage connection once the shipped migrations have run on
     * the default one.
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
        self::createCodeTableOn(SeparateConnectionDevice::CONNECTION);

        Schema::connection(SeparateConnectionDevice::CONNECTION)->create('pending_sign_ins', static function (Blueprint $blueprint): void {
            $blueprint->uuid('id')->primary();
            $blueprint->string('authenticatable_type');
            $blueprint->string('authenticatable_id');
            $blueprint->string('principal_type')->nullable();
            $blueprint->string('principal_id')->nullable();
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
     * A reset stores the hash and the cutoff on the identity's connection and
     * revokes the devices on theirs.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAResetSpansBothConnections(): void
    {
        $identity = $this->seedIdentity();

        $this->seedDevice($identity);
        $this->seedDevice($identity);

        self::assertSame(2, Auth::passwords('api')->set($identity, 'a brand new passphrase', PasswordFlow::RESET)->revoked);

        $stored = $identity->fresh();

        self::assertNotNull($stored);
        self::assertTrue(app(Hasher::class)->check('a brand new passphrase', $stored->getAuthPassword()));
        self::assertSame(self::NOW, $stored->getTokensValidAfter()?->format('Y-m-d H:i:s'));
        self::assertSame(2, DB::connection(SeparateConnectionDevice::CONNECTION)->table('devices')->where('revoked_reason', 'password_reset')->count());
    }

    /**
     * A failure once the devices' revocation has committed rolls the identity's
     * transaction back, password and cutoff with it, and leaves the devices
     * revoked; nothing reports a password set.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFailureAfterTheDevicesCommitEndsMoreNeverLess(): void
    {
        $identity = $this->seedIdentity();
        $set      = 0;

        $this->seedDevice($identity);

        Event::listen(DeviceRevoked::class, static function (): never {
            throw new \RuntimeException('a listener failed');
        });

        Event::listen(PasswordSet::class, static function () use (&$set): void {
            $set++;
        });

        try {
            Auth::passwords('api')->set($identity, 'a brand new passphrase', PasswordFlow::RESET);
            self::fail('The listener failure was swallowed.');
        } catch (\RuntimeException $exception) {
            self::assertSame('a listener failed', $exception->getMessage());
        }

        $stored = $identity->fresh();

        self::assertNotNull($stored);
        self::assertTrue(app(Hasher::class)->check(self::OLD_PASSWORD, $stored->getAuthPassword()));
        self::assertNull($stored->getTokensValidAfter());
        self::assertSame(1, DB::connection(SeparateConnectionDevice::CONNECTION)->table('devices')->where('revoked_reason', 'password_reset')->count());
        self::assertSame(0, $set);
    }

    /**
     * Keep the devices and pending sign-ins on their own connection and
     * configure the `api` guard.
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
        $config->set('auth.providers.identities', ['driver' => 'model', 'model' => SeparateConnectionCutoffIdentity::class]);
        $config->set('auth.guards.api', ['driver' => 'jwt', 'provider' => 'identities']);
        $config->set('hashing.bcrypt.rounds', 4);
    }

    /**
     * Persist an identity with the old password and no cutoff yet.
     *
     * @return \Tests\Integration\Fixtures\SeparateConnectionCutoffIdentity
     */
    private function seedIdentity(): SeparateConnectionCutoffIdentity
    {
        return SeparateConnectionCutoffIdentity::query()->create(['email' => 'ada@example.test', 'password' => app(Hasher::class)->make(self::OLD_PASSWORD)]);
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
}
