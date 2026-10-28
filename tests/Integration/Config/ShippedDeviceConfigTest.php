<?php

declare(strict_types = 1);

namespace Tests\Integration\Config;

use Carbon\Carbon;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Events\DeviceAuthenticated;
use SineMacula\Laravel\Authentication\Events\EventContext;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Listeners\RecordDeviceUsage;
use SineMacula\Laravel\Authentication\Models\Device;
use Tests\Concerns\InteractsWithDevices;
use Tests\TestCase;

/**
 * Integration tests for the last-use throttle in the shipped
 * `config/authentication.php`.
 *
 * Loads the shipped `device` block against a controlled environment, so a
 * renamed key or env var fails here rather than shipping silently: the listener
 * falls back to the same 60 seconds the shipped default gives.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RecordDeviceUsage::class)]
final class ShippedDeviceConfigTest extends TestCase
{
    use InteractsWithDevices;

    /** @var string Env var setting the last-use throttle. */
    private const string THROTTLE_ENV = 'AUTHENTICATION_DEVICE_LAST_USED_THROTTLE_SECONDS';

    /** @var list<string> Every env var the shipped `device` block reads. */
    private const array DEVICE_ENV = [
        'AUTHENTICATION_DEVICE_MODEL',
        'AUTHENTICATION_DEVICE_TABLE',
        self::THROTTLE_ENV,
    ];

    /** @var array<string, false|string> Ambient process-environment values of the device env vars, restored on teardown. */
    private array $ambientProcessEnvironment = [];

    /** @var array<array-key, mixed> Ambient `$_SERVER`, restored on teardown. */
    private array $ambientServer = [];

    /** @var array<array-key, mixed> Ambient `$_ENV`, restored on teardown. */
    private array $ambientEnv = [];

    /**
     * Freeze the clock, and save and clear every env var the shipped `device`
     * block reads.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        Carbon::setTestNow(Carbon::createStrict(2026, 4, 6, 12, 0, 0));

        $this->ambientServer = $_SERVER;
        $this->ambientEnv    = $_ENV;

        foreach (self::DEVICE_ENV as $name) {
            $this->ambientProcessEnvironment[$name] = getenv($name);

            unset($_SERVER[$name], $_ENV[$name]);

            putenv($name);
        }
    }

    /**
     * Restore the ambient environment and release the clock.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        foreach ($this->ambientProcessEnvironment as $name => $value) {
            putenv($value === false ? $name : "{$name}={$value}");
        }

        $_SERVER = $this->ambientServer;
        $_ENV    = $this->ambientEnv;

        Carbon::setTestNow();

        parent::tearDown();
    }

    /**
     * Out of the box a device's last use is recorded at most once a minute.
     *
     * @return void
     */
    public function testShippedThrottleDefaultsToOneMinute(): void
    {
        self::assertSame(60, $this->shippedDeviceConfig()['last_used_throttle_seconds'] ?? null);
    }

    /**
     * `AUTHENTICATION_DEVICE_LAST_USED_THROTTLE_SECONDS` set to 0 makes the
     * listener record every use: a use one second after the last is recorded.
     *
     * @return void
     */
    public function testShippedThrottleReadsTheEnvironment(): void
    {
        putenv(self::THROTTLE_ENV . '=0');

        config()->set('authentication.device', $this->shippedDeviceConfig());

        $lastUsedAt = Carbon::now();

        $device = new Device;
        $device->forceFill([
            ...self::liveSession(),
            'authenticatable_type' => 'owner',
            'authenticatable_id'   => '1',
            'last_used_at'         => $lastUsedAt,
        ])->save();

        Carbon::setTestNow($lastUsedAt->copy()->addSecond());

        event(new DeviceAuthenticated(new EventContext('api', new ClientContext(null, null), device: $device)));

        $stored = DB::table('devices')->where('id', $device->getKey())->value('last_used_at');

        self::assertIsString($stored);
        self::assertSame($lastUsedAt->getTimestamp() + 1, Carbon::parse($stored)->getTimestamp());
    }

    /**
     * Load the shipped config file and return its `device` block.
     *
     * @return array<array-key, mixed>
     */
    private function shippedDeviceConfig(): array
    {
        $config = require dirname(__DIR__, 3) . '/config/authentication.php';

        self::assertIsArray($config);
        self::assertIsArray($config['device'] ?? null);

        return $config['device'];
    }
}
