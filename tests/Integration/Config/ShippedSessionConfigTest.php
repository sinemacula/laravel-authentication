<?php

declare(strict_types = 1);

namespace Tests\Integration\Config;

use Carbon\Carbon;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Events\EventContext;
use SineMacula\Laravel\Authentication\Events\SessionAuthenticated;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Listeners\RecordSessionUsage;
use SineMacula\Laravel\Authentication\Models\Session;
use Tests\Concerns\InteractsWithSessionRecords;
use Tests\TestCase;

/**
 * Integration tests for the `session` block of the shipped
 * `config/authentication.php`: the env vars it reads and the last-use throttle.
 *
 * Loads the shipped `session` block against a controlled environment, so a
 * renamed key or env var fails here rather than shipping silently: the listener
 * falls back to the same 60 seconds the shipped default gives.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RecordSessionUsage::class)]
final class ShippedSessionConfigTest extends TestCase
{
    use InteractsWithSessionRecords;

    /** @var string Env var setting the last-use throttle. */
    private const string THROTTLE_ENV = 'AUTHENTICATION_SESSION_LAST_USED_THROTTLE_SECONDS';

    /** @var list<string> Every env var the shipped `session` block reads. */
    private const array SESSION_ENV = [
        'AUTHENTICATION_SESSION_MODEL',
        'AUTHENTICATION_SESSION_TABLE',
        self::THROTTLE_ENV,
        'AUTHENTICATION_SESSION_PRUNE_AFTER_DAYS',
    ];

    /** @var array<string, false|string> Ambient process-environment values of the session env vars, restored on teardown. */
    private array $ambientProcessEnvironment = [];

    /** @var array<array-key, mixed> Ambient `$_SERVER`, restored on teardown. */
    private array $ambientServer = [];

    /** @var array<array-key, mixed> Ambient `$_ENV`, restored on teardown. */
    private array $ambientEnv = [];

    /**
     * Freeze the clock, and save and clear every env var the shipped `session`
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

        foreach (self::SESSION_ENV as $name) {
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
     * Out of the box a session's last use is recorded at most once a minute.
     *
     * @return void
     */
    public function testShippedThrottleDefaultsToOneMinute(): void
    {
        self::assertSame(60, $this->shippedSessionConfig()['last_used_throttle_seconds'] ?? null);
    }

    /**
     * `AUTHENTICATION_SESSION_LAST_USED_THROTTLE_SECONDS` set to 0 makes the
     * listener record every use: a use one second after the last is recorded.
     *
     * @return void
     */
    public function testShippedThrottleReadsTheEnvironment(): void
    {
        putenv(self::THROTTLE_ENV . '=0');

        config()->set('authentication.session', $this->shippedSessionConfig());

        $lastUsedAt = Carbon::now();

        $session = new Session;
        $session->forceFill([
            ...self::liveSession(),
            'authenticatable_type' => 'owner',
            'authenticatable_id'   => '1',
            'last_used_at'         => $lastUsedAt,
        ])->save();

        Carbon::setTestNow($lastUsedAt->copy()->addSecond());

        event(new SessionAuthenticated(new EventContext('api', new ClientContext(null, null), session: $session)));

        $stored = DB::table('authentication_sessions')->where('id', $session->getKey())->value('last_used_at');

        self::assertIsString($stored);
        self::assertSame($lastUsedAt->getTimestamp() + 1, Carbon::parse($stored)->getTimestamp());
    }

    /**
     * Rows of `[env var, value, key]`: an env var the shipped `session` block
     * reads, a value for it, and the key it sets.
     *
     * @return iterable<string, array{0: string, 1: string, 2: string}>
     */
    public static function provideSessionEnvironment(): iterable
    {
        yield from [
            'model'            => ['AUTHENTICATION_SESSION_MODEL', 'App\Models\CustomSession', 'model'],
            'table'            => ['AUTHENTICATION_SESSION_TABLE', 'custom_sessions', 'table'],
            'prune after days' => ['AUTHENTICATION_SESSION_PRUNE_AFTER_DAYS', '7', 'prune_after_days'],
        ];
    }

    /**
     * Each of the session block's other env vars sets its key.
     *
     * @param  string  $name
     * @param  string  $value
     * @param  string  $key
     * @return void
     */
    #[DataProvider('provideSessionEnvironment')]
    public function testShippedSessionBlockReadsTheEnvironment(string $name, string $value, string $key): void
    {
        self::assertNotSame($value, $this->shippedSessionConfig()[$key] ?? null);

        putenv("{$name}={$value}");

        self::assertSame($value, $this->shippedSessionConfig()[$key] ?? null);
    }

    /**
     * Load the shipped config file and return its `session` block.
     *
     * @return array<array-key, mixed>
     */
    private function shippedSessionConfig(): array
    {
        $config = require dirname(__DIR__, 3) . '/config/authentication.php';

        self::assertIsArray($config);
        self::assertIsArray($config['session'] ?? null);

        return $config['session'];
    }
}
