<?php

declare(strict_types = 1);

namespace Tests\Integration\ApiKeys;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Query\Builder;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\ApiKeys\ApiKeyService;
use SineMacula\Laravel\Authentication\AuthenticationServiceProvider;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Guards\ApiKeyGuard;
use Tests\Concerns\InteractsWithMachineCredentials;
use Tests\TestCase;

/**
 * End-to-end tests of API keys on a storage connection other than the default,
 * with no device model configured at all: the `api_key` guard, which keeps no
 * device sessions, is built and authenticates, and its keys are issued,
 * rotated, used and revoked on the storage connection, where the shipped
 * migrations created their table.
 *
 * The storage connection is a second connection to the test database with a
 * table prefix of its own: a database of its own on SQLite, and prefixed tables
 * beside the default connection's on PostgreSQL and MySQL.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ApiKeyGuard::class)]
#[CoversClass(ApiKeyService::class)]
#[CoversClass(AuthenticationServiceProvider::class)]
final class StorageConnectionApiKeysTest extends TestCase
{
    use InteractsWithMachineCredentials;

    /** @var string The connection the package's tables live on. */
    private const string STORAGE = 'package_store';

    /**
     * Freeze the clock and create the machine tables on the default connection.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        self::freezeMachineClockAt(CarbonImmutable::createStrict(2026, 4, 6, 12, 0, 0));

        $this->createMachineTables();
    }

    /**
     * Drop the machine tables and release the clock.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $this->dropMachineTables();

        self::releaseMachineClock();

        parent::tearDown();
    }

    /**
     * A key is issued on the storage connection and authenticates through the
     * `api_key` guard, its use recorded there; its rotation's replacement
     * authenticates instead of it, and once revoked the replacement is refused.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testKeysAreIssuedUsedAndRevokedOnTheStorageConnection(): void
    {
        $machine = $this->seedMachine();
        $issued  = $this->apiKeys()->issue($machine, $machine, ['read']);

        self::assertSame(1, $this->keys()->count());
        self::assertTrue($this->authenticates($issued->key()));
        self::assertNotNull($this->keys()->where('id', $issued->id)->value('last_used_at'));

        $rotated = $this->apiKeys()->rotate($machine, $issued->id, 0);

        self::assertNotNull($rotated);
        self::assertSame(2, $this->keys()->count());
        self::assertFalse($this->authenticates($issued->key()));
        self::assertTrue($this->authenticates($rotated->key()));

        self::assertTrue($this->apiKeys()->revoke($machine, $rotated->id));
        self::assertNotNull($this->keys()->where('id', $rotated->id)->value('revoked_at'));
        self::assertFalse($this->authenticates($rotated->key()));
    }

    /**
     * Configure the machine guards with no device model, and put the package's
     * tables on a prefixed second connection to the test database.
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

        self::configureMachineGuards($config);

        $config->set('database.connections.' . self::STORAGE, [...$config->array('database.connections.testing'), 'prefix' => 'store_']);
        $config->set('authentication.storage.connection', self::STORAGE);
        $config->set('authentication.device.model', '');
    }

    /**
     * Whether the key authenticates a request on the `machine` guard.
     *
     * @param  string  $key
     * @return bool
     */
    private function authenticates(string $key): bool
    {
        $this->startMachineRequest($key);

        return Auth::guard('machine')->check();
    }

    /**
     * A query on the keys' table, on the storage connection.
     *
     * @return \Illuminate\Database\Query\Builder
     */
    private function keys(): Builder
    {
        return DB::connection(self::STORAGE)->table('api_keys');
    }
}
