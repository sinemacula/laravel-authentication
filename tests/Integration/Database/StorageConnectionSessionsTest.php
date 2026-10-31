<?php

declare(strict_types = 1);

namespace Tests\Integration\Database;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Query\Builder;
use Illuminate\Database\QueryException;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Codes\CodeBinding;
use SineMacula\Laravel\Authentication\Codes\Enums\CodeCheck;
use SineMacula\Laravel\Authentication\Codes\IssuedCode;
use SineMacula\Laravel\Authentication\Codes\OneTimeCodes;
use SineMacula\Laravel\Authentication\Contracts\AdditionalFactorPolicy;
use SineMacula\Laravel\Authentication\Database\StorageConnection;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Factors\AdditionalFactorContext;
use SineMacula\Laravel\Authentication\Models\Device;
use SineMacula\Laravel\Authentication\RateLimiting\AccountAttempts;
use Tests\Concerns\InteractsWithDevices;
use Tests\Concerns\InteractsWithPasskeys;
use Tests\Concerns\InteractsWithRateLimits;
use Tests\Concerns\InteractsWithSessions;
use Tests\Integration\Fixtures\IntegrationIdentity;
use Tests\Integration\Fixtures\NamedConnectionIdentity;
use Tests\TestCase;

/**
 * End-to-end tests of the package on a storage connection other than the
 * default, with the counters on a connection of their own and the identities on
 * the default one: a session, its refresh, a passkey, a one-time code and a
 * pending sign-in are read and written where the shipped migrations created
 * their tables; a failure while a pending sign-in starts its session rolls the
 * whole completion back there; a rollback there leaves the counters counted;
 * and a device loads an owner that names its connection from that connection.
 *
 * Each connection is a second connection to the test database with a table
 * prefix of its own: a database of its own on SQLite, and prefixed tables
 * beside the default connection's on PostgreSQL and MySQL.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(StorageConnection::class)]
final class StorageConnectionSessionsTest extends TestCase
{
    use InteractsWithDevices, InteractsWithPasskeys, InteractsWithRateLimits, InteractsWithSessions;

    /** @var string The connection the package's tables live on. */
    private const string STORAGE = 'package_store';

    /** @var string The connection the counters live on. */
    private const string COUNTERS = 'counters';

    /**
     * Create the identity tables on the default connection.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->createSessionTables();
    }

    /**
     * Drop the identity tables and forget the device listeners a test added.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Device::flushEventListeners();

        $this->dropSessionTables();

        parent::tearDown();
    }

    /**
     * A failed sign-in counts on the counters' connection; a successful one
     * writes its device on the storage connection, and its refresh rotates the
     * device there.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASessionIsWrittenAndRefreshedOnTheStorageConnection(): void
    {
        $identity = $this->seedIdentity();

        self::assertSame(FailureReason::INVALID_CREDENTIALS, $this->sessions()->signIn('password', ['email' => 'ada@example.test', 'password' => 'wrong'])->reason);
        self::assertSame(1, $this->accountHits($identity));

        $session = $this->sessions()->signIn('password', self::credentials())->session;

        self::assertNotNull($session);
        self::assertSame(self::STORAGE, $session->device->getConnectionName());
        self::assertSame(1, $this->devices()->count());

        $digest = $this->devices()->value('refresh_key');

        self::assertNotNull($this->freshGuard()->refresh($session->tokens->refreshToken));
        self::assertNotSame($digest, $this->devices()->value('refresh_key'));
    }

    /**
     * A passkey is registered, and its owner signed in with it, on the storage
     * connection, each ceremony's challenge written and used up there.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPasskeyRegistersAndSignsInOnTheStorageConnection(): void
    {
        $this->registerPasskey($this->seedIdentity());

        self::assertSame(1, DB::connection(self::STORAGE)->table('passkeys')->count());

        $this->signInOptions();

        self::assertSame(1, DB::connection(self::STORAGE)->table('passkey_challenges')->count());
        self::assertTrue($this->signInWithPasskey()->isSignedIn());
        self::assertSame(1, $this->devices()->count());
    }

    /**
     * A one-time code is issued, and used, on the storage connection.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAOneTimeCodeIsIssuedAndUsedOnTheStorageConnection(): void
    {
        $codes   = app(OneTimeCodes::class);
        $binding = CodeBinding::signIn('api', 'email', 'ada@example.test');
        $now     = CarbonImmutable::now();
        $issued  = $codes->issue($binding, $now);

        self::assertInstanceOf(IssuedCode::class, $issued);
        self::assertSame(1, DB::connection(self::STORAGE)->table('one_time_codes')->count());
        self::assertSame(CodeCheck::ACCEPTED, $codes->check($binding, $issued->code, $now));
        self::assertNotNull(DB::connection(self::STORAGE)->table('one_time_codes')->value('consumed_at'));
    }

    /**
     * A pending sign-in waits on the storage connection; a failure while its
     * completion writes the session rolls the completion back there, so the
     * pending sign-in can still be completed, once.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFailedSessionWriteKeepsThePendingSignIn(): void
    {
        $this->seedIdentity();
        $this->requireAFurtherFactor();

        $pending = $this->sessions()->signIn('password', self::credentials())->pending;

        self::assertNotNull($pending);
        self::assertSame(1, DB::connection(self::STORAGE)->table('pending_sign_ins')->count());

        Device::creating(static function (): never {
            throw new \RuntimeException('The session could not be written.');
        });

        try {
            $this->sessions()->complete($pending->token);

            self::fail('Expected the session write to fail.');
        } catch (\RuntimeException $exception) {
            self::assertSame('The session could not be written.', $exception->getMessage());
        }

        self::assertSame(1, DB::connection(self::STORAGE)->table('pending_sign_ins')->count());
        self::assertSame(0, $this->devices()->count());

        Device::flushEventListeners();

        self::assertTrue($this->sessions()->complete($pending->token)->isSignedIn());
        self::assertSame(0, DB::connection(self::STORAGE)->table('pending_sign_ins')->count());
        self::assertSame(1, $this->devices()->count());
    }

    /**
     * A sign-in counted inside a transaction on the storage connection that is
     * rolled back stays counted, since the counters live on a connection of
     * their own.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARolledBackStorageTransactionLeavesTheCountersCounted(): void
    {
        $identity = $this->seedIdentity();
        $storage  = DB::connection(self::STORAGE);

        $storage->beginTransaction();

        self::assertSame(FailureReason::INVALID_CREDENTIALS, $this->sessions()->signIn('password', ['email' => 'ada@example.test', 'password' => 'wrong'])->reason);

        $storage->rollBack();

        self::assertSame(1, $this->accountHits($identity));
    }

    /**
     * A device on the storage connection loads, lazily and eagerly, an owner
     * whose model names its connection from that connection; an owner whose
     * model names none is looked for on the device's connection, as Laravel
     * relations do, where it is not.
     *
     * @return void
     */
    public function testADeviceLoadsAnOwnerThatNamesItsConnection(): void
    {
        $identity = $this->seedIdentity();

        $this->seedOwnedDevice(NamedConnectionIdentity::class, $identity->getKey());

        $owner = Device::query()->sole()->authenticatable;

        self::assertInstanceOf(NamedConnectionIdentity::class, $owner);
        self::assertSame($identity->getKey(), $owner->getKey());
        self::assertInstanceOf(NamedConnectionIdentity::class, Device::query()->with('authenticatable')->sole()->authenticatable);

        $this->devices()->delete();
        $this->seedOwnedDevice(IntegrationIdentity::class, $identity->getKey());

        $this->expectException(QueryException::class);

        Device::query()->sole()->authenticatable()->getResults();
    }

    /**
     * Configure the guards and passkeys, and put the package's tables on one
     * prefixed connection to the test database and the counters on another.
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

        $config  = $app->make(ConfigRepository::class);
        $testing = $config->array('database.connections.testing');

        self::configureSessionGuards($config);
        self::configurePasskeys($config);

        $config->set('database.connections.' . self::STORAGE, [...$testing, 'prefix' => 'store_']);
        $config->set('database.connections.' . self::COUNTERS, [...$testing, 'prefix' => 'counters_']);
        $config->set('authentication.storage.connection', self::STORAGE);
        $config->set('authentication.rate_limits.connection', self::COUNTERS);
    }

    /**
     * Require a further factor of every sign-in.
     *
     * @return void
     */
    private function requireAFurtherFactor(): void
    {
        app()->instance(AdditionalFactorPolicy::class, new class implements AdditionalFactorPolicy {
            /**
             * Always require a further factor.
             *
             * @param  \SineMacula\Laravel\Authentication\Factors\AdditionalFactorContext  $context
             * @return bool
             */
            #[\Override]
            public function requiresAdditionalFactor(AdditionalFactorContext $context): bool
            {
                return true;
            }
        });
    }

    /**
     * Persist a live device owned by the identity of the type and key.
     *
     * @param  class-string  $type
     * @param  mixed  $key
     * @return void
     */
    private function seedOwnedDevice(string $type, mixed $key): void
    {
        (new Device)->forceFill([...self::liveSession(), 'authenticatable_type' => $type, 'authenticatable_id' => (string) $key])->save(); // @phpstan-ignore cast.string
    }

    /**
     * The identity's account sign-in counter, read on the counters' connection.
     *
     * @param  \Tests\Integration\Fixtures\IntegrationIdentity  $identity
     * @return int
     */
    private function accountHits(IntegrationIdentity $identity): int
    {
        $hits = DB::connection(self::COUNTERS)->table('rate_limits')->where('key', self::counterKey('sign_in', 'per_account', AccountAttempts::account($identity)))->value('hits');

        return is_numeric($hits) ? (int) $hits : 0;
    }

    /**
     * A query on the devices table, on the storage connection.
     *
     * @return \Illuminate\Database\Query\Builder
     */
    private function devices(): Builder
    {
        return DB::connection(self::STORAGE)->table('devices');
    }
}
