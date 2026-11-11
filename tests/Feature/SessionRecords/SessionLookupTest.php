<?php

declare(strict_types = 1);

namespace Tests\Feature\SessionRecords;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Exceptions\InvalidSessionModelConfigurationException;
use SineMacula\Laravel\Authentication\Models\Session;
use SineMacula\Laravel\Authentication\SessionRecords\SessionLookup;
use Tests\Concerns\InteractsWithLaggingReplica;
use Tests\Concerns\InteractsWithSessionRecords;
use Tests\Integration\Fixtures\SeparateConnectionSession;
use Tests\TestCase;

/**
 * Feature tests for finding a session of the configured model by its
 * identifier, over a read/write split whose replica lags behind.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SessionLookup::class)]
final class SessionLookupTest extends TestCase
{
    use InteractsWithLaggingReplica, InteractsWithSessionRecords;

    /**
     * Remove the temporary database files.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        parent::tearDown();

        $this->removeLaggingReplicaFiles();
    }

    /**
     * A session only the primary holds yet is found as the configured model.
     *
     * @return void
     */
    public function testFindsASessionTheReplicaHasNotSeen(): void
    {
        $session = new Session;
        $session->forceFill([...self::liveSession(), 'authenticatable_type' => 'owner', 'authenticatable_id' => '1'])->save();

        self::assertNull(DB::connection(self::REPLICA_CONNECTION)->table('authentication_sessions')->where('id', $session->getKey())->first());

        $found = SessionLookup::find($session->getKey());

        self::assertInstanceOf(Session::class, $found);
        self::assertSame($session->getKey(), $found->getKey());
    }

    /**
     * An identifier that names no session is not found; one that cannot be a
     * key of the model is rejected without a query.
     *
     * @return void
     */
    public function testUnknownAndMalformedIdentifiersFindNothing(): void
    {
        $queries = 0;

        DB::listen(static function (QueryExecuted $query) use (&$queries): void {
            $queries++;
        });

        self::assertNull(SessionLookup::find('0190f1d2-7c4e-7a3b-9f10-2b3c4d5e6f70'));
        self::assertSame(1, $queries);

        self::assertNull(SessionLookup::find('not-a-uuid'));
        self::assertNull(SessionLookup::find(42));
        self::assertNull(SessionLookup::find(null));
        self::assertSame(1, $queries);
    }

    /**
     * The locking lookup finds a session only the primary holds yet.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheLockingLookupFindsTheSessionOnThePrimary(): void
    {
        $session = new Session;
        $session->forceFill([...self::liveSession(), 'authenticatable_type' => 'owner', 'authenticatable_id' => '1'])->save();

        $queries = 0;

        DB::listen(static function (QueryExecuted $query) use (&$queries): void {
            $queries++;
        });

        $found = DB::transaction(static fn (): mixed => SessionLookup::lock($session->getKey()));

        self::assertInstanceOf(Session::class, $found);
        self::assertSame([$session->getKey(), 1], [$found->getKey(), $queries]);
        self::assertNull(SessionLookup::lock('not-a-uuid'));
        self::assertSame(1, $queries);
    }

    /**
     * The model is a new instance of the configured class, which must be an
     * Eloquent session.
     *
     * @return void
     */
    public function testTheModelIsAFreshInstanceOfTheConfiguredClass(): void
    {
        $model = SessionLookup::model();

        self::assertInstanceOf(Session::class, $model);
        self::assertFalse($model->exists);
        self::assertNotSame($model, SessionLookup::model());

        config()->set('authentication.session.model', \stdClass::class);

        $this->expectException(InvalidSessionModelConfigurationException::class);

        SessionLookup::model();
    }

    /**
     * A configured model that names a connection other than the storage
     * connection is refused.
     *
     * @return void
     */
    public function testTheModelMustLiveOnTheStorageConnection(): void
    {
        config()->set('authentication.session.model', SeparateConnectionSession::class);

        try {
            SessionLookup::model();

            self::fail('Expected the session model to be refused.');
        } catch (InvalidSessionModelConfigurationException $exception) {
            self::assertSame(
                'authentication.session.model [' . SeparateConnectionSession::class . '] must live on the storage connection (authentication.storage.connection),'
                    . ' where the package writes its sessions with its other rows in one transaction: the session model is on [session_store], the storage'
                    . ' connection is [' . config()->string('database.default') . '].',
                $exception->getMessage(),
            );
        }

        config()->set('authentication.storage.connection', SeparateConnectionSession::CONNECTION);

        self::assertInstanceOf(SeparateConnectionSession::class, SessionLookup::model());

        config()->set('authentication.session.model', Session::class);

        self::assertSame(SeparateConnectionSession::CONNECTION, SessionLookup::model()->getConnectionName());
    }

    /**
     * `SessionLookup` cannot be instantiated from outside.
     *
     * @return void
     *
     * @SuppressWarnings("php:S3011")
     */
    public function testConstructorIsPrivate(): void
    {
        $reflection  = new \ReflectionClass(SessionLookup::class);
        $constructor = $reflection->getConstructor();

        self::assertNotNull($constructor);
        self::assertTrue($constructor->isPrivate());

        $instance = $reflection->newInstanceWithoutConstructor();
        $constructor->invoke($instance);
    }

    /**
     * Make the lagging split the default connection.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        $this->configureLaggingReplica(app(ConfigRepository::class));
    }

    /**
     * Create the package tables on the primary and the replica.
     *
     * @return void
     */
    #[\Override]
    protected function defineDatabaseMigrations(): void
    {
        $this->migratePackageTablesOnPrimaryAndReplica();
    }
}
