<?php

declare(strict_types = 1);

namespace Tests\Integration\Sessions;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\DatabaseManager;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Sessions\ConnectionRevocations;
use Tests\Concerns\InteractsWithExternalSignIns;
use Tests\Concerns\InteractsWithSessions;
use Tests\TestCase;

/**
 * Races a sign-in through a connection against the disabling of that connection
 * on PostgreSQL and MySQL, on two connections to one database: the disabling
 * transaction reads before the sign-in commits and disables after it, as it
 * does when the adapter's lock on the connection made the sign-in wait for it.
 * On MySQL's REPEATABLE READ that first read fixes the snapshot a plain read
 * would see, so only a locking read finds the session the sign-in committed
 * meanwhile; on PostgreSQL's REPEATABLE READ not even that does, so the
 * disabling is refused there.
 *
 * Skipped on SQLite, whose in-memory database each connection would have to
 * itself.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ConnectionRevocations::class)]
final class ConcurrentExternalSignInAndConnectionDisablingTest extends TestCase
{
    use InteractsWithExternalSignIns, InteractsWithSessions;

    /** @var string The second connection to the test database, the sign-in's. */
    private const string SIGN_IN_CONNECTION = 'signing_in';

    /**
     * Skip where two connections cannot share the database, add the second
     * connection and create the tables.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        if (DB::connection()->getDriverName() === 'sqlite') {
            self::markTestSkipped('Two connections need a shared database server.');
        }

        $config = app(ConfigRepository::class);

        $config->set('database.connections.' . self::SIGN_IN_CONNECTION, $config->get('database.connections.' . $config->string('database.default')));

        $this->createSessionTables();
    }

    /**
     * Close the second connection and drop the tables.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        DB::disconnect(self::SIGN_IN_CONNECTION);

        $this->dropSessionTables();

        parent::tearDown();
    }

    /**
     * A sign-in through the connection that commits after the disabling
     * transaction first read is still found and revoked by the disabling.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASignInCommittedAfterTheDisablingFirstReadIsRevoked(): void
    {
        $identity  = $this->seedIdentity();
        $result    = $this->linkedResult($identity);
        $manager   = app(DatabaseManager::class);
        $disabling = $manager->getDefaultConnection();

        DB::beginTransaction();

        self::assertSame(0, DB::table('authentication_provenance')->count());

        $manager->setDefaultConnection(self::SIGN_IN_CONNECTION);

        $signedIn = $this->sessions()->signInExternally($result);

        $manager->setDefaultConnection($disabling);

        self::assertTrue($signedIn->isSignedIn());
        self::assertSame(1, $this->sessions()->connectionDisabled('connection-7'));

        DB::commit();

        self::assertSame('connection_disabled', DB::table('authentication_sessions')->where('id', $signedIn->session?->record->getKey())->value('revoked_reason'));
    }

    /**
     * On PostgreSQL a disabling in a REPEATABLE READ transaction is refused
     * before anything is read: every read there, a locking one included, sees
     * the snapshot the transaction's first read took, so it would miss the
     * session a sign-in through the connection committed since, and leave it
     * live.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testADisablingInARepeatableReadTransactionOnPostgresIsRefused(): void
    {
        if (DB::connection()->getDriverName() !== 'pgsql') {
            self::markTestSkipped('Only PostgreSQL reads a snapshot with a locking read.');
        }

        $identity  = $this->seedIdentity();
        $result    = $this->linkedResult($identity);
        $manager   = app(DatabaseManager::class);
        $disabling = $manager->getDefaultConnection();

        DB::beginTransaction();
        DB::statement('set transaction isolation level repeatable read');

        self::assertSame(0, DB::table('authentication_provenance')->count());

        $manager->setDefaultConnection(self::SIGN_IN_CONNECTION);

        $signedIn = $this->sessions()->signInExternally($result);

        $manager->setDefaultConnection($disabling);

        $refusal = null;

        try {
            $this->sessions()->connectionDisabled('connection-7');
        } catch (\LogicException $exception) {
            $refusal = $exception->getMessage();
        } finally {
            DB::rollBack();
        }

        self::assertStringContainsString('READ COMMITTED', (string) $refusal);
        self::assertTrue($signedIn->isSignedIn());
        self::assertNull(DB::table('authentication_sessions')->where('id', $signedIn->session?->record->getKey())->value('revoked_at'));
    }

    /**
     * Register the guards.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        assert($app instanceof Application);

        self::configureSessionGuards($app->make(ConfigRepository::class));
    }
}
