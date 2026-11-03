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
 * Races a sign-in through a link against the widening of that link's scope on
 * PostgreSQL and MySQL, on two connections to one database: the widening's
 * transaction reads before the sign-in commits and widens after it, as it does
 * when the adapter's lock on the link made the sign-in wait for it. On MySQL's
 * REPEATABLE READ that first read fixes the snapshot a plain read would see, so
 * only a locking read finds the session the sign-in committed meanwhile; on
 * PostgreSQL's REPEATABLE READ not even that does, so the widening is refused
 * there. A widening also holds up no other identity's sign-in.
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
final class ConcurrentExternalSignInAndWideningTest extends TestCase
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
     * A sign-in through the link that commits after the widening's transaction
     * first read is still found and revoked by the widening.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASignInCommittedAfterTheWideningFirstReadIsRevoked(): void
    {
        $identity = $this->seedIdentity();
        $result   = $this->linkedResult($identity, subject: 'subject-1');
        $manager  = app(DatabaseManager::class);
        $widening = $manager->getDefaultConnection();

        DB::beginTransaction();

        self::assertSame(0, DB::table('authentication_sessions')->count());

        $manager->setDefaultConnection(self::SIGN_IN_CONNECTION);

        $signedIn = $this->sessions()->signInExternally($result);

        $manager->setDefaultConnection($widening);

        self::assertTrue($signedIn->isSignedIn());
        self::assertSame(1, $this->sessions()->linkScopeWidened($identity, 'connection-7', 'link-1'));

        DB::commit();

        self::assertSame('link_scope_widened', DB::table('authentication_sessions')->where('id', $signedIn->session?->record->getKey())->value('revoked_reason'));
    }

    /**
     * A widening of one identity's link holds up no other identity's sign-in
     * while its transaction is open: it asks the provenance only about the
     * identity's external sessions, each of which has one, so on MySQL it locks
     * those rows and no gap a later session's provenance would go in, even when
     * the identity's newest session was signed in with a password and has none.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAWideningHoldsUpNoOtherIdentitysSignIn(): void
    {
        $ada      = $this->seedIdentity();
        $grace    = $this->seedIdentity('grace@example.test');
        $manager  = app(DatabaseManager::class);
        $widening = $manager->getDefaultConnection();

        self::assertTrue($this->sessions()->signInExternally($this->linkedResult($grace))->isSignedIn());
        self::assertTrue($this->sessions()->signInExternally($this->linkedResult($ada))->isSignedIn());
        self::assertTrue($this->sessions()->signIn('password', self::credentials())->isSignedIn());

        if (DB::connection()->getDriverName() === 'mysql') {
            DB::connection(self::SIGN_IN_CONNECTION)->statement('set session innodb_lock_wait_timeout = 2');
        }

        DB::beginTransaction();

        self::assertSame(1, $this->sessions()->linkScopeWidened($ada, 'connection-7', 'link-1'));

        $manager->setDefaultConnection(self::SIGN_IN_CONNECTION);

        try {
            $signedIn = $this->sessions()->signInExternally($this->linkedResult($grace));
        } finally {
            $manager->setDefaultConnection($widening);

            DB::commit();
        }

        self::assertTrue($signedIn->isSignedIn());
    }

    /**
     * On PostgreSQL a widening in a REPEATABLE READ transaction is refused
     * before anything is read: every read there, a locking one included, sees
     * the snapshot the transaction's first read took, so it would miss the
     * session a sign-in through the link committed since, and leave it live.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAWideningInARepeatableReadTransactionOnPostgresIsRefused(): void
    {
        if (DB::connection()->getDriverName() !== 'pgsql') {
            self::markTestSkipped('Only PostgreSQL reads a snapshot with a locking read.');
        }

        $identity = $this->seedIdentity();
        $result   = $this->linkedResult($identity, subject: 'subject-1');
        $manager  = app(DatabaseManager::class);
        $widening = $manager->getDefaultConnection();

        DB::beginTransaction();
        DB::statement('set transaction isolation level repeatable read');

        self::assertSame(0, DB::table('authentication_sessions')->count());

        $manager->setDefaultConnection(self::SIGN_IN_CONNECTION);

        $signedIn = $this->sessions()->signInExternally($result);

        $manager->setDefaultConnection($widening);

        $refusal = null;

        try {
            $this->sessions()->linkScopeWidened($identity, 'connection-7', 'link-1');
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
