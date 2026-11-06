<?php

declare(strict_types = 1);

namespace Tests\Integration\Sessions;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\DatabaseManager;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Sessions\ConnectionGuards;
use SineMacula\Laravel\Authentication\Sessions\ConnectionRevocations;
use SineMacula\Laravel\Authentication\Sessions\SessionWriter;
use SineMacula\Laravel\Authentication\Sessions\SignInResult;
use Tests\Concerns\InteractsWithExternalSignIns;
use Tests\Concerns\InteractsWithIsolationLevels;
use Tests\Concerns\InteractsWithSessions;
use Tests\TestCase;

/**
 * Races a sign-in through a link against the widening of that link's scope on
 * PostgreSQL and MySQL, on two connections to one database, with the widening's
 * transaction at READ COMMITTED and at REPEATABLE READ: it reads before the
 * sign-in commits and widens after it, as it does when the adapter's lock on
 * the link made the sign-in wait for it. On MySQL's REPEATABLE READ that first
 * read fixes the snapshot a plain read would see, so only a locking read finds
 * the session the sign-in committed meanwhile. On PostgreSQL's REPEATABLE READ
 * not even that does, so both write the link's guard: the widening then fails
 * to serialise, and once its caller retries the whole transaction it finds the
 * session; a sign-in whose transaction read before a widening committed fails
 * the same way. A widening also holds up no other identity's sign-in.
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
#[CoversClass(ConnectionGuards::class)]
#[CoversClass(SessionWriter::class)]
final class ConcurrentExternalSignInAndWideningTest extends TestCase
{
    use InteractsWithExternalSignIns, InteractsWithIsolationLevels, InteractsWithSessions;

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
     * first read is revoked by the widening: found by its locking reads, or,
     * where those read the transaction's snapshot (PostgreSQL's REPEATABLE
     * READ), once the widening has failed to serialise on the link's guard,
     * revoked nothing, and been retried whole.
     *
     * @param  string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideIsolationLevels')]
    public function testASignInCommittedAfterTheWideningFirstReadIsRevoked(string $level): void
    {
        $identity = $this->seedIdentity();
        $result   = $this->linkedResult($identity, subject: 'subject-1');
        $widen    = fn (): int => $this->sessions()->linkScopeWidened($identity, 'connection-7', 'link-1');

        self::beginTransactionAt($level);

        self::assertSame(0, DB::table('authentication_sessions')->count());

        $signedIn = $this->onSignInConnection(fn (): SignInResult => $this->sessions()->signInExternally($result, self::requestContext()));
        $key      = $signedIn->session?->record->getKey();

        self::assertTrue($signedIn->isSignedIn());

        if (self::readsASnapshot($level)) {
            self::assertSame('40001', self::serializationFailure($widen));
            self::assertNull(DB::table('authentication_sessions')->where('id', $key)->value('revoked_at'));

            self::beginTransactionAt($level);
        }

        self::assertSame(1, $widen());

        DB::commit();

        self::assertSame('link_scope_widened', DB::table('authentication_sessions')->where('id', $key)->value('revoked_reason'));
    }

    /**
     * On PostgreSQL's REPEATABLE READ a sign-in through the link, in a
     * transaction that read before a widening of the link committed, fails to
     * serialise on the link's guard rather than establish a session the
     * widening never saw; retried whole, it signs in.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASignInWhoseTransactionReadBeforeAWideningCommittedFailsToSerialize(): void
    {
        if (!self::readsASnapshot('repeatable read')) {
            self::markTestSkipped('Only PostgreSQL reads a snapshot with a locking read.');
        }

        $identity = $this->seedIdentity();
        $result   = $this->linkedResult($identity, subject: 'subject-1');
        $signIn   = fn (): mixed => $this->sessions()->signInExternally($result, self::requestContext());

        self::beginTransactionAt('repeatable read');

        self::assertSame(0, DB::table('authentication_sessions')->count());
        self::assertSame(0, $this->onSignInConnection(fn (): int => $this->sessions()->linkScopeWidened($identity, 'connection-7', 'link-1')));
        self::assertSame('40001', self::serializationFailure($signIn));
        self::assertSame(0, DB::table('authentication_sessions')->count());

        self::beginTransactionAt('repeatable read');

        self::assertTrue($signIn()->isSignedIn());

        DB::commit();

        self::assertSame(1, DB::table('authentication_sessions')->whereNull('revoked_at')->count());
    }

    /**
     * A widening of one identity's link holds up no other identity's sign-in
     * while its transaction is open: it writes only its own link's guard, and
     * it asks the provenance only about the identity's external sessions, each
     * of which has one, so on MySQL it locks those rows and no gap a later
     * session's provenance would go in, even when the identity's newest session
     * was signed in with a password and has none.
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

        self::assertNotSame(ConnectionGuards::slot('link-1'), ConnectionGuards::slot('link-2'));
        self::assertTrue($this->sessions()->signInExternally($this->linkedResult($grace, linkId: 'link-2'), self::requestContext())->isSignedIn());
        self::assertTrue($this->sessions()->signInExternally($this->linkedResult($ada), self::requestContext())->isSignedIn());
        self::assertTrue($this->sessions()->signIn('password', self::credentials(), self::requestContext())->isSignedIn());

        self::limitLockWaits(self::SIGN_IN_CONNECTION);

        DB::beginTransaction();

        self::assertSame(1, $this->sessions()->linkScopeWidened($ada, 'connection-7', 'link-1'));

        $manager->setDefaultConnection(self::SIGN_IN_CONNECTION);

        try {
            $signedIn = $this->sessions()->signInExternally($this->linkedResult($grace, linkId: 'link-2'), self::requestContext());
        } finally {
            $manager->setDefaultConnection($widening);

            DB::commit();
        }

        self::assertTrue($signedIn->isSignedIn());
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

    /**
     * Run the work on the second connection, the sign-in's, as its default.
     *
     * @template TResult
     *
     * @param  \Closure(): TResult  $work
     * @return TResult
     */
    private function onSignInConnection(\Closure $work): mixed
    {
        $manager = app(DatabaseManager::class);
        $default = $manager->getDefaultConnection();

        $manager->setDefaultConnection(self::SIGN_IN_CONNECTION);

        try {
            return $work();
        } finally {
            $manager->setDefaultConnection($default);
        }
    }
}
