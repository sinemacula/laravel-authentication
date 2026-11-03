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
 * only a locking read finds the session the sign-in committed meanwhile.
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
