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
 * Races an external sign-in against the disabling of its connection, on two
 * connections to one database.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ConnectionRevocations::class)]
#[CoversClass(ConnectionGuards::class)]
#[CoversClass(SessionWriter::class)]
final class ConcurrentExternalSignInAndConnectionDisablingTest extends TestCase
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
     * A sign-in committed after the disabling's first read is revoked.
     *
     * @param  string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideIsolationLevels')]
    public function testASignInCommittedAfterTheDisablingFirstReadIsRevoked(string $level): void
    {
        $identity = $this->seedIdentity();
        $result   = $this->linkedResult($identity);
        $disable  = fn (): int => $this->sessions()->connectionDisabled('connection-7');

        self::beginTransactionAt($level);

        self::assertSame(0, DB::table('authentication_provenance')->count());

        $signedIn = $this->onSignInConnection(fn (): SignInResult => $this->sessions()->signInExternally($result, self::requestContext()));
        $key      = $signedIn->session?->record->getKey();

        self::assertTrue($signedIn->isSignedIn());

        if (self::readsASnapshot($level)) {
            self::assertSame('40001', self::serializationFailure($disable));
            self::assertNull(DB::table('authentication_sessions')->where('id', $key)->value('revoked_at'));

            self::beginTransactionAt($level);
        }

        self::assertSame(1, $disable());

        DB::commit();

        self::assertSame('connection_disabled', DB::table('authentication_sessions')->where('id', $key)->value('revoked_reason'));
    }

    /**
     * A sign-in whose transaction read before a disabling committed fails to
     * serialise on PostgreSQL.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASignInWhoseTransactionReadBeforeADisablingCommittedFailsToSerialize(): void
    {
        if (!self::readsASnapshot('repeatable read')) {
            self::markTestSkipped('Only PostgreSQL reads a snapshot with a locking read.');
        }

        $identity = $this->seedIdentity();
        $result   = $this->linkedResult($identity, linkId: 'link-2');

        self::beginTransactionAt('repeatable read');

        self::assertSame(0, DB::table('authentication_provenance')->count());
        self::assertSame(0, $this->onSignInConnection(fn (): int => $this->sessions()->connectionDisabled('connection-7')));
        self::assertSame('40001', self::serializationFailure(fn (): mixed => $this->sessions()->signInExternally($result, self::requestContext())));
        self::assertSame(0, DB::table('authentication_sessions')->count());
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
     * Run the work on the sign-in's connection as the default.
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
