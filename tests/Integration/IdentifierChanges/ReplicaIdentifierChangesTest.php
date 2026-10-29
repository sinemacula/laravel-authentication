<?php

declare(strict_types = 1);

namespace Tests\Integration\IdentifierChanges;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Codes\Enums\CodePurpose;
use SineMacula\Laravel\Authentication\IdentifierChanges\Enums\IdentifierChangeOutcome;
use SineMacula\Laravel\Authentication\IdentifierChanges\IdentifierChangeService;
use SineMacula\Laravel\Authentication\IdentifierChanges\PendingChanges;
use SineMacula\Laravel\Authentication\IdentifierChanges\SendIdentifierChangeCode;
use SineMacula\Laravel\Authentication\Sessions\Reauthentication;
use SineMacula\Laravel\Authentication\Sessions\RecentAuthentication;
use Tests\Concerns\ChangesIdentifiers;
use Tests\Concerns\InteractsWithLaggingReplica;
use Tests\TestCase;

/**
 * Proves every read that decides a change of identifier outside a transaction
 * is from the write connection: an identity, a session and a pending change
 * written moments ago, which only the primary holds yet, are found while the
 * replica lags behind, by `pending()`, by the queued job that delivers the
 * change's code, and by a device's reauthentication.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(IdentifierChangeService::class)]
#[CoversClass(PendingChanges::class)]
#[CoversClass(SendIdentifierChangeCode::class)]
#[CoversClass(RecentAuthentication::class)]
final class ReplicaIdentifierChangesTest extends TestCase
{
    use ChangesIdentifiers, InteractsWithLaggingReplica;

    /**
     * Start changing, with the identities table on the replica as well, where
     * no identity is copied.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->startChanging();

        self::createChangeableIdentitiesTable(self::REPLICA_CONNECTION);
    }

    /**
     * Stop changing and remove the temporary database files.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $this->stopChanging();

        parent::tearDown();

        $this->removeLaggingReplicaFiles();
    }

    /**
     * A change requested moments ago, which only the primary holds, is the one
     * `pending()` reports.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPendingChangeIsReadOnThePrimary(): void
    {
        $identity = self::seedChangeable();

        self::assertTrue($this->changes()->requestByCode($identity, 'email', self::NEW_EMAIL, Reauthentication::confirmedAt($this->now))->isSent());
        self::assertSame(0, DB::connection(self::REPLICA_CONNECTION)->table('identifier_changes')->count());

        self::assertSame(self::NEW_EMAIL, $this->changes()->pending($identity, 'email')?->identifier);
    }

    /**
     * The job that delivers a change's code finds the identity and the change,
     * which only the primary holds, and sends the code to the new identifier,
     * which then confirms the change.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheCodeIsDeliveredFromThePrimary(): void
    {
        $identity = self::seedChangeable();

        self::assertTrue($this->changes()->requestByCode($identity, 'email', self::NEW_EMAIL, Reauthentication::confirmedAt($this->now))->isSent());
        self::assertSame(0, DB::connection(self::REPLICA_CONNECTION)->table('changeable_identities')->count());
        self::assertSame(1, $this->runQueued(SendIdentifierChangeCode::class));

        self::assertSame(self::CODE, $this->sender->lastCodeFor(self::NEW_EMAIL, CodePurpose::CHANGE_IDENTIFIER));
        self::assertSame(IdentifierChangeOutcome::CHANGED, $this->changes()->confirmByCode($identity, 'email', self::CODE));
    }

    /**
     * A session signed in moments ago, which only the primary holds, proves a
     * recent authentication.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testADeviceOnThePrimaryProvesARecentAuthentication(): void
    {
        $identity = self::seedChangeable();
        $device   = self::seedDevice($identity);

        self::assertSame(0, DB::connection(self::REPLICA_CONNECTION)->table('devices')->count());
        self::assertTrue($this->changes()->requestByCode($identity, 'email', self::NEW_EMAIL, Reauthentication::device($device))->isSent());
    }

    /**
     * Create the package tables, the codes and the pending changes among them,
     * on the primary and the replica.
     *
     * @return void
     */
    #[\Override]
    protected function defineDatabaseMigrations(): void
    {
        $this->migratePackageTablesOnPrimaryAndReplica('2026_04_06_000003_create_one_time_codes_table.php', '2026_04_06_000007_create_identifier_changes_table.php');
    }

    /**
     * Configure the guards over a lagging read/write split.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        $config = app(ConfigRepository::class);

        self::configureChangeGuards($config);

        $this->configureLaggingReplica($config);
    }
}
