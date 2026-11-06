<?php

declare(strict_types = 1);

namespace Tests\Integration\Sessions;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Sessions\ActiveSessions;
use SineMacula\Laravel\Authentication\Sessions\SessionSummary;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use Tests\Concerns\InteractsWithLaggingReplica;
use Tests\Concerns\InteractsWithSessions;
use Tests\TestCase;

/**
 * Proves the session list, and the lookup of one session, are read from the
 * write connection: a session the primary has just revoked is no longer listed
 * or found, and one the primary has just created is, while the replica still
 * holds the old state.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ActiveSessions::class)]
final class ReplicaSessionListingTest extends TestCase
{
    use InteractsWithLaggingReplica, InteractsWithSessions;

    /**
     * Create the identity table on the primary and the replica.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->createOnPrimaryAndReplica('integration_identities', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('email')->unique();
            $blueprint->string('password')->nullable();
            $blueprint->boolean('is_active')->default(true);
            $blueprint->timestamps();
        });
    }

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
     * The list follows the primary: the revoked session is gone and the new one
     * is there, though the replica still holds the revoked one live and lacks
     * the new one.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testListsWhatThePrimaryHolds(): void
    {
        $identity = $this->seedIdentity();

        $this->copyRowToReplica('integration_identities', $identity->getKey());

        $revoked = $this->sessions()->signIn('password', self::credentials(), self::requestContext())->session;

        self::assertNotNull($revoked);

        $this->copyRowToReplica('authentication_sessions', $revoked->record->getKey());

        DB::connection(self::PRIMARY_CONNECTION)->table('authentication_sessions')->update(['revoked_at' => now(), 'revoked_reason' => 'revoked']);

        $created = $this->sessions()->signIn('password', self::credentials(), self::requestContext())->session;

        self::assertNotNull($created);
        $live = DB::connection(self::REPLICA_CONNECTION)->table('authentication_sessions')->whereNull('revoked_at')->pluck('id')->all();

        self::assertSame([IdentifierCoercion::stringify($revoked->record->getSessionIdentifier())], $live);

        $listed = $this->sessions()->sessions($identity);
        $ids    = array_map(static fn (SessionSummary $summary): string => $summary->id, $listed->items());

        self::assertSame([IdentifierCoercion::stringify($created->record->getSessionIdentifier())], $ids);
        self::assertSame(1, $listed->total());
    }

    /**
     * One session is found as the primary holds it: the revoked session is not
     * found and the new one is, though the replica still holds the revoked one
     * live and lacks the new one.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testFindsOneSessionAsThePrimaryHoldsIt(): void
    {
        $identity = $this->seedIdentity();

        $this->copyRowToReplica('integration_identities', $identity->getKey());

        $revoked = $this->sessions()->signIn('password', self::credentials(), self::requestContext())->session;

        self::assertNotNull($revoked);

        $this->copyRowToReplica('authentication_sessions', $revoked->record->getKey());

        DB::connection(self::PRIMARY_CONNECTION)->table('authentication_sessions')->update(['revoked_at' => now(), 'revoked_reason' => 'revoked']);

        $created = $this->sessions()->signIn('password', self::credentials(), self::requestContext())->session;

        self::assertNotNull($created);
        self::assertSame(1, DB::connection(self::REPLICA_CONNECTION)->table('authentication_sessions')->whereNull('revoked_at')->count());

        $sessions = $this->sessions();
        $id       = IdentifierCoercion::stringify($created->record->getSessionIdentifier());

        self::assertNull($sessions->session($identity, $revoked->record->getSessionIdentifier()));
        self::assertSame($id, $sessions->session($identity, $id)?->id);
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

        self::configureSessionGuards($config);

        $this->configureLaggingReplica($config);
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
