<?php

declare(strict_types = 1);

namespace Tests\Performance;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Proofs\Provenance;
use SineMacula\Laravel\Authentication\Sessions\ConnectionRevocations;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use Tests\Concerns\InteractsWithSessions;
use Tests\Integration\Fixtures\IntegrationIdentity;

/**
 * Query-budget contracts for the revocations by connection: a connection's
 * sessions cost one read of the provenance's connection index and one locking
 * read per chunk of 500, and one `UPDATE` per session; a link's cost one read
 * of the identity's sessions, one of their provenance and one locking read per
 * chunk; a trigger turned off reads and writes nothing.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ConnectionRevocations::class)]
final class ConnectionRevocationsQueryBudgetTest extends PerformanceContractTestCase
{
    use InteractsWithSessions;

    /**
     * Create the tables.
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
     * Drop the tables.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $this->dropSessionTables();

        parent::tearDown();
    }

    /**
     * A disabled connection with three sessions reads one chunk of its
     * provenance, locks those sessions in one read and writes one `UPDATE`
     * each.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAConnectionsSessionsCostTwoReadsAndAnUpdateEach(): void
    {
        $identity = $this->seedIdentity();

        $this->external($identity, 'conn-a');
        $this->external($identity, 'conn-a');
        $this->external($identity, 'conn-a');

        $sessions = $this->sessions();

        self::assertSame(3, $this->assertQueryBudget(2, 3, static fn (): int => $sessions->connectionDisabled('conn-a')));
    }

    /**
     * Past one chunk, each chunk of 500 costs its two reads, and the writes
     * stay one per session.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testEachChunkOfFiveHundredCostsTwoReads(): void
    {
        $identity = $this->seedIdentity();

        $this->insertSessions($identity, 'conn-a', ConnectionRevocations::CHUNK + 1);

        $sessions = $this->sessions();
        $count    = ConnectionRevocations::CHUNK + 1;

        self::assertSame($count, $this->assertQueryBudget(4, $count, static fn (): int => $sessions->connectionDeleted('conn-a')));
    }

    /**
     * A removed link reads the identity's sessions, their provenance and the
     * locked sessions through the connection, and writes one `UPDATE` each.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testALinksSessionsCostThreeReadsAndAnUpdateEach(): void
    {
        $identity = $this->seedIdentity();

        $this->external($identity, 'conn-a');
        $this->external($identity, 'conn-a');
        $this->external($identity, 'conn-b');

        $sessions = $this->sessions();

        self::assertSame(2, $this->assertQueryBudget(3, 2, static fn (): int => $sessions->linkRemoved($identity, 'conn-a')));
    }

    /**
     * A trigger turned off reads and writes nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATriggerTurnedOffCostsNothing(): void
    {
        $identity = $this->seedIdentity();

        $this->external($identity, 'conn-a');

        config()->set('authentication.revocation.connection_disabled', false);

        $sessions = $this->sessions();

        self::assertSame(0, $this->assertQueryBudget(0, 0, static fn (): int => $sessions->connectionDisabled('conn-a')));
    }

    /**
     * Register the session guards.
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
     * Start a session of the identity through the connection.
     *
     * @param  \Tests\Integration\Fixtures\IntegrationIdentity  $identity
     * @param  string  $connection
     * @return void
     *
     * @throws \Throwable
     */
    private function external(IntegrationIdentity $identity, string $connection): void
    {
        self::assertNotNull($this->sessions()->start($identity, null, 'sso', null, new Provenance($connection))->session);
    }

    /**
     * Insert that many live sessions of the identity on the `api` guard, each
     * established through the connection.
     *
     * @param  \Tests\Integration\Fixtures\IntegrationIdentity  $identity
     * @param  string  $connection
     * @param  int  $count
     * @return void
     */
    private function insertSessions(IntegrationIdentity $identity, string $connection, int $count): void
    {
        $keys = array_map(static fn (): string => (string) Str::uuid7(), range(1, $count));
        $at   = $this->now->toDateTimeString();
        $idle = $this->now->addDay()->toDateTimeString();

        $sessions = array_map(static fn (string $key): array => [
            'id'                   => $key,
            'generation'           => (string) Str::uuid7(),
            'authenticatable_type' => $identity->getMorphClass(),
            'authenticatable_id'   => IdentifierCoercion::stringify($identity->getKey()),
            'principal_type'       => $identity->getMorphClass(),
            'principal_id'         => IdentifierCoercion::stringify($identity->getKey()),
            'status'               => 'active',
            'guard'                => 'api',
            'sign_in_method'       => 'sso',
            'refresh_key'          => hash('sha256', 'refresh-' . $key),
            'signed_in_at'         => $at,
            'idle_expires_at'      => $idle,
        ], $keys);

        foreach (array_chunk($sessions, 200) as $chunk) {
            DB::table('authentication_sessions')->insert($chunk);
        }

        $provenance = array_map(static fn (string $key): array => ['session_id' => $key, 'connection_id' => $connection, 'created_at' => $at], $keys);

        foreach (array_chunk($provenance, 200) as $chunk) {
            DB::table('authentication_provenance')->insert($chunk);
        }
    }
}
