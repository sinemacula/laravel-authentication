<?php

declare(strict_types = 1);

namespace Tests\Integration\Listeners;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Events\EventContext;
use SineMacula\Laravel\Authentication\Events\SessionAuthenticated;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Listeners\RecordSessionUsage;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use Tests\Concerns\InteractsWithLaggingReplica;
use Tests\Concerns\InteractsWithSessions;
use Tests\TestCase;

/**
 * Proves `RecordSessionUsage` reads a session no guard has bound on the write
 * connection: a session signed in moments ago, which only the primary holds
 * yet, has its use recorded while the replica lags behind.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RecordSessionUsage::class)]
final class RecordSessionUsageTest extends TestCase
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
     * An event naming a session only the primary holds, with no guard bound to
     * it, has the use written to that session's row.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASessionOnlyThePrimaryHoldsHasItsUseRecorded(): void
    {
        $this->seedIdentity();

        $session = $this->sessions()->signIn('password', self::credentials(), self::requestContext())->session;

        self::assertNotNull($session);

        $id = IdentifierCoercion::stringify($session->record->getKey());

        DB::connection(self::PRIMARY_CONNECTION)->table('authentication_sessions')->update(['last_used_at' => null, 'last_used_ip' => null]);
        Auth::forgetGuards();

        self::assertSame(0, DB::connection(self::REPLICA_CONNECTION)->table('authentication_sessions')->count());

        (new RecordSessionUsage)(new SessionAuthenticated(new EventContext('api', new ClientContext('203.0.113.7', 'Agent/1.0'), sessionId: $id)));

        $row = DB::connection(self::PRIMARY_CONNECTION)->table('authentication_sessions')->where('id', $id)->first(['last_used_at', 'last_used_ip']);

        self::assertNotNull($row?->last_used_at);
        self::assertSame('203.0.113.7', $row->last_used_ip);
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
