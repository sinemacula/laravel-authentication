<?php

declare(strict_types = 1);

namespace Tests\Integration\Sessions;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Sessions\ConnectionRevocations;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use Tests\Concerns\InteractsWithSessionRecords;
use Tests\Concerns\InteractsWithSessions;
use Tests\Integration\Fixtures\IntegerKeySession;
use Tests\Integration\Fixtures\IntegrationIdentity;
use Tests\TestCase;

/**
 * Integration tests of revocation by connection and by link over a session
 * model whose keys are integers the database issues, past one chunk: the
 * provenance holds the keys as strings, read in string order, while the
 * identity's own sessions are read in numeric order, and each session the
 * connection established is still revoked exactly once.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ConnectionRevocations::class)]
final class IntegerKeyConnectionRevocationsTest extends TestCase
{
    use InteractsWithSessionRecords, InteractsWithSessions;

    /** @var string The integer-keyed session table the sessions live in. */
    private const string TABLE = 'integer_key_sessions';

    /** @var string The frozen time every revocation happens at. */
    private const string NOW = '2027-01-15 10:00:00';

    /** @var int How many sessions the connection established: one past a chunk, so string and numeric order differ. */
    private const int THROUGH = ConnectionRevocations::CHUNK + 1;

    /**
     * Freeze the clocks, create the tables and point the session model and its
     * table at the integer-keyed ones.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        Carbon::setTestNow(CarbonImmutable::parse(self::NOW));
        CarbonImmutable::setTestNow(CarbonImmutable::parse(self::NOW));

        $this->createSessionTables();

        self::createSessionRecordTable(self::TABLE, incrementing: true);

        config()->set('authentication.session.model', IntegerKeySession::class);
        config()->set('authentication.session.table', self::TABLE);
    }

    /**
     * Drop the tables, put the session table back for the migrations' rollback
     * and release the clocks.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Schema::dropIfExists(self::TABLE);

        config()->set('authentication.session.table', 'authentication_sessions');

        $this->dropSessionTables();

        Carbon::setTestNow();
        CarbonImmutable::setTestNow();

        parent::tearDown();
    }

    /**
     * A disabled connection revokes every one of its integer-keyed sessions
     * once, across the chunk its string-ordered keys break at, and leaves
     * another connection's sessions alone.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testEveryIntegerKeyedSessionOfTheConnectionIsRevokedOnce(): void
    {
        $this->insertSessions($this->seedIdentity());

        self::assertSame(self::THROUGH, Auth::sessions('api')->connectionDisabled('conn-a'));
        self::assertSame(self::THROUGH, DB::table(self::TABLE)->where('revoked_reason', 'connection_disabled')->count());
        self::assertSame([502, 503, 504], self::unrevoked());
        self::assertSame(0, Auth::sessions('api')->connectionDisabled('conn-a'));
    }

    /**
     * A removed link revokes every one of the identity's integer-keyed sessions
     * the connection established once, across the chunk its numerically ordered
     * keys break at, and leaves its other sessions alone.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testEveryIntegerKeyedSessionThroughTheLinkIsRevokedOnce(): void
    {
        $identity = $this->seedIdentity();

        $this->insertSessions($identity);

        self::assertSame(self::THROUGH, Auth::sessions('api')->linkRemoved($identity, 'conn-a'));
        self::assertSame(self::THROUGH, DB::table(self::TABLE)->where('revoked_reason', 'link_removed')->count());
        self::assertSame([502, 503, 504], self::unrevoked());
        self::assertSame(0, Auth::sessions('api')->linkRemoved($identity, 'conn-a'));
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
     * Insert the identity's live sessions under keys 1 to 504: those up to
     * `THROUGH` established through `conn-a`, the rest through `conn-b`.
     *
     * @param  \Tests\Integration\Fixtures\IntegrationIdentity  $identity
     * @return void
     */
    private function insertSessions(IntegrationIdentity $identity): void
    {
        $owner    = IdentifierCoercion::stringify($identity->getKey());
        $sessions = array_map(static fn (int $key): array => [
            'id'                   => $key,
            'generation'           => (string) Str::uuid7(),
            'authenticatable_type' => $identity->getMorphClass(),
            'authenticatable_id'   => $owner,
            'principal_type'       => $identity->getMorphClass(),
            'principal_id'         => $owner,
            'status'               => 'active',
            'guard'                => 'api',
            'sign_in_method'       => 'sso',
            'refresh_key'          => hash('sha256', 'refresh-' . $key),
            'signed_in_at'         => '2027-01-15 09:00:00',
            'idle_expires_at'      => '2027-02-15 09:00:00',
            'absolute_expires_at'  => '2027-07-15 09:00:00',
        ], range(1, self::THROUGH + 3));

        $provenance = array_map(static fn (int $key): array => [
            'session_id'    => (string) $key,
            'connection_id' => $key <= self::THROUGH ? 'conn-a' : 'conn-b',
            'created_at'    => self::NOW,
        ], range(1, self::THROUGH + 3));

        foreach (array_chunk($sessions, 200) as $chunk) {
            DB::table(self::TABLE)->insert($chunk);
        }

        foreach (array_chunk($provenance, 200) as $chunk) {
            DB::table('authentication_provenance')->insert($chunk);
        }
    }

    /**
     * The keys of the sessions left unrevoked, in order.
     *
     * @return list<int>
     */
    private static function unrevoked(): array
    {
        return array_values(array_map(intval(...), DB::table(self::TABLE)->whereNull('revoked_at')->orderBy('id')->pluck('id')->all()));
    }
}
