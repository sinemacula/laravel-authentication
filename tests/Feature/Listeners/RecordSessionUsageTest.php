<?php

declare(strict_types = 1);

namespace Tests\Feature\Listeners;

use Carbon\Carbon;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use Orchestra\Testbench\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\Session;
use SineMacula\Laravel\Authentication\Events\EventContext;
use SineMacula\Laravel\Authentication\Events\SessionAuthenticated;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Listeners\RecordSessionUsage;
use Tests\Concerns\InteractsWithSessionRecords;
use Tests\Integration\Fixtures\UncastSession;
use Tests\Unit\Stubs\StubBareSession;
use Tests\Unit\Stubs\StubSession;

/**
 * Feature tests for the RecordSessionUsage listener.
 *
 * Uses Orchestra Testbench with an in-memory sqlite connection and a
 * manually-created session table so the listener's persistence is exercised
 * end-to-end without the package migration.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RecordSessionUsage::class)]
final class RecordSessionUsageTest extends TestCase
{
    use InteractsWithSessionRecords, MockeryPHPUnitIntegration;

    /** @var string Timestamp format for assertions. */
    private const string DATETIME_FORMAT = 'Y-m-d H:i:s';

    /** @var string IP address the test requests come from. */
    private const string IP = '203.0.113.7';

    /** @var string User agent the test requests send. */
    private const string USER_AGENT = 'Mozilla/5.0 (iPhone; CPU iPhone OS 18_4 like Mac OS X)';

    /** @var \Carbon\Carbon Frozen clock reference. */
    private Carbon $now;

    /**
     * Freeze the clock and create the session tables the listener persists
     * against.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->now = Carbon::createStrict(2026, 4, 6, 12, 0, 0);

        Carbon::setTestNow($this->now);

        config()->set('authentication.session.last_used_throttle_seconds', 60);

        self::createSessionRecordTable('stub_sessions');
        self::createSessionRecordTable('authentication_sessions');
    }

    /**
     * Release the frozen clock and drop the in-memory schema once each test has
     * completed.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Carbon::setTestNow();

        Schema::dropIfExists('authentication_sessions');
        Schema::dropIfExists('stub_sessions');

        parent::tearDown();
    }

    /**
     * A first use records the time, the request's IP address, and its user
     * agent on the row in one update, and mirrors them on the in-memory model
     * as persisted state.
     *
     * @return void
     */
    public function testRecordsTheTimeIpAndUserAgentOfAFirstUse(): void
    {
        $session = $this->persistedSession(null);

        (new RecordSessionUsage)(self::bound($session, self::IP, self::USER_AGENT));

        $row = $this->storedRow($session->id);

        self::assertSame($this->now->format(self::DATETIME_FORMAT), $row['last_used_at']);
        self::assertSame(self::IP, $row['last_used_ip']);
        self::assertSame(self::USER_AGENT, $row['last_used_user_agent']);

        self::assertSame($this->now->getTimestamp(), $session->getLastUsedAt()?->getTimestamp());
        self::assertSame(self::IP, $session->getAttribute('last_used_ip'));
        self::assertSame(self::USER_AGENT, $session->getAttribute('last_used_user_agent'));
        self::assertFalse($session->isDirty(['last_used_at', 'last_used_ip', 'last_used_user_agent']));
    }

    /**
     * The use is recorded on the session that was used and on no other:
     * sessions of the same owner and of another owner keep their own last use.
     *
     * @return void
     */
    public function testRecordsTheUseOnTheUsedSessionOnly(): void
    {
        $session = $this->persistedSession(null, ['authenticatable_type' => 'owner', 'authenticatable_id' => '1']);

        $earlier = $this->now->copy()->subDay();
        $others  = [
            $this->persistedSession($earlier, [
                'authenticatable_type' => 'owner',
                'authenticatable_id'   => '1',
                'last_used_ip'         => '198.51.100.9',
                'last_used_user_agent' => 'Other/1.0',
            ]),
            $this->persistedSession($earlier, [
                'authenticatable_type' => 'owner',
                'authenticatable_id'   => '2',
                'last_used_ip'         => '198.51.100.10',
                'last_used_user_agent' => 'Another/1.0',
            ]),
        ];

        $before = array_map(fn (StubSession $other): array => $this->storedRow($other->id), $others);

        (new RecordSessionUsage)(self::bound($session, self::IP, self::USER_AGENT));

        self::assertSame(self::IP, $this->storedRow($session->id)['last_used_ip']);
        self::assertSame($before, array_map(fn (StubSession $other): array => $this->storedRow($other->id), $others));
    }

    /**
     * Within the throttle window nothing is written, neither the time nor the
     * client the request came from.
     *
     * @return void
     */
    public function testSkipsTheWriteWithinTheThrottleWindow(): void
    {
        $session = $this->persistedSession($this->now);

        Carbon::setTestNow($this->now->copy()->addSeconds(59));

        (new RecordSessionUsage)(self::bound($session, '198.51.100.1', 'Other/1.0'));

        $row = $this->storedRow($session->id);

        self::assertSame($this->now->format(self::DATETIME_FORMAT), $row['last_used_at']);
        self::assertNull($row['last_used_ip']);
        self::assertNull($row['last_used_user_agent']);
    }

    /**
     * Rows of `[seconds elapsed since the recorded use, whether it is written
     * again]` around a 60-second throttle window.
     *
     * @return iterable<string, array{0: int, 1: bool}>
     */
    public static function provideElapsedSeconds(): iterable
    {
        yield from [
            'one second before the window' => [59, false],
            'exactly the window'           => [60, true],
            'one second after the window'  => [61, true],
        ];
    }

    /**
     * A use is recorded again once the throttle window has fully elapsed, the
     * boundary second included.
     *
     * @param  int  $elapsed
     * @param  bool  $written
     * @return void
     */
    #[DataProvider('provideElapsedSeconds')]
    public function testRecordsAgainOnceTheThrottleWindowHasElapsed(int $elapsed, bool $written): void
    {
        $session = $this->persistedSession($this->now);

        $later = $this->now->copy()->addSeconds($elapsed);

        Carbon::setTestNow($later);

        (new RecordSessionUsage)(self::bound($session, self::IP, self::USER_AGENT));

        self::assertSame(
            ($written ? $later : $this->now)->format(self::DATETIME_FORMAT),
            $this->storedRow($session->id)['last_used_at'],
        );
    }

    /**
     * A last-use time stored without a `datetime` cast still starts the
     * throttle window, rather than reading as "never used" and writing on every
     * request.
     *
     * @return void
     */
    public function testThrottlesASessionWhoseLastUseIsStoredUncast(): void
    {
        $session = new UncastSession;
        $session->forceFill(['last_used_at' => $this->now->format(self::DATETIME_FORMAT)])->save();

        $session = UncastSession::query()->findOrFail($session->getKey());

        Carbon::setTestNow($this->now->copy()->addSeconds(30));

        $queries = $this->countQueries(fn () => (new RecordSessionUsage)(self::bound($session, self::IP, self::USER_AGENT)));

        self::assertSame(0, $queries);
    }

    /**
     * A last use recorded further in the future than the throttle window, by a
     * server whose clock ran ahead, is replaced with the real time instead of
     * blocking every write until it is reached.
     *
     * @return void
     */
    public function testCorrectsALastUseRecordedInTheFuture(): void
    {
        $session = $this->persistedSession($this->now->copy()->addMinutes(2));

        (new RecordSessionUsage)(self::bound($session, self::IP, self::USER_AGENT));

        self::assertSame($this->now->format(self::DATETIME_FORMAT), $this->storedRow($session->id)['last_used_at']);
    }

    /**
     * A throttle of zero or less records every use, even one in the same second
     * as the last.
     *
     * @return void
     */
    public function testRecordsEveryUseWhenTheThrottleIsDisabled(): void
    {
        config()->set('authentication.session.last_used_throttle_seconds', -1);

        $session = $this->persistedSession($this->now);

        (new RecordSessionUsage)(self::bound($session, self::IP, self::USER_AGENT));

        self::assertSame(self::IP, $this->storedRow($session->id)['last_used_ip']);
    }

    /**
     * The client is stored as `ClientContext` cleans it: an address that is not
     * an IP address is dropped, and a user agent with a NUL byte and invalid
     * UTF-8 is stored without them.
     *
     * @return void
     */
    public function testStoresTheClientAsClientContextCleansIt(): void
    {
        $session = $this->persistedSession(null);

        (new RecordSessionUsage)(self::bound($session, 'not-an-ip', "Agent\0/1.0 \xC3\x28"));

        $row = $this->storedRow($session->id);

        self::assertNull($row['last_used_ip']);
        self::assertSame('Agent/1.0 ?(', $row['last_used_user_agent']);
    }

    /**
     * A generic `Session` that is not an Eloquent model is ignored without a
     * query.
     *
     * @return void
     */
    public function testIgnoresASessionThatIsNotAnEloquentModel(): void
    {
        $session = \Mockery::mock(Session::class);
        $session->shouldReceive('getSessionIdentifier')->andReturn('plain-session');
        $session->shouldNotReceive('getLastUsedAt');

        $queries = $this->countQueries(fn () => (new RecordSessionUsage)(self::bound($session, self::IP, self::USER_AGENT)));

        self::assertSame(0, $queries);
    }

    /**
     * A persisted Eloquent model that implements only the generic `Session`
     * contract, without the column names the write needs, is ignored.
     *
     * @return void
     */
    public function testIgnoresAPersistedModelOutsideTheEloquentSessionBoundary(): void
    {
        $session         = new StubBareSession;
        $session->exists = true;

        $queries = $this->countQueries(fn () => (new RecordSessionUsage)(self::bound($session, self::IP, self::USER_AGENT)));

        self::assertSame(0, $queries);
    }

    /**
     * An Eloquent session that was never saved is ignored: nothing is written
     * and the in-memory model is left as it was.
     *
     * @return void
     */
    public function testIgnoresAnUnpersistedEloquentSession(): void
    {
        $session = new StubSession;

        $queries = $this->countQueries(fn () => (new RecordSessionUsage)(self::bound($session, self::IP, self::USER_AGENT)));

        self::assertSame(0, $queries);
        self::assertNull($session->getAttribute('last_used_at'));
    }

    /**
     * Define the test environment: in-memory sqlite connection.
     *
     * @param  mixed  $app
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        assert($app instanceof Application);

        /** @var \Illuminate\Config\Repository $config */
        $config = $app->make(ConfigRepository::class);

        $config->set('database.default', 'testing');
        $config->set('database.connections.testing', [
            'driver'   => 'sqlite',
            'database' => ':memory:',
            'prefix'   => '',
        ]);
    }

    /**
     * The event of the session bound for a client with the given IP address and
     * user agent.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @param  string  $ip
     * @param  string  $userAgent
     * @return \SineMacula\Laravel\Authentication\Events\SessionAuthenticated
     */
    private static function bound(Session $session, string $ip, string $userAgent): SessionAuthenticated
    {
        return new SessionAuthenticated(new EventContext('api', new ClientContext($ip, $userAgent), session: $session));
    }

    /**
     * Persist a stub session last used at the given time, with any further
     * state.
     *
     * @param  ?\Carbon\Carbon  $lastUsedAt
     * @param  array<string, mixed>  $state
     * @return \Tests\Unit\Stubs\StubSession
     */
    private function persistedSession(?Carbon $lastUsedAt, array $state = []): StubSession
    {
        $session = new StubSession;
        $session->forceFill(['last_used_at' => $lastUsedAt, ...$state])->save();

        return $session;
    }

    /**
     * Read the last-use columns stored on a stub session row.
     *
     * @param  string  $id
     * @return array<string, mixed>
     */
    private function storedRow(string $id): array
    {
        return (array) DB::table('stub_sessions')
            ->where('id', $id)
            ->first(['last_used_at', 'last_used_ip', 'last_used_user_agent']);
    }

    /**
     * Count the queries a callback runs.
     *
     * @param  callable(): mixed  $callback
     * @return int
     */
    private function countQueries(callable $callback): int
    {
        $queries = 0;

        DB::listen(static function () use (&$queries): void {
            $queries++;
        });

        $callback();

        return $queries;
    }
}
