<?php

declare(strict_types = 1);

namespace Tests\Performance;

use Carbon\Carbon;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Events\EventContext;
use SineMacula\Laravel\Authentication\Events\SessionAuthenticated;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Listeners\RecordSessionUsage;
use Tests\Concerns\InteractsWithSessionRecords;
use Tests\Unit\Stubs\StubSession;

/**
 * Query-budget contracts for isolated session last-use writes: the time, IP
 * address, and user agent are written in one update, and nothing is read.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RecordSessionUsage::class)]
final class RecordSessionUsageQueryBudgetTest extends PerformanceContractTestCase
{
    use InteractsWithSessionRecords;

    /** @var string Timestamp format used by the session table columns. */
    private const string DATETIME_FORMAT = 'Y-m-d H:i:s';

    /**
     * Provision the persisted stub-session table.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        self::createSessionRecordTable('stub_sessions');
    }

    /**
     * Release the persisted stub-session table.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Schema::dropIfExists('stub_sessions');

        parent::tearDown();
    }

    /**
     * Within the debounce window the listener should skip all SQL activity.
     *
     * @return void
     */
    public function testListenerWithinThrottleWindowUsesZeroReadsAndNoWrites(): void
    {
        config()->set('authentication.session.last_used_throttle_seconds', 60);

        $session = $this->makePersistedSession($this->now);

        $advanced = $this->now->copy()->addSeconds(30);
        Carbon::setTestNow($advanced);

        $listener = app(RecordSessionUsage::class);

        $this->assertQueryBudget(0, 0, static fn () => $listener(new SessionAuthenticated(new EventContext('api', new ClientContext('127.0.0.1', null), session: $session))));

        self::assertSame($this->now->format(self::DATETIME_FORMAT), $session->last_used_at?->format(self::DATETIME_FORMAT));
    }

    /**
     * A stale or missing last use should do exactly one update, which writes
     * the time and the client together, and no reads.
     *
     * @return void
     */
    public function testListenerForStaleTimestampUsesZeroReadsAndOneWrite(): void
    {
        config()->set('authentication.session.last_used_throttle_seconds', 60);

        $session = $this->makePersistedSession(null);

        $advanced = $this->now->copy()->addSeconds(61);
        Carbon::setTestNow($advanced);

        $listener = app(RecordSessionUsage::class);

        $this->assertQueryBudget(0, 1, static fn () => $listener(new SessionAuthenticated(new EventContext('api', new ClientContext('127.0.0.1', null), session: $session))));

        self::assertSame($advanced->format(self::DATETIME_FORMAT), $session->last_used_at?->format(self::DATETIME_FORMAT));
        self::assertSame('127.0.0.1', $session->last_used_ip);
    }

    /**
     * Persist one stub session with an optional stored last-use time.
     *
     * @param  ?\Carbon\Carbon  $lastUsedAt
     * @return \Tests\Unit\Stubs\StubSession
     */
    private function makePersistedSession(?Carbon $lastUsedAt): StubSession
    {
        $session = new StubSession;
        $session->forceFill([
            'refresh_key'  => 'stub-refresh-key',
            'last_used_at' => $lastUsedAt,
        ])->save();

        return $session;
    }
}
