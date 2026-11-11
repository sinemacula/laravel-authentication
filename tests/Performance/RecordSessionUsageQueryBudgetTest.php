<?php

declare(strict_types = 1);

namespace Tests\Performance;

use Carbon\Carbon;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Events\EventContext;
use SineMacula\Laravel\Authentication\Events\SessionAuthenticated;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Listeners\RecordSessionUsage;
use Tests\Concerns\InteractsWithSessionRecords;
use Tests\Unit\Stubs\PlainIdentityFixture;
use Tests\Unit\Stubs\PlainPrincipalFixture;
use Tests\Unit\Stubs\StubIdentity;
use Tests\Unit\Stubs\StubSession;

/**
 * Query-budget contracts for writing a session's last use.
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

        config()->set('authentication.session.model', StubSession::class);

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

        $this->bindGuardTo($session);

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

        $this->bindGuardTo($session);

        $advanced = $this->now->copy()->addSeconds(61);
        Carbon::setTestNow($advanced);

        $listener = app(RecordSessionUsage::class);

        $this->assertQueryBudget(0, 1, static fn () => $listener(new SessionAuthenticated(new EventContext('api', new ClientContext('127.0.0.1', null), session: $session))));

        self::assertSame($advanced->format(self::DATETIME_FORMAT), $session->last_used_at?->format(self::DATETIME_FORMAT));
        self::assertSame('127.0.0.1', $session->last_used_ip);
    }

    /**
     * A session no resolved guard has bound is read by its identifier, once,
     * and then written as a bound one is.
     *
     * @return void
     */
    public function testListenerForAnUnboundSessionUsesOneReadAndOneWrite(): void
    {
        config()->set('authentication.session.last_used_throttle_seconds', 60);

        $session  = $this->makePersistedSession(null);
        $listener = app(RecordSessionUsage::class);

        $this->assertQueryBudget(1, 1, static fn () => $listener(new SessionAuthenticated(new EventContext('api', new ClientContext('127.0.0.1', null), session: $session))));
    }

    /**
     * Configure the `api` guard.
     *
     * @param  mixed  $app
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        assert($app instanceof Application);

        $config = $app->make(ConfigRepository::class);

        $config->set('auth.providers.identities', ['driver' => 'model', 'model' => StubIdentity::class]);
        $config->set('auth.guards.api', ['driver' => 'jwt', 'provider' => 'identities']);
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
            'tenant_id'    => null,
        ])->save();

        return $session;
    }

    /**
     * Bind the `api` guard to the session, with its own report of the bind held
     * back.
     *
     * @param  \Tests\Unit\Stubs\StubSession  $session
     * @return void
     */
    private function bindGuardTo(StubSession $session): void
    {
        Event::fake([SessionAuthenticated::class]);

        Auth::forgetGuards();

        $guard = app('auth')->guard('api');

        self::assertInstanceOf(JwtGuard::class, $guard);

        $guard->login(new PlainIdentityFixture(1), new PlainPrincipalFixture('p-1'), $session);
    }
}
