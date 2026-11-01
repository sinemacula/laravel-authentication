<?php

declare(strict_types = 1);

namespace Benchmarks\Support;

use Carbon\Carbon;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Container\Container;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Facade;
use SineMacula\Laravel\Authentication\Events\EventContext;
use SineMacula\Laravel\Authentication\Events\SessionAuthenticated;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Listeners\RecordSessionUsage;
use Tests\Unit\Stubs\StubSession;

/**
 * Runtime benchmark fixtures for session last-use writes.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class RecordSessionUsageBenchHarness
{
    /** @var int Number of mutable write-path sessions to pre-seed. */
    private const int WRITE_SESSION_POOL_SIZE = 128;

    /** @var \SineMacula\Laravel\Authentication\Listeners\RecordSessionUsage */
    private readonly RecordSessionUsage $listener;

    /** @var \Tests\Unit\Stubs\StubSession */
    private readonly StubSession $freshSession;

    /** @var list<\Tests\Unit\Stubs\StubSession> */
    private array $staleSessions = [];

    /** @var int Current index into the stale-session pool. */
    private int $staleSessionIndex = 0;

    /**
     * Seed the listener benchmark fixtures, and check that each path reaches
     * the outcome it measures.
     *
     * @throws \LogicException
     */
    public function __construct()
    {
        BenchDatabase::boot();

        $now = Carbon::createStrict(2026, 4, 10, 12, 0, 0);
        Carbon::setTestNow($now);

        $config = new ConfigRepository([
            'authentication' => [
                'session' => [
                    'last_used_throttle_seconds' => 60,
                ],
            ],
        ]);

        $container = new Container;
        $container->instance('config', $config);
        Facade::setFacadeApplication($container);

        $this->listener = new RecordSessionUsage;

        $this->createSchema();

        $freshSession = new StubSession;
        $freshSession->forceFill([
            ...BenchSchema::liveSession(),
            'client_name'  => 'bench-session-fresh',
            'refresh_key'  => 'bench-session-fresh',
            'last_used_at' => Carbon::now(),
        ])->save();

        $this->freshSession = $freshSession;

        for ($index = 0; $index < self::WRITE_SESSION_POOL_SIZE; $index++) {

            $session = new StubSession;
            $session->forceFill([
                ...BenchSchema::liveSession(),
                'client_name'  => 'bench-session-stale-' . $index,
                'refresh_key'  => 'bench-session-stale-' . $index,
                'last_used_at' => null,
            ])->save();

            $this->staleSessions[] = $session;
        }

        $this->assertEachPathReachesItsOutcome();
    }

    /**
     * Benchmark the debounced no-op listener path.
     *
     * @return void
     */
    public function runWithinThrottleSkip(): void
    {
        ($this->listener)(self::bound($this->freshSession));
    }

    /**
     * Benchmark the listener path that persists a fresh timestamp.
     *
     * @return void
     */
    public function runStaleTimestampWrite(): void
    {
        $session = $this->staleSessions[$this->staleSessionIndex % count($this->staleSessions)];
        $this->staleSessionIndex++;

        ($this->listener)(self::bound($session));
    }

    /**
     * Run each benchmarked path once and throw unless it reaches the outcome
     * its name describes: a session used within the throttle writes nothing,
     * and one never used writes its last use. Both run on sessions of their
     * own, so the benchmark's sessions are untouched.
     *
     * @return void
     *
     * @throws \LogicException
     */
    private function assertEachPathReachesItsOutcome(): void
    {
        foreach (['within-throttle skip' => [Carbon::now(), false], 'stale timestamp write' => [null, true]] as $path => [$lastUsedAt, $writes]) {

            $session = new StubSession;
            $session->forceFill([
                ...BenchSchema::liveSession(),
                'client_name'  => 'bench-session-check',
                'refresh_key'  => 'bench-session-check',
                'last_used_at' => $lastUsedAt,
            ])->save();

            $statements = BenchOutcome::statementsOf(function () use ($session): void {
                ($this->listener)(self::bound($session));
            });
            $wrote = array_filter($statements, static fn (string $statement): bool => str_starts_with($statement, 'update')) !== [];

            BenchOutcome::assert($path, $wrote === $writes);
        }
    }

    /**
     * Create the shared tables once.
     *
     * @return void
     */
    private function createSchema(): void
    {
        $schema = BenchDatabase::schema();

        if ($schema->hasTable('stub_sessions')) {
            return;
        }

        $schema->create('stub_sessions', static function (Blueprint $blueprint): void {
            BenchSchema::defineSessionColumns($blueprint);
        });
    }

    /**
     * The event of the session bound for the benchmark's client.
     *
     * @param  \Tests\Unit\Stubs\StubSession  $session
     * @return \SineMacula\Laravel\Authentication\Events\SessionAuthenticated
     */
    private static function bound(StubSession $session): SessionAuthenticated
    {
        return new SessionAuthenticated(new EventContext('api', ClientContext::fromRequest(BenchRequest::client()), session: $session));
    }
}
