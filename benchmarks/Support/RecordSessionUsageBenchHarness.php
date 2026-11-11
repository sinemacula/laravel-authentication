<?php

declare(strict_types = 1);

namespace Benchmarks\Support;

use Carbon\Carbon;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Application;
use Illuminate\Support\Timebox;
use SineMacula\Laravel\Authentication\Events\EventContext;
use SineMacula\Laravel\Authentication\Events\SessionAuthenticated;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Listeners\RecordSessionUsage;
use SineMacula\Laravel\Authentication\Providers\ModelProvider;
use SineMacula\Laravel\Authentication\Resolvers\DefaultPrincipalResolver;
use Tests\Unit\Stubs\PlainIdentityFixture;
use Tests\Unit\Stubs\PlainPrincipalFixture;
use Tests\Unit\Stubs\StubIdentity;
use Tests\Unit\Stubs\StubRequestResolvingGuard;
use Tests\Unit\Stubs\StubSession;

/**
 * Runtime benchmark fixtures for session last-use writes, on sessions already
 * bound to a resolved guard.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class RecordSessionUsageBenchHarness
{
    /** @var int Number of mutable write-path sessions to pre-seed. */
    private const int WRITE_SESSION_POOL_SIZE = 128;

    /** @var \Illuminate\Foundation\Application */
    private readonly Application $app;

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
        $now = Carbon::createStrict(2026, 4, 10, 12, 0, 0);
        Carbon::setTestNow($now);

        $guards = ['bench-fresh' => ['driver' => 'bench-usage'], 'bench-check' => ['driver' => 'bench-usage']];

        for ($index = 0; $index < self::WRITE_SESSION_POOL_SIZE; $index++) {
            $guards['bench-stale-' . $index] = ['driver' => 'bench-usage'];
        }

        $app = PackageBenchApplication::create($guards);

        $app['config']->set('authentication.session.last_used_throttle_seconds', 60);
        $app['auth']->extend('bench-usage', fn (Application $app, string $name): StubRequestResolvingGuard => new StubRequestResolvingGuard(
            $name,
            new ModelProvider($app->make('hash'), StubIdentity::class),
            new DefaultPrincipalResolver,
            $app->make('events'),
            BenchRequest::client(),
            new Timebox,
        ));

        $this->app      = $app;
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

        $this->bind('bench-fresh', $freshSession);

        for ($index = 0; $index < self::WRITE_SESSION_POOL_SIZE; $index++) {

            $session = new StubSession;
            $session->forceFill([
                ...BenchSchema::liveSession(),
                'client_name'  => 'bench-session-stale-' . $index,
                'refresh_key'  => 'bench-session-stale-' . $index,
                'last_used_at' => null,
            ])->save();

            $this->bind('bench-stale-' . $index, $session);

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
        ($this->listener)(self::bound('bench-fresh', $this->freshSession));
    }

    /**
     * Benchmark the listener path that persists a fresh timestamp.
     *
     * @return void
     */
    public function runStaleTimestampWrite(): void
    {
        $index = $this->staleSessionIndex % count($this->staleSessions);
        $this->staleSessionIndex++;

        ($this->listener)(self::bound('bench-stale-' . $index, $this->staleSessions[$index]));
    }

    /**
     * Run each benchmarked path once and throw unless it reaches the outcome
     * its name describes.
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

            $this->bind('bench-check', $session);

            $statements = BenchOutcome::statementsOf(function () use ($session): void {
                ($this->listener)(self::bound('bench-check', $session));
            });
            $wrote = array_filter($statements, static fn (string $statement): bool => str_starts_with($statement, 'update')) !== [];
            $read  = array_filter($statements, static fn (string $statement): bool => str_starts_with($statement, 'select')) !== [];

            BenchOutcome::assert($path, $wrote === $writes && !$read);
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
     * Resolve the named guard through the auth manager and bind it to the
     * session, as a request's authentication binds it.
     *
     * @param  string  $guard
     * @param  \Tests\Unit\Stubs\StubSession  $session
     * @return void
     */
    private function bind(string $guard, StubSession $session): void
    {
        /** @var \SineMacula\Laravel\Authentication\AuthManager $auth */
        $auth     = $this->app->make('auth');
        $resolved = $auth->guard($guard);

        assert($resolved instanceof StubRequestResolvingGuard);

        $resolved->login(new PlainIdentityFixture(1), new PlainPrincipalFixture('p-1'), $session);
    }

    /**
     * The event of the session the named guard bound, for the benchmark's
     * client.
     *
     * @param  string  $guard
     * @param  \Tests\Unit\Stubs\StubSession  $session
     * @return \SineMacula\Laravel\Authentication\Events\SessionAuthenticated
     */
    private static function bound(string $guard, StubSession $session): SessionAuthenticated
    {
        return new SessionAuthenticated(new EventContext($guard, ClientContext::fromRequest(BenchRequest::client()), session: $session));
    }
}
