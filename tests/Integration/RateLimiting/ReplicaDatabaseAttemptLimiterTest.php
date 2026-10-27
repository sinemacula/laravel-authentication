<?php

declare(strict_types = 1);

namespace Tests\Integration\RateLimiting;

use Carbon\Carbon;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\DatabaseManager;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Contracts\AttemptLimiter;
use SineMacula\Laravel\Authentication\RateLimiting\AttemptSubject;
use SineMacula\Laravel\Authentication\RateLimiting\DatabaseAttemptLimiter;
use SineMacula\Laravel\Authentication\RateLimiting\Enums\AttemptFlow;
use SineMacula\Laravel\Authentication\RateLimiting\RateLimitStore;
use Tests\Concerns\InteractsWithLaggingReplica;
use Tests\TestCase;

/**
 * Proves the limiter counts and reads on the write connection: with a read
 * replica that has not seen the counters, attempts are still refused and
 * failures still block.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DatabaseAttemptLimiter::class)]
#[CoversClass(RateLimitStore::class)]
final class ReplicaDatabaseAttemptLimiterTest extends TestCase
{
    use InteractsWithLaggingReplica;

    /**
     * Create the counters table on the replica too; the shipped migrations
     * create it on the primary.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        Carbon::setTestNow(Carbon::createFromTimestamp(1800000150));

        $migration = require __DIR__ . '/../../../database/migrations/2026_04_06_000002_create_rate_limits_table.php';

        /** @var \Illuminate\Database\DatabaseManager $manager */
        $manager = app(DatabaseManager::class);

        $manager->setDefaultConnection(self::REPLICA_CONNECTION);
        $migration->up();
        $manager->setDefaultConnection(self::SPLIT_CONNECTION);
    }

    /**
     * Release the clock and remove the temporary database files.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Carbon::setTestNow();

        parent::tearDown();

        $this->removeLaggingReplicaFiles();
    }

    /**
     * Failures recorded on the primary block the next refresh although the
     * replica has no counter at all.
     *
     * @return void
     */
    public function testFailuresBlockWhileTheReplicaLags(): void
    {
        $subject = new AttemptSubject('api', AttemptFlow::REFRESH, 'device-1', null, '203.0.113.7');

        $this->limiter()->recordFailure($subject);
        $this->limiter()->recordFailure($subject);

        self::assertSame(0, DB::connection(self::REPLICA_CONNECTION)->table('rate_limits')->count());
        self::assertSame(30, $this->limiter()->blocked($subject));
    }

    /**
     * Sign-in slots taken on the primary fill the window although the replica
     * has none.
     *
     * @return void
     */
    public function testSignInIsRefusedWhileTheReplicaLags(): void
    {
        $subject = new AttemptSubject('api', AttemptFlow::SIGN_IN, 'ben@example.com', 'email', null);

        self::assertTrue($this->limiter()->acquire($subject)->granted());
        self::assertTrue($this->limiter()->acquire($subject)->granted());
        self::assertFalse($this->limiter()->acquire($subject)->granted());
        self::assertSame(0, DB::connection(self::REPLICA_CONNECTION)->table('rate_limits')->count());
    }

    /**
     * Configure the lagging replica and the guard's limits.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        /** @var \Illuminate\Config\Repository $config */
        $config = app(ConfigRepository::class);

        $this->configureLaggingReplica($config);

        $config->set('auth.guards.api', [
            'driver'      => 'jwt',
            'provider'    => 'users',
            'rate_limits' => [
                'sign_in' => ['per_identifier' => ['max' => 2, 'decay_seconds' => 300]],
                'refresh' => ['per_identifier' => ['max' => 2, 'decay_seconds' => 60]],
            ],
        ]);
    }

    /**
     * The container's attempt limiter.
     *
     * @return \SineMacula\Laravel\Authentication\Contracts\AttemptLimiter
     */
    private function limiter(): AttemptLimiter
    {
        $limiter = $this->app?->make(AttemptLimiter::class);

        self::assertInstanceOf(AttemptLimiter::class, $limiter);

        return $limiter;
    }
}
