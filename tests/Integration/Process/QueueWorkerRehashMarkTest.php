<?php

declare(strict_types = 1);

namespace Tests\Integration\Process;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Application;
use Illuminate\Queue\Worker;
use Illuminate\Queue\WorkerOptions;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\AuthenticationServiceProvider;
use SineMacula\Laravel\Authentication\Listeners\RevokeDevicesOnPasswordChange;
use SineMacula\Laravel\Authentication\Sessions\Methods\Rehashing;
use Tests\Concerns\InteractsWithSessions;
use Tests\Integration\Fixtures\AbandonedAttemptJob;
use Tests\Integration\Fixtures\IntegrationIdentity;
use Tests\Integration\Fixtures\LogoutOtherDevicesJob;
use Tests\TestCase;

/**
 * End-to-end tests for the rehash mark across queued jobs run by one worker in
 * one application: an attempt one job abandons leaves its user marked, and a
 * worker forgets only scoped instances between jobs, so only the mark's scoped
 * binding keeps a later job's change of password from being taken for that
 * attempt's rehash.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuthenticationServiceProvider::class)]
#[CoversClass(Rehashing::class)]
final class QueueWorkerRehashMarkTest extends TestCase
{
    use InteractsWithSessions;

    /**
     * Create the tables, the queue's included.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->createSessionTables();

        Schema::create('jobs', static function (Blueprint $blueprint): void {
            $blueprint->id();
            $blueprint->string('queue')->index();
            $blueprint->longText('payload');
            $blueprint->unsignedTinyInteger('attempts');
            $blueprint->unsignedInteger('reserved_at')->nullable();
            $blueprint->unsignedInteger('available_at');
            $blueprint->unsignedInteger('created_at');
        });
    }

    /**
     * Drop the tables.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Schema::dropIfExists('jobs');

        $this->dropSessionTables();

        parent::tearDown();
    }

    /**
     * With the mark shared for the life of the worker, the attempt the first
     * job abandoned still marks its user when the second job signs that user's
     * other devices out, and the sessions survive: the leak the scoped binding
     * closes.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAMarkSharedAcrossJobsLeaksIntoTheNext(): void
    {
        $shared = new Rehashing;

        $this->app?->bind(Rehashing::class, static fn (): Rehashing => $shared);

        $this->runBothJobs();

        self::assertSame(0, DB::table('devices')->whereNotNull('revoked_at')->count());
    }

    /**
     * With the package's scoped binding, the second job starts with no mark, so
     * its forced rehash is answered as the sign-out it is.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testEachJobStartsWithNoMark(): void
    {
        $this->runBothJobs();

        self::assertSame('password_changed', DB::table('devices')->value('revoked_reason'));
    }

    /**
     * Configure the guards, Laravel's session guards over an Eloquent user
     * provider of the identity model, and a database queue.
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

        self::configureSessionGuards($config);

        $config->set('auth.defaults.guard', 'api');
        $config->set('auth.providers.users', ['driver' => 'eloquent', 'model' => IntegrationIdentity::class]);
        $config->set('auth.guards.web', ['driver' => 'session', 'provider' => 'users']);
        $config->set('auth.guards.console', ['driver' => 'session', 'provider' => 'users']);
        $config->set('auth.timebox_duration', 1);
        $config->set('session.driver', 'array');
        $config->set('queue.default', 'database');
        $config->set('queue.connections.database', ['driver' => 'database', 'table' => 'jobs', 'queue' => 'default', 'retry_after' => 90]);
    }

    /**
     * Sign an observed identity in, then queue a job that abandons a `web`
     * attempt for it and one that signs its other devices out, and run both
     * through one worker's loop, which forgets scoped instances before each
     * job.
     *
     * @return void
     *
     * @throws \Throwable
     */
    private function runBothJobs(): void
    {
        $identity = $this->seedIdentity();

        self::assertTrue($this->sessions()->signIn('password', self::credentials())->isSignedIn());

        IntegrationIdentity::observe(RevokeDevicesOnPasswordChange::class);

        dispatch(new AbandonedAttemptJob(self::credentials()));
        dispatch(new LogoutOtherDevicesJob((int) $identity->getKey(), self::PASSWORD)); // @phpstan-ignore cast.int

        $worker = $this->app?->make('queue.worker');

        self::assertInstanceOf(Worker::class, $worker);

        $options = new WorkerOptions(sleep: 0, maxTries: 1, stopWhenEmpty: true);

        self::assertSame(Worker::EXIT_SUCCESS, self::keepingSignalHandlers(static fn (): mixed => $worker->daemon('database', 'default', $options)));
        self::assertTrue($this->app?->make('abandoned.attempt'));
        self::assertSame(0, DB::table('jobs')->count());
    }

    /**
     * Run the callback, then restore the signal handlers a worker's loop
     * installs, so the test process still stops on an interrupt.
     *
     * @param  \Closure(): mixed  $callback
     * @return mixed
     */
    private static function keepingSignalHandlers(\Closure $callback): mixed
    {
        if (!function_exists('pcntl_signal_get_handler')) {
            return $callback();
        }

        $signals  = [SIGQUIT, SIGTERM, SIGINT, SIGUSR2, SIGCONT];
        $handlers = array_map(pcntl_signal_get_handler(...), $signals);
        $async    = pcntl_async_signals();

        try {
            return $callback();
        } finally {
            foreach ($signals as $index => $signal) {
                pcntl_signal($signal, $handlers[$index]);
            }

            pcntl_async_signals($async);
        }
    }
}
