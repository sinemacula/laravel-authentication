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
use Tests\Integration\Fixtures\SavePasswordJob;
use Tests\TestCase;

/**
 * End-to-end tests for the rehash mark across queued jobs run by one worker in
 * one application: an attempt one job abandons leaves its user marked, and a
 * worker forgets only scoped instances between jobs, so only the mark's scoped
 * binding keeps a later job's save of a fresh hash of the same password from
 * being taken for that attempt's rehash. A later job's `logoutOtherDevices()`
 * revokes either way, since its `OtherDeviceLogout` tells its forced rehash
 * apart.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuthenticationServiceProvider::class)]
#[CoversClass(Rehashing::class)]
final class QueueWorkerRehashingTest extends TestCase
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
     * Even with the mark shared for the life of the worker, the second job's
     * save of a fresh hash of the password revokes: the attempt the first job
     * abandoned validated an instance no later job saves.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASavedPasswordRevokesEvenWithTheMarkShared(): void
    {
        $this->shareOneMark();

        $this->runBothJobs(SavePasswordJob::class);

        self::assertSame('password_changed', DB::table('devices')->value('revoked_reason'));
    }

    /**
     * With the package's scoped binding, the second job starts with no mark, so
     * its save is answered as the change it is.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testEachJobStartsWithNoMark(): void
    {
        $this->runBothJobs(SavePasswordJob::class);

        self::assertSame('password_changed', DB::table('devices')->value('revoked_reason'));
    }

    /**
     * A second job's `logoutOtherDevices()` is answered as the sign-out it is,
     * even with the mark shared.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testLogoutOtherDevicesRevokesEvenWithTheMarkShared(): void
    {
        $this->shareOneMark();

        $this->runBothJobs(LogoutOtherDevicesJob::class);

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
     * Share one mark for the life of the worker instead of the package's scoped
     * binding.
     *
     * @return void
     */
    private function shareOneMark(): void
    {
        $shared = new Rehashing;

        $this->app?->bind(Rehashing::class, static fn (): Rehashing => $shared);
    }

    /**
     * Sign an observed identity in, then queue a job that abandons a `web`
     * attempt for it and the given job, which saves a fresh hash of its current
     * password, and run both through one worker's loop, which forgets scoped
     * instances before each job. The worker has no memory limit: the suite's
     * own process may already use more than a worker's default, which would
     * stop the loop before the first job.
     *
     * @param  class-string<\Tests\Integration\Fixtures\LogoutOtherDevicesJob|\Tests\Integration\Fixtures\SavePasswordJob>  $second
     * @return void
     *
     * @throws \Throwable
     */
    private function runBothJobs(string $second): void
    {
        $identity = $this->seedIdentity();

        self::assertTrue($this->sessions()->signIn('password', self::credentials())->isSignedIn());

        IntegrationIdentity::observe(RevokeDevicesOnPasswordChange::class);

        $hash = $identity->getAuthPassword();

        dispatch(new AbandonedAttemptJob(self::credentials()));
        dispatch(new $second((int) $identity->getKey(), self::PASSWORD)); // @phpstan-ignore cast.int

        $worker = $this->app?->make('queue.worker');

        self::assertInstanceOf(Worker::class, $worker);

        $options = new WorkerOptions(memory: PHP_INT_MAX, sleep: 0, maxTries: 1, stopWhenEmpty: true);

        self::assertSame(Worker::EXIT_SUCCESS, self::keepingSignalHandlers(static fn (): mixed => $worker->daemon('database', 'default', $options)));
        self::assertTrue($this->app?->make('abandoned.attempt'));
        self::assertSame(0, DB::table('jobs')->count());
        self::assertNotSame($hash, $identity->fresh()?->getAuthPassword());
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
