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
use SineMacula\Laravel\Authentication\Listeners\RevokeSessionsOnPasswordChange;
use SineMacula\Laravel\Authentication\Sessions\Methods\Rehashing;
use Tests\Concerns\InteractsWithSessions;
use Tests\Integration\Fixtures\AbandonedAttemptJob;
use Tests\Integration\Fixtures\IntegrationIdentity;
use Tests\Integration\Fixtures\LogoutOtherDevicesJob;
use Tests\Integration\Fixtures\SavePasswordJob;
use Tests\TestCase;

/**
 * End-to-end tests of the rehash mark across queued jobs one worker runs.
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
     * With the mark shared across jobs, a later job's save of a fresh hash
     * still revokes.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASavedPasswordRevokesEvenWithTheMarkShared(): void
    {
        $this->shareOneMark();

        $this->runBothJobs(SavePasswordJob::class);

        self::assertSame($this->app?->make('abandoned.mark'), $this->app?->make(Rehashing::class));
        self::assertSame('password_changed', DB::table('authentication_sessions')->value('revoked_reason'));
    }

    /**
     * With the scoped binding, each job starts with a mark of its own.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testEachJobStartsWithNoMark(): void
    {
        $this->runBothJobs(SavePasswordJob::class);

        self::assertNotSame($this->app?->make('abandoned.mark'), $this->app?->make(Rehashing::class));
        self::assertSame('password_changed', DB::table('authentication_sessions')->value('revoked_reason'));
    }

    /**
     * A later job's `logoutOtherDevices()` revokes even with the mark shared.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testLogoutOtherDevicesRevokesEvenWithTheMarkShared(): void
    {
        $this->shareOneMark();

        $this->runBothJobs(LogoutOtherDevicesJob::class);

        self::assertSame('password_changed', DB::table('authentication_sessions')->value('revoked_reason'));
    }

    /**
     * Configure the guards, Laravel's session guards over the identity model,
     * and a database queue.
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
     * Share one mark for the life of the worker instead of the scoped binding.
     *
     * @return void
     */
    private function shareOneMark(): void
    {
        $shared = new Rehashing;

        $this->app?->bind(Rehashing::class, static fn (): Rehashing => $shared);
    }

    /**
     * Run a job that abandons a `web` attempt and then the given job through
     * one worker's loop.
     *
     * No memory limit, as the suite's process may already exceed the default.
     *
     * @param  class-string<\Tests\Integration\Fixtures\LogoutOtherDevicesJob|\Tests\Integration\Fixtures\SavePasswordJob>  $second
     * @return void
     *
     * @throws \Throwable
     */
    private function runBothJobs(string $second): void
    {
        $identity = $this->seedIdentity();

        self::assertTrue($this->sessions()->signIn('password', self::credentials(), self::requestContext())->isSignedIn());

        IntegrationIdentity::observe(RevokeSessionsOnPasswordChange::class);

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
     * installs.
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
