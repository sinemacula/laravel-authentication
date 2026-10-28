<?php

declare(strict_types = 1);

namespace Tests\Integration\Process;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Application;
use Illuminate\Queue\Events\JobProcessing;
use Illuminate\Queue\Worker;
use Illuminate\Queue\WorkerOptions;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\AuthManager;
use SineMacula\Laravel\Authentication\Listeners\ForgetGuardStateBeforeJob;
use Tests\Concerns\InteractsWithSessions;
use Tests\Integration\Fixtures\ObserveGuardJob;
use Tests\Integration\Fixtures\SignInOnGuardJob;
use Tests\TestCase;

/**
 * End-to-end tests for queued jobs run by one worker in one application: a
 * worker forgets only scoped instances between jobs, so without the package's
 * reset a guard one job signed in would still be signed in for the next.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ForgetGuardStateBeforeJob::class)]
#[CoversClass(AuthManager::class)]
final class QueueWorkerGuardStateTest extends TestCase
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
     * Without the reset, the identity the first job signed in is still signed
     * in when the second job runs: the leak the reset closes.
     *
     * @return void
     */
    public function testWithoutTheResetOneJobsIdentityLeaksIntoTheNext(): void
    {
        Event::forget(JobProcessing::class);

        self::assertSame(['identity' => $this->runBothJobs()], $this->app?->make('observed.identity'));
    }

    /**
     * With the reset, each job starts with the package guards signed out.
     *
     * @return void
     */
    public function testEachJobStartsSignedOut(): void
    {
        $this->runBothJobs();

        self::assertSame(['identity' => null], $this->app?->make('observed.identity'));
    }

    /**
     * Configure the guards and a database queue.
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

        $config->set('queue.default', 'database');
        $config->set('queue.connections.database', ['driver' => 'database', 'table' => 'jobs', 'queue' => 'default', 'retry_after' => 90]);
    }

    /**
     * Queue a job that signs an identity in on the `api` guard and then one
     * that records who the guard says is signed in, run both through one
     * worker, and return the identity's key.
     *
     * @return mixed
     */
    private function runBothJobs(): mixed
    {
        $identity = $this->seedIdentity();

        dispatch(new SignInOnGuardJob((int) $identity->getKey())); // @phpstan-ignore cast.int
        dispatch(new ObserveGuardJob);

        $worker = $this->app?->make('queue.worker');

        self::assertInstanceOf(Worker::class, $worker);

        $options = new WorkerOptions(sleep: 0, maxTries: 1);

        $worker->runNextJob('database', 'default', $options);
        $worker->runNextJob('database', 'default', $options);

        return $identity->getKey();
    }
}
