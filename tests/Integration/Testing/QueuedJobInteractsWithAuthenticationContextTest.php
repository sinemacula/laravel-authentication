<?php

declare(strict_types = 1);

namespace Tests\Integration\Testing;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Application;
use Illuminate\Queue\Worker;
use Illuminate\Queue\WorkerOptions;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Testing\Concerns\InteractsWithAuthenticationContext;
use Tests\Concerns\InteractsWithSessions;
use Tests\Integration\Fixtures\ObserveGuardJob;
use Tests\TestCase;

/**
 * Integration tests for the testing helpers around a queued job a worker runs
 * against the database queue: the job starts signed out, as in production, and
 * the request the test sends after it is acted as again.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversTrait(InteractsWithAuthenticationContext::class)]
final class QueuedJobInteractsWithAuthenticationContextTest extends TestCase
{
    use InteractsWithAuthenticationContext, InteractsWithSessions;

    /**
     * Create the tables, the queue's included, and a route behind `auth:api`.
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

        Route::middleware('auth:api')->get('/me', static fn (): array => ['identity' => Auth::id()]);
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
     * Request, job, request: the job a worker runs between two requests starts
     * signed out, and both requests are authenticated as the identity acted as.
     *
     * @return void
     */
    public function testAJobBetweenRequestsStartsSignedOutAndTheNextRequestActsAgain(): void
    {
        $ada = $this->seedIdentity();

        $this->actingAsIdentity($ada, guard: 'api');

        $this->getJson('/me')->assertOk()->assertExactJson(['identity' => $ada->getKey()]);

        dispatch(new ObserveGuardJob);

        $worker = $this->app?->make('queue.worker');

        self::assertInstanceOf(Worker::class, $worker);

        $worker->runNextJob('database', 'default', new WorkerOptions(sleep: 0, maxTries: 1));

        self::assertSame(['identity' => null], $this->app?->make('observed.identity'));

        $this->getJson('/me')->assertOk()->assertExactJson(['identity' => $ada->getKey()]);
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
}
