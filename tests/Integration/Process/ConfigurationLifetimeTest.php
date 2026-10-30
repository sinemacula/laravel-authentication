<?php

declare(strict_types = 1);

namespace Tests\Integration\Process;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Application;
use Illuminate\Queue\Worker;
use Illuminate\Queue\WorkerOptions;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Audience\GuardAudiencePolicy;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenServiceFactory;
use Tests\Concerns\InteractsWithSessions;
use Tests\Integration\Fixtures\ObserveConfigurationJob;
use Tests\TestCase;

/**
 * End-to-end tests of the configuration lifetimes the operations guide
 * documents, across two jobs one queue worker runs: a setting read on every use
 * follows a change made between them, while the token service the factory built
 * for the first job, and the guard itself, serve the second.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(JwtTokenServiceFactory::class)]
#[CoversClass(GuardAudiencePolicy::class)]
final class ConfigurationLifetimeTest extends TestCase
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
     * A change between two jobs reaches the audience, which is read on every
     * use, but not the token lifetimes, which the token service built for the
     * first job keeps, nor the guard, which the worker resets rather than
     * rebuilds.
     *
     * @return void
     */
    public function testOnlyTheSettingsReadOnEveryUseFollowAChangeBetweenJobs(): void
    {
        $observed = $this->runTwoJobs(static function (): void {
            config()->set('authentication.jwt.access_ttl_minutes', 15);
            config()->set('auth.guards.api.audience.methods', ['sso']);
        });

        self::assertSame(5, $observed[0]['access_ttl_minutes']);
        self::assertSame(5, $observed[1]['access_ttl_minutes']);
        self::assertTrue($observed[0]['allows_password']);
        self::assertFalse($observed[1]['allows_password']);
        self::assertSame($observed[0]['guard'], $observed[1]['guard']);
    }

    /**
     * A token service factory built after the change, as a restarted worker
     * builds one, reads the new lifetimes.
     *
     * @return void
     */
    public function testAFreshFactoryReadsTheChangedLifetimes(): void
    {
        $this->runTwoJobs(static function (): void {
            config()->set('authentication.jwt.access_ttl_minutes', 15);
        });

        $app = $this->app;

        self::assertInstanceOf(Application::class, $app);

        $fresh = new JwtTokenServiceFactory($app, $app->make(ConfigRepository::class));

        self::assertSame(15, $fresh->forGuard('api')->lifetimes()->accessTtlMinutes);
    }

    /**
     * Configure the guards, the shipped access lifetime and a database queue.
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

        $config->set('authentication.jwt.access_ttl_minutes', 5);
        $config->set('queue.default', 'database');
        $config->set('queue.connections.database', ['driver' => 'database', 'table' => 'jobs', 'queue' => 'default', 'retry_after' => 90]);
    }

    /**
     * Queue two observing jobs, run them through one worker with the change
     * made between them, and return what each observed.
     *
     * @param  \Closure(): void  $change
     * @return list<array{access_ttl_minutes: int, allows_password: bool, guard: int}>
     */
    private function runTwoJobs(\Closure $change): array
    {
        dispatch(new ObserveConfigurationJob);
        dispatch(new ObserveConfigurationJob);

        $worker = $this->app?->make('queue.worker');

        self::assertInstanceOf(Worker::class, $worker);

        $options = new WorkerOptions(sleep: 0, maxTries: 1);

        $worker->runNextJob('database', 'default', $options);
        $change();
        $worker->runNextJob('database', 'default', $options);

        $observed = $this->app?->make('observed.configuration');

        self::assertIsArray($observed);
        self::assertCount(2, $observed);

        /** @var list<array{access_ttl_minutes: int, allows_password: bool, guard: int}> $observed */
        return $observed;
    }
}
