<?php

declare(strict_types = 1);

namespace Benchmarks\Support;

// phpcs:disable Squiz.Commenting.VariableComment.Missing, Squiz.Commenting.FunctionComment.MissingReturn

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Container\Container;
use Illuminate\Contracts\Events\Dispatcher as DispatcherContract;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Events\Dispatcher;
use Illuminate\Hashing\BcryptHasher;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Facade;
use SineMacula\Laravel\Authentication\Guards\BasicGuard;
use SineMacula\Laravel\Authentication\Providers\ModelProvider;
use SineMacula\Laravel\Authentication\Resolvers\DefaultPrincipalResolver;
use Tests\Performance\Fixtures\PerformanceAccessOnlyIdentity;

/**
 * Runtime benchmark fixtures for BasicGuard credential flows.
 */
final class BasicGuardBenchHarness
{
    private const string EMAIL         = 'bench-basic@example.test';
    private const string MISSING_EMAIL = 'missing-basic@example.test';
    private const string PASSWORD      = 'correct horse battery staple';
    private readonly ModelProvider $provider;
    private readonly DefaultPrincipalResolver $resolver;
    private readonly DispatcherContract $events;
    private readonly ImmediateTimebox $timebox;

    /**
     * Seed the BasicGuard benchmark fixtures.
     */
    public function __construct()
    {
        BenchDatabase::boot();

        $config = new ConfigRepository([
            'authentication' => [
                'timebox' => [
                    'credentials_microseconds' => 400000,
                ],
            ],
        ]);

        $container = new Container;
        $container->instance('config', $config);
        Facade::setFacadeApplication($container);

        $this->events = new Dispatcher($container);
        $this->events->setTransactionManagerResolver(static fn (): null => null);
        $this->timebox  = new ImmediateTimebox;
        $this->resolver = new DefaultPrincipalResolver;

        $hasher         = new BcryptHasher;
        $this->provider = new ModelProvider($hasher, PerformanceAccessOnlyIdentity::class);

        $this->createSchema();
        $this->seedFixture($hasher);
    }

    /**
     * Benchmark valid HTTP Basic credentials.
     *
     * @return void
     */
    public function runValidCredentials(): void
    {
        $this->makeGuard($this->makeRequest(self::EMAIL, self::PASSWORD))->user();
    }

    /**
     * Benchmark wrong-password HTTP Basic credentials.
     *
     * @return void
     */
    public function runWrongPassword(): void
    {
        $this->makeGuard($this->makeRequest(self::EMAIL, 'wrong password'))->user();
    }

    /**
     * Benchmark a nonexistent HTTP Basic identifier.
     *
     * @return void
     */
    public function runMissingUser(): void
    {
        $this->makeGuard($this->makeRequest(self::MISSING_EMAIL, self::PASSWORD))->user();
    }

    /**
     * Create the backing table once.
     *
     * @return void
     */
    private function createSchema(): void
    {
        $schema = BenchDatabase::schema();

        if ($schema->hasTable('access_only_identities')) {
            return;
        }

        $schema->create('access_only_identities', static function (Blueprint $blueprint): void {
            $blueprint->id();
            $blueprint->string('email')->unique();
            $blueprint->string('password');
            $blueprint->timestamps();
        });
    }

    /**
     * Seed the single BasicGuard identity fixture.
     *
     * @param  \Illuminate\Contracts\Hashing\Hasher  $hasher
     * @return void
     */
    private function seedFixture(Hasher $hasher): void
    {
        $query = (new PerformanceAccessOnlyIdentity)->newQuery();

        if ($query->where('email', self::EMAIL)->first() !== null) {
            return;
        }

        $identity = new PerformanceAccessOnlyIdentity;
        $identity->forceFill([
            'email'    => self::EMAIL,
            'password' => $hasher->make(self::PASSWORD),
        ]);
        $identity->save();
    }

    /**
     * Instantiate a fresh BasicGuard for the supplied request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \SineMacula\Laravel\Authentication\Guards\BasicGuard
     */
    private function makeGuard(Request $request): BasicGuard
    {
        return new BasicGuard(
            'basic',
            $this->provider,
            $this->resolver,
            $this->events,
            $request,
            $this->timebox,
        );
    }

    /**
     * Build a Request with HTTP Basic credentials.
     *
     * @param  string  $user
     * @param  string  $password
     * @return \Illuminate\Http\Request
     */
    private function makeRequest(string $user, string $password): Request
    {
        return Request::create('/bench/basic', 'GET', [], [], [], [
            'PHP_AUTH_USER' => $user,
            'PHP_AUTH_PW'   => $password,
        ]);
    }
}
