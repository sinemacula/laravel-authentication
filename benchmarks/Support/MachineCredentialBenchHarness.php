<?php

declare(strict_types = 1);

namespace Benchmarks\Support;

use Carbon\Carbon;
use Carbon\CarbonImmutable;
use Firebase\JWT\JWT;
use Illuminate\Container\Container;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Support\Timebox;
use SineMacula\Laravel\Authentication\ApiKeys\ApiKeyService;
use SineMacula\Laravel\Authentication\ClientCredentials\ClientCredentialsExchange;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Guards\ApiKeyGuard;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenService;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenServiceFactory;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenExchange;
use SineMacula\Laravel\Authentication\Providers\ModelProvider;
use SineMacula\Laravel\Authentication\Resolvers\DefaultPrincipalResolver;
use SineMacula\Laravel\Authentication\Sessions\SessionService;
use Tests\Integration\Fixtures\MachineClient;

/**
 * Runtime benchmark fixtures for machine credentials: a request authenticated
 * by the `api_key` guard, and a request bearing an access token a client
 * credentials exchange granted, which the `jwt` guard checks against the API
 * key it names. Both run on the package's own audience policy and scope
 * registry, resolved from the container as in an application.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class MachineCredentialBenchHarness
{
    /** @var string Name of the `api_key` guard. */
    private const string KEY_GUARD = 'machine';

    /** @var string Name of the `jwt` guard client credentials tokens are granted on. */
    private const string TOKEN_GUARD = 'm2m';

    /** @var int Number of never-used keys to pre-issue for the path that records a key's use. */
    private const int KEY_POOL_SIZE = 128;

    /** @var string Path of the requests the benchmarks send. */
    private const string PATH = '/bench/machine';

    /** @var \Illuminate\Foundation\Application */
    private readonly Application $app;

    /** @var \SineMacula\Laravel\Authentication\Providers\ModelProvider */
    private readonly ModelProvider $provider;

    /** @var \SineMacula\Laravel\Authentication\Resolvers\DefaultPrincipalResolver */
    private readonly DefaultPrincipalResolver $resolver;

    /** @var \Illuminate\Contracts\Events\Dispatcher */
    private readonly Dispatcher $events;

    /** @var \SineMacula\Laravel\Authentication\Jwt\JwtTokenService */
    private readonly JwtTokenService $tokens;

    /** @var \Illuminate\Support\Timebox */
    private readonly Timebox $timebox;

    /** @var string A key used within the last-use throttle, so a request records nothing. */
    private string $usedKey = '';

    /** @var string The used key with a secret it was not issued with. */
    private string $refusedKey = '';

    /** @var list<string> Keys never used, each recording its first use. */
    private array $unusedKeys = [];

    /** @var int Current index into the never-used key pool. */
    private int $unusedIndex = 0;

    /** @var string A never-used key outside the pool, for the set-up check. */
    private string $unusedCheckKey = '';

    /** @var string An access token granted by the client credentials exchange. */
    private string $clientToken = '';

    /**
     * Seed the machine credential fixtures, and check that each path reaches
     * the outcome it measures.
     *
     * @throws \LogicException
     * @throws \Random\RandomException
     */
    public function __construct()
    {
        $now = Carbon::createStrict(2026, 4, 10, 12, 0, 0);

        Carbon::setTestNow($now);
        CarbonImmutable::setTestNow(CarbonImmutable::instance($now));
        JWT::$timestamp = $now->getTimestamp();

        $this->app = PackageBenchApplication::create([
            self::KEY_GUARD   => ['driver' => 'api_key', 'provider' => 'machines', 'audience' => ['methods' => ['api_key']]],
            self::TOKEN_GUARD => ['driver' => 'jwt', 'provider' => 'machines', 'audience' => ['methods' => ['client_credentials']]],
        ]);

        $this->provider = new ModelProvider($this->app->make('hash'), MachineClient::class);
        $this->resolver = new DefaultPrincipalResolver;
        $this->events   = $this->app->make('events');
        $this->tokens   = $this->app->make(JwtTokenServiceFactory::class)->forGuard(self::TOKEN_GUARD);
        $this->timebox  = new Timebox;

        BenchSchema::ensureMachineClientTable();
        BenchSchema::ensureApiKeyTable();
        BenchSchema::ensureDeviceTable();

        $this->seedFixtures();
        $this->assertEachPathReachesItsOutcome();
    }

    /**
     * Benchmark an `api_key` request whose key was used within the throttle.
     *
     * @return void
     */
    public function runUsedKey(): void
    {
        $this->keyGuard($this->usedKey)->user();
    }

    /**
     * Benchmark an `api_key` request whose key records its first use.
     *
     * @return void
     *
     * @throws \LogicException
     */
    public function runUnusedKey(): void
    {
        $key = BenchOutcome::take('unused key', $this->unusedKeys, $this->unusedIndex++);

        $this->keyGuard($key)->user();
    }

    /**
     * Benchmark an `api_key` request whose key's secret is wrong.
     *
     * @return void
     */
    public function runRefusedKey(): void
    {
        $this->keyGuard($this->refusedKey)->user();
    }

    /**
     * Benchmark a `jwt` request bearing a client credentials token, which the
     * guard verifies and checks against the API key it names.
     *
     * @return void
     */
    public function runClientCredentialsBearer(): void
    {
        $this->tokenGuard($this->clientToken)->user();
    }

    /**
     * Seed a machine, issue it keys on both guards, use one key, and exchange
     * another for an access token.
     *
     * @return void
     *
     * @throws \LogicException
     * @throws \Random\RandomException
     */
    private function seedFixtures(): void
    {
        $machine = MachineClient::query()->firstOrCreate(['email' => 'bench-machine@example.test'], ['is_active' => true]);
        $keys    = new ApiKeyService($this->keyGuard(null), $this->app);

        $this->usedKey = $keys->issue($machine, $machine, ['reports'])->key();

        $this->keyGuard($this->usedKey)->user();

        $this->refusedKey = substr($this->usedKey, 0, -1) . (str_ends_with($this->usedKey, 'A') ? 'B' : 'A');

        for ($index = 0; $index < self::KEY_POOL_SIZE; $index++) {
            $this->unusedKeys[] = $keys->issue($machine, $machine, ['reports'])->key();
        }

        $this->unusedCheckKey = $keys->issue($machine, $machine, ['reports'])->key();

        $client = (new ApiKeyService($this->tokenGuard(null), $this->app))->issue($machine, $machine, ['reports'])->key();

        [$clientId, $clientSecret] = self::clientCredentialsOf($client);

        $granted = (new ClientCredentialsExchange($this->tokenGuard(null), $this->app))->exchange($clientId, $clientSecret);

        $this->clientToken = $granted->accessToken ?? '';
    }

    /**
     * Run each benchmarked path once and throw unless it reaches the outcome
     * its name describes: a used key authenticates and records nothing, a
     * never-used key authenticates and records its use, a wrong secret is
     * refused as an invalid credential, and a client credentials token binds
     * its machine with the token's scopes.
     *
     * @return void
     *
     * @throws \LogicException
     */
    private function assertEachPathReachesItsOutcome(): void
    {
        foreach (['used key' => [$this->usedKey, false], 'unused key' => [$this->unusedCheckKey, true]] as $path => [$key, $writes]) {

            $bound      = false;
            $statements = BenchOutcome::statementsOf(function () use ($key, &$bound): void {
                $bound = $this->keyGuard($key)->user() !== null;
            });

            $wrote = array_filter($statements, static fn (string $statement): bool => str_starts_with($statement, 'update')) !== [];

            BenchOutcome::assert($path, $bound && $wrote === $writes);
        }

        $reasons = [];

        $this->events->listen(AuthenticationFailed::class, static function (AuthenticationFailed $failed) use (&$reasons): void {
            $reasons[] = $failed->reason;
        });

        BenchOutcome::assert('refused key', $this->keyGuard($this->refusedKey)->user() === null);

        $this->events->forget(AuthenticationFailed::class);

        BenchOutcome::assert('refused key', $reasons === [FailureReason::CREDENTIAL_INVALID]);
        BenchOutcome::assert('client credentials bearer', $this->tokenGuard($this->clientToken)->scopes() === ['reports']);
    }

    /**
     * The OAuth client id and secret of an API key,
     * `<prefix>_<public>_<secret>`: its public part and its secret.
     *
     * @param  string  $key
     * @return array{0: string, 1: string}
     *
     * @throws \LogicException
     */
    private static function clientCredentialsOf(#[\SensitiveParameter] string $key): array
    {
        $separator = strrpos($key, '_');

        if ($separator === false) {
            throw new \LogicException('An issued API key has no secret.');
        }

        return [substr($key, 0, $separator), substr($key, $separator + 1)];
    }

    /**
     * A fresh `api_key` guard serving a request with the key, or none.
     *
     * @param  ?string  $key
     * @return \SineMacula\Laravel\Authentication\Guards\ApiKeyGuard
     */
    private function keyGuard(#[\SensitiveParameter] ?string $key): ApiKeyGuard
    {
        return new ApiKeyGuard(self::KEY_GUARD, $this->provider, $this->resolver, $this->events, self::request($key), $this->timebox);
    }

    /**
     * A fresh `jwt` guard for client credentials, serving a request with the
     * token, or none.
     *
     * @param  ?string  $token
     * @return \SineMacula\Laravel\Authentication\Guards\JwtGuard
     */
    private function tokenGuard(#[\SensitiveParameter] ?string $token): JwtGuard
    {
        $exchange = new RefreshTokenExchange(
            $this->tokens,
            $this->provider,
            BenchDatabase::connectionResolver(),
            static fn (): null => null,
            $this->events,
            $this->resolver,
            self::TOKEN_GUARD,
        );

        return new JwtGuard(
            self::TOKEN_GUARD,
            $this->provider,
            $this->resolver,
            $this->events,
            self::request($token),
            $this->timebox,
            $this->tokens,
            $exchange,
            fn (JwtGuard $guard, \Closure $timebox): SessionService => new SessionService(
                $guard,
                $timebox,
                $this->tokens,
                Container::getInstance(),
                BenchDatabase::connectionResolver(),
                static fn (): null => null,
            ),
            BenchRequest::refreshTransport(...),
        );
    }

    /**
     * A request from the benchmark's client, bearing the credential or none.
     *
     * @param  ?string  $bearer
     * @return \Illuminate\Http\Request
     */
    private static function request(#[\SensitiveParameter] ?string $bearer): Request
    {
        $request = BenchRequest::client()->duplicate(server: ['REQUEST_URI' => self::PATH]);

        if ($bearer !== null) {
            $request->headers->set('Authorization', 'Bearer ' . $bearer);
        }

        return $request;
    }
}
