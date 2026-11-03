<?php

declare(strict_types = 1);

namespace Benchmarks\Support;

use Carbon\Carbon;
use Firebase\JWT\JWT;
use Illuminate\Container\Container;
use Illuminate\Contracts\Events\Dispatcher as DispatcherContract;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Events\Dispatcher;
use Illuminate\Hashing\BcryptHasher;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Facade;
use Illuminate\Support\Timebox;
use SineMacula\Laravel\Authentication\Events\SessionAuthenticated;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Jwt\JwtKeyring;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenService;
use SineMacula\Laravel\Authentication\Jwt\TokenLifetimes;
use SineMacula\Laravel\Authentication\Listeners\RecordSessionUsage;
use SineMacula\Laravel\Authentication\Models\Session;
use SineMacula\Laravel\Authentication\Providers\ModelProvider;
use SineMacula\Laravel\Authentication\Resolvers\DefaultPrincipalResolver;
use SineMacula\Laravel\Authentication\Runtime\GuardContext;
use SineMacula\Laravel\Authentication\Sessions\RevocationWriter;
use SineMacula\Laravel\Authentication\Sessions\SessionRevocations;
use Tests\Integration\Fixtures\Coexist2dIdentity;
use Tests\Integration\Fixtures\Coexist3dIdentity;
use Tests\Integration\Fixtures\Coexist3dPrincipal;
use Tests\Integration\Fixtures\IntegrationIdentity;
use Tests\Integration\Fixtures\TenantAware3dIdentity;
use Tests\Performance\Fixtures\PerformanceAccessOnlyIdentity;

/**
 * Runtime benchmark fixtures for JwtGuard bearer-auth hot paths.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class JwtGuardBenchHarness
{
    /** @var string HS256 signing secret for benchmark tokens. */
    private const string SECRET = 'benchmark-secret-key-with-at-least-32-bytes!';

    /** @var string Shared benchmark password. */
    private const string PASSWORD = 'correct horse battery staple';

    /** @var string Access-only 2D identity email. */
    private const string ACCESS_ONLY_EMAIL = 'bench-access-only@example.test';

    /** @var string Coexistence 2D identity email. */
    private const string COEXIST_TWO_D_EMAIL = 'bench-coexist-2d@example.test';

    /** @var string Session-bearing identity email. */
    private const string SESSION_EMAIL = 'bench-session@example.test';

    /** @var string 3D identity email. */
    private const string THREE_D_EMAIL = 'bench-3d@example.test';

    /** @var string Tenant-aware 3D identity email. */
    private const string TENANT_THREE_D_EMAIL = 'bench-tenant-3d@example.test';

    /** @var int Number of mutable write-path tokens to pre-seed. */
    private const int TOKEN_POOL_SIZE = 128;

    /** @var string Path of the requests the set-up check sends. */
    private const string CHECK_PATH = '/bench/check';

    /** @var \SineMacula\Laravel\Authentication\Jwt\JwtTokenService */
    private readonly JwtTokenService $tokens;

    /** @var \SineMacula\Laravel\Authentication\Providers\ModelProvider */
    private readonly ModelProvider $accessOnlyProvider;

    /** @var \SineMacula\Laravel\Authentication\Providers\ModelProvider */
    private readonly ModelProvider $coexistTwoDProvider;

    /** @var \SineMacula\Laravel\Authentication\Providers\ModelProvider */
    private readonly ModelProvider $sessionProvider;

    /** @var \SineMacula\Laravel\Authentication\Providers\ModelProvider */
    private readonly ModelProvider $threeDProvider;

    /** @var \SineMacula\Laravel\Authentication\Providers\ModelProvider */
    private readonly ModelProvider $tenantAwareThreeDProvider;

    /** @var \SineMacula\Laravel\Authentication\Resolvers\DefaultPrincipalResolver */
    private readonly DefaultPrincipalResolver $resolver;

    /** @var \Illuminate\Contracts\Events\Dispatcher */
    private readonly DispatcherContract $events;

    /** @var \Illuminate\Support\Timebox */
    private readonly Timebox $timebox;

    /** @var string 2D access-only bearer token. */
    private string $accessOnlyToken;

    /** @var string Coexist 2D bearer token. */
    private string $coexistTwoDToken;

    /** @var string Session bearer with fresh timestamp; empty until seeded, which the set-up check refuses. */
    private string $sessionFreshToken = '';

    /** @var string 3D bearer token. */
    private string $threeDToken;

    /** @var string Tenant-aware 3D bearer token. */
    private string $tenantAwareThreeDToken;

    /** @var string Tenant-aware secondary bearer token. */
    private string $tenantAwareSecondaryToken;

    /** @var list<string> */
    private array $sessionWriteTokens = [];

    /** @var string Session bearer token, outside the write pool, whose session has never been used, for the set-up check. */
    private string $sessionWriteCheckToken = '';

    /** @var int Current index into the write-token pool. */
    private int $sessionWriteIndex = 0;

    /**
     * Seed the bearer-auth benchmark fixtures, and check that each path reaches
     * the outcome it measures.
     *
     * @throws \LogicException
     * @throws \Random\RandomException
     */
    public function __construct()
    {
        BenchDatabase::boot();

        $now = Carbon::createStrict(2026, 4, 10, 12, 0, 0);
        Carbon::setTestNow($now);
        JWT::$timestamp = $now->getTimestamp();

        $config = JwtBenchSetup::config();

        $container = new Container;
        $container->instance('config', $config);
        Facade::setFacadeApplication($container);
        JwtBenchSetup::bindPackageDefaults($container);

        $this->resolver = new DefaultPrincipalResolver;
        $this->events   = new Dispatcher($container);
        $this->events->setTransactionManagerResolver(static fn (): null => null);
        $this->events->listen(
            SessionAuthenticated::class,
            new RecordSessionUsage,
        );

        $hasher = new BcryptHasher;

        $this->tokens = new JwtTokenService(
            JwtKeyring::fromKeyMap(['bench' => self::SECRET], 'bench', 'HS256'),
            'api',
            new TokenLifetimes(15, 60 * 24 * 30, 60 * 24 * 180, 30),
            30,
            'https://issuer.example.test',
            'https://api.example.test',
        );
        $this->timebox = new Timebox;

        $this->accessOnlyProvider        = new ModelProvider($hasher, PerformanceAccessOnlyIdentity::class);
        $this->coexistTwoDProvider       = new ModelProvider($hasher, Coexist2dIdentity::class);
        $this->sessionProvider           = new ModelProvider($hasher, IntegrationIdentity::class);
        $this->threeDProvider            = new ModelProvider($hasher, Coexist3dIdentity::class);
        $this->tenantAwareThreeDProvider = new ModelProvider($hasher, TenantAware3dIdentity::class);

        $this->createSchema();
        $this->seedAccessOnlyFixture($hasher);
        $this->seedCoexistenceTwoDimensionalFixture($hasher);
        $this->seedSessionFixtures($hasher);
        $this->seedThreeDimensionalFixtures($hasher);
        $this->seedTenantAwareThreeDimensionalFixtures($hasher);

        $this->assertEachPathReachesItsOutcome();
    }

    /**
     * Benchmark the 2D bearer path with no session hint.
     *
     * @return void
     */
    public function runAccessOnlyBearer(): void
    {
        $this->bearer('access_only', $this->accessOnlyProvider, '/bench/jwt/access-only', $this->accessOnlyToken);
    }

    /**
     * Benchmark the session-bearing bearer path when the listener should skip
     * the debounced timestamp write.
     *
     * @return void
     */
    public function runSessionBearerNoWrite(): void
    {
        $this->bearer('session_api', $this->sessionProvider, '/bench/jwt/session-fresh', $this->sessionFreshToken);
    }

    /**
     * Benchmark the session-bearing bearer path when the listener must persist
     * `last_used_at`.
     *
     * @return void
     */
    public function runSessionBearerWithWrite(): void
    {
        $token = $this->sessionWriteTokens[$this->sessionWriteIndex % count($this->sessionWriteTokens)];
        $this->sessionWriteIndex++;

        $this->bearer('session_api', $this->sessionProvider, '/bench/jwt/session-write', $token);
    }

    /**
     * Benchmark the 3D principal-resolution bearer path.
     *
     * @return void
     */
    public function runThreeDimensionalBearer(): void
    {
        $this->bearer('api_3d', $this->threeDProvider, '/bench/jwt/3d', $this->threeDToken);
    }

    /**
     * Benchmark the tenant-aware 3D bearer path including tenant access.
     *
     * @return void
     */
    public function runThreeDimensionalBearerTenantAccess(): void
    {
        $guard = $this->bearer('tenant_api_3d', $this->tenantAwareThreeDProvider, '/bench/jwt/tenant-3d', $this->tenantAwareThreeDToken);

        $guard->principal()?->getIdentity();
        $guard->tenant();
    }

    /**
     * Benchmark the tenant-aware 3D bearer path for a non-default tenant hint.
     *
     * @return void
     */
    public function runThreeDimensionalBearerSecondaryTenantAccess(): void
    {
        $guard = $this->bearer('tenant_api_3d', $this->tenantAwareThreeDProvider, '/bench/jwt/tenant-3d-secondary', $this->tenantAwareSecondaryToken);

        $guard->principal()?->getIdentity();
        $guard->tenant();
    }

    /**
     * Benchmark sequential authentication through distinct 2D and 3D guards.
     *
     * @return void
     */
    public function runGuardCoexistenceBearer(): void
    {
        $this->bearer('api_2d', $this->coexistTwoDProvider, '/bench/jwt/coexist-2d', $this->coexistTwoDToken)->principal(); // @phpstan-ignore method.resultUnused
        $this->bearer('api_3d', $this->threeDProvider, '/bench/jwt/coexist-3d', $this->threeDToken)->principal(); // @phpstan-ignore method.resultUnused
    }

    /**
     * Create the benchmark schema when missing.
     *
     * @return void
     */
    private function createSchema(): void
    {
        BenchSchema::ensureAccessOnlyIdentityTable();

        foreach (['integration_identities', 'coexist_2d_identities', 'coexist_3d_identities', 'tenant_aware_3d_identities'] as $table) {
            BenchSchema::ensureIdentityTable($table);
        }

        BenchSchema::ensureCoexistPrincipalTable();
        BenchSchema::ensureTenantTables();
        BenchSchema::ensureSessionTable();
        BenchSchema::ensureProofTables();
    }

    /**
     * Seed the no-session 2D bearer fixture.
     *
     * @param  \Illuminate\Contracts\Hashing\Hasher  $hasher
     * @return void
     *
     * @throws \Random\RandomException
     */
    private function seedAccessOnlyFixture(Hasher $hasher): void
    {
        $identity = PerformanceAccessOnlyIdentity::query()->first();

        if (!$identity instanceof PerformanceAccessOnlyIdentity) {

            $identity = new PerformanceAccessOnlyIdentity;
            $identity->forceFill([
                'email'    => self::ACCESS_ONLY_EMAIL,
                'password' => $hasher->make(self::PASSWORD),
            ]);
            $identity->save();
        }

        $this->accessOnlyToken = $this->tokens->issueAccessToken($identity, $identity, null, null)->reveal();
    }

    /**
     * Seed the 2D coexistence bearer fixture.
     *
     * @param  \Illuminate\Contracts\Hashing\Hasher  $hasher
     * @return void
     *
     * @throws \Random\RandomException
     */
    private function seedCoexistenceTwoDimensionalFixture(Hasher $hasher): void
    {
        $identity = Coexist2dIdentity::query()->first();

        if (!$identity instanceof Coexist2dIdentity) {

            $identity = new Coexist2dIdentity;
            $identity->forceFill([
                'email'     => self::COEXIST_TWO_D_EMAIL,
                'password'  => $hasher->make(self::PASSWORD),
                'is_active' => true,
            ]);
            $identity->save();
        }

        $this->coexistTwoDToken = $this->tokens->issueAccessToken($identity, $identity, null, null)->reveal();
    }

    /**
     * Seed the session-backed bearer fixtures.
     *
     * @param  \Illuminate\Contracts\Hashing\Hasher  $hasher
     * @return void
     *
     * @throws \Random\RandomException
     */
    private function seedSessionFixtures(Hasher $hasher): void
    {
        $identity = IntegrationIdentity::query()->first();

        if (!$identity instanceof IntegrationIdentity) {

            $identity            = new IntegrationIdentity;
            $identity->email     = self::SESSION_EMAIL;
            $identity->password  = $hasher->make(self::PASSWORD);
            $identity->is_active = true;
            $identity->save();
        }

        $freshSession = Session::query()->where('client_name', 'bench-session-fresh')->first();
        $freshSession = $freshSession instanceof Session ? $freshSession : $this->seedSession($identity, 'bench-session-fresh', Carbon::now());

        $this->sessionFreshToken = $this->tokens->issueAccessToken($identity, $identity, null, $freshSession)->reveal();

        if ($this->sessionWriteTokens !== []) {
            return;
        }

        $this->sessionWriteCheckToken = $this->tokens->issueAccessToken($identity, $identity, null, $this->seedSession($identity, 'bench-session-write-check', null))->reveal();

        for ($index = 0; $index < self::TOKEN_POOL_SIZE; $index++) {
            $this->sessionWriteTokens[] = $this->tokens->issueAccessToken(
                $identity,
                $identity,
                null,
                $this->seedSession($identity, 'bench-session-write-' . $index, null),
            )->reveal();
        }
    }

    /**
     * Save a session the identity's password sign-in on `session_api` started
     * now, with the first-factor proof that sign-in records.
     *
     * @param  \Tests\Integration\Fixtures\IntegrationIdentity  $identity
     * @param  string  $clientName
     * @param  ?\Carbon\Carbon  $lastUsedAt
     * @return \SineMacula\Laravel\Authentication\Models\Session
     *
     * @throws \LogicException
     */
    private function seedSession(IntegrationIdentity $identity, string $clientName, ?Carbon $lastUsedAt): Session
    {
        /** @var string $identityId */
        $identityId = $identity->getKey();

        $session = new Session;
        $session->forceFill([
            ...BenchSchema::signedIn('session_api'),
            'authenticatable_type' => IntegrationIdentity::class,
            'authenticatable_id'   => $identityId,
            'principal_type'       => $identity->getMorphClass(),
            'principal_id'         => $identityId,
            'client_name'          => $clientName,
            'last_used_at'         => $lastUsedAt,
        ])->save();

        BenchSchema::recordFirstFactor($session);

        return $session;
    }

    /**
     * Seed the 3D bearer fixture.
     *
     * @param  \Illuminate\Contracts\Hashing\Hasher  $hasher
     * @return void
     *
     * @throws \Random\RandomException
     */
    private function seedThreeDimensionalFixtures(Hasher $hasher): void
    {
        $identity = Coexist3dIdentity::query()->first();

        if (!$identity instanceof Coexist3dIdentity) {

            $identity            = new Coexist3dIdentity;
            $identity->email     = self::THREE_D_EMAIL;
            $identity->password  = $hasher->make(self::PASSWORD);
            $identity->is_active = true;
            $identity->save();
        }

        $principal = Coexist3dPrincipal::query()->where('identity_id', $identity->getKey())->first();

        if (!$principal instanceof Coexist3dPrincipal) {

            /** @var int $identityKey */
            $identityKey = $identity->getKey();

            $principal              = new Coexist3dPrincipal;
            $principal->identity_id = $identityKey;
            $principal->name        = 'bench-3d-principal';
            $principal->is_active   = true;
            $principal->save();
        }

        $this->threeDToken = $this->tokens->issueAccessToken($identity, $principal, null, null)->reveal();
    }

    /**
     * Seed the tenant-aware 3D bearer fixture.
     *
     * @param  \Illuminate\Contracts\Hashing\Hasher  $hasher
     * @return void
     *
     * @throws \Random\RandomException
     */
    private function seedTenantAwareThreeDimensionalFixtures(Hasher $hasher): void
    {
        $identity = TenantAware3dIdentity::query()->first();

        if (!$identity instanceof TenantAware3dIdentity) {

            $identity            = new TenantAware3dIdentity;
            $identity->email     = self::TENANT_THREE_D_EMAIL;
            $identity->password  = $hasher->make(self::PASSWORD);
            $identity->is_active = true;
            $identity->save();
        }

        $principal = TenantFixtures::seedTenantPrincipal(
            $identity,
            TenantFixtures::seedTenant('Bench Tenant Staff', 'staff'),
            'bench-tenant-3d-principal',
        );

        $secondaryPrincipal = TenantFixtures::seedTenantPrincipal(
            $identity,
            TenantFixtures::seedTenant('Bench Tenant Customer', 'customer'),
            'bench-tenant-3d-secondary-principal',
        );

        $this->tenantAwareThreeDToken    = $this->tokens->issueAccessToken($identity, $principal, null, null)->reveal();
        $this->tenantAwareSecondaryToken = $this->tokens->issueAccessToken($identity, $secondaryPrincipal, null, null)->reveal();
    }

    /**
     * Run each benchmarked path once and throw unless it reaches the outcome
     * its name describes: every bearer authenticates, a session bearer binds
     * its session, writing its last use only on the path that measures the
     * write, a 3D bearer binds its principal, and a tenant-aware one its
     * tenant. The write path runs on a session row of its own, outside the
     * benchmark's pool.
     *
     * @return void
     *
     * @throws \LogicException
     */
    private function assertEachPathReachesItsOutcome(): void
    {
        BenchOutcome::assert('access-only bearer', $this->bearer('access_only', $this->accessOnlyProvider, self::CHECK_PATH, $this->accessOnlyToken)->hasUser());
        BenchOutcome::assert('2D coexistence bearer', $this->bearer('api_2d', $this->coexistTwoDProvider, self::CHECK_PATH, $this->coexistTwoDToken)->hasUser());
        BenchOutcome::assert('3D bearer', $this->bearer('api_3d', $this->threeDProvider, self::CHECK_PATH, $this->threeDToken)->principal() instanceof Coexist3dPrincipal);

        foreach ([$this->tenantAwareThreeDToken, $this->tenantAwareSecondaryToken] as $token) {
            BenchOutcome::assert('tenant-aware 3D bearer', $this->bearer('tenant_api_3d', $this->tenantAwareThreeDProvider, self::CHECK_PATH, $token)->tenant() !== null);
        }

        $sessionPaths = [
            'session bearer without a write' => [$this->sessionFreshToken, false],
            'session bearer with a write'    => [$this->sessionWriteCheckToken, true],
        ];

        foreach ($sessionPaths as $path => [$token, $writes]) {

            $bound      = false;
            $statements = BenchOutcome::statementsOf(function () use ($token, &$bound): void {
                $bound = $this->bearer('session_api', $this->sessionProvider, self::CHECK_PATH, $token)->session() !== null;
            });

            $wrote = array_filter($statements, static fn (string $statement): bool => str_starts_with($statement, 'update')) !== [];

            BenchOutcome::assert($path, $bound && $wrote === $writes);
        }
    }

    /**
     * Authenticate a bearer request through a fresh guard and return the guard.
     *
     * @param  string  $name
     * @param  \SineMacula\Laravel\Authentication\Providers\ModelProvider  $provider
     * @param  string  $path
     * @param  string  $token
     * @return \SineMacula\Laravel\Authentication\Guards\JwtGuard
     */
    private function bearer(string $name, ModelProvider $provider, string $path, #[\SensitiveParameter] string $token): JwtGuard
    {
        $guard = $this->makeGuard($name, $provider, $this->makeBearerRequest($path, $token));

        $guard->user();

        return $guard;
    }

    /**
     * Instantiate a fresh JwtGuard for the supplied request, held by the auth
     * manager as the guard resolved under its name.
     *
     * @param  string  $name
     * @param  \SineMacula\Laravel\Authentication\Providers\ModelProvider  $provider
     * @param  \Illuminate\Http\Request  $request
     * @return \SineMacula\Laravel\Authentication\Guards\JwtGuard
     */
    private function makeGuard(string $name, ModelProvider $provider, Request $request): JwtGuard
    {
        $guard = new JwtGuard(
            $name,
            $provider,
            $this->resolver,
            $this->events,
            $request,
            $this->timebox,
            $this->tokens,
            static fn (GuardContext $context): SessionRevocations => new SessionRevocations(
                $context,
                new RevocationWriter(BenchDatabase::connectionResolver(), static fn (): null => null),
                new Container,
            ),
            BenchRequest::refreshTransport(...),
        );

        /** @var \Benchmarks\Support\BenchAuthManager $auth */
        $auth = Container::getInstance()->make('auth');

        $auth->hold($guard);

        return $guard;
    }

    /**
     * Build a real Request carrying a bearer token.
     *
     * @param  string  $path
     * @param  string  $token
     * @return \Illuminate\Http\Request
     */
    private function makeBearerRequest(string $path, #[\SensitiveParameter] string $token): Request
    {
        return Request::create($path, 'GET', [], [], [], [
            'HTTP_AUTHORIZATION' => 'Bearer ' . $token,
        ]);
    }
}
