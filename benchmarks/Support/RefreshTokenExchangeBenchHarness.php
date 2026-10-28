<?php

declare(strict_types = 1);

namespace Benchmarks\Support;

use Carbon\Carbon;
use Firebase\JWT\JWT;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Container\Container;
use Illuminate\Contracts\Events\Dispatcher as DispatcherContract;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Events\Dispatcher;
use Illuminate\Hashing\BcryptHasher;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Facade;
use Illuminate\Support\Timebox;
use SineMacula\Laravel\Authentication\Contracts\AttemptLimiter;
use SineMacula\Laravel\Authentication\Contracts\AudiencePolicy;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\DeviceAuthenticated;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Jwt\JwtKeyring;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenService;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenExchange;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenHasher;
use SineMacula\Laravel\Authentication\Jwt\TokenLifetimes;
use SineMacula\Laravel\Authentication\Listeners\RecordDeviceUsage;
use SineMacula\Laravel\Authentication\Models\Device;
use SineMacula\Laravel\Authentication\Providers\ModelProvider;
use SineMacula\Laravel\Authentication\Resolvers\DefaultPrincipalResolver;
use SineMacula\Laravel\Authentication\Sessions\SessionService;
use Tests\Fixtures\Sessions\PermissiveAudiencePolicy;
use Tests\Fixtures\Sessions\UnlimitedAttemptLimiter;
use Tests\Integration\Fixtures\TenantAware3dIdentity;
use Tests\Integration\Fixtures\TenantAware3dPrincipal;
use Tests\Unit\Stubs\StubPrincipal;

/**
 * Runtime benchmark fixtures for refresh-token exchanges.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class RefreshTokenExchangeBenchHarness
{
    /** @var string HS256 signing secret for benchmark tokens. */
    private const string SECRET = 'benchmark-refresh-secret-key-with-at-least-32-bytes!';

    /** @var string Benchmark identity email. */
    private const string EMAIL = 'bench-refresh@example.test';

    /** @var string Shared benchmark password. */
    private const string PASSWORD = 'correct horse battery staple';

    /** @var int Number of mutable success-path tokens to pre-seed. */
    private const int TOKEN_POOL_SIZE = 128;

    /** @var \SineMacula\Laravel\Authentication\Jwt\JwtTokenService */
    private readonly JwtTokenService $tokens;

    /** @var \SineMacula\Laravel\Authentication\Providers\ModelProvider */
    private readonly ModelProvider $provider;

    /** @var \SineMacula\Laravel\Authentication\Providers\ModelProvider */
    private readonly ModelProvider $tenantAwareProvider;

    /** @var \SineMacula\Laravel\Authentication\Resolvers\DefaultPrincipalResolver */
    private readonly DefaultPrincipalResolver $resolver;

    /** @var \Illuminate\Contracts\Events\Dispatcher */
    private readonly DispatcherContract $events;

    /** @var \Illuminate\Support\Timebox */
    private readonly Timebox $timebox;

    /** @var string Token targeting a nonexistent device; empty until seeded, which the set-up check refuses. */
    private string $unknownDeviceToken = '';

    /** @var list<string> Tokens with a mismatched rotation ID, each for its own device, since the first replay revokes it. */
    private array $rotationMismatchTokens = [];

    /** @var int Current index into the mismatch pool. */
    private int $rotationMismatchIndex = 0;

    /** @var string Success token outside the pool, for the set-up check; empty until seeded, which the check refuses. */
    private string $successCheckToken = '';

    /** @var string Tenant-aware success token outside the pool, for the set-up check. */
    private string $tenantAwareCheckToken = '';

    /** @var string Secondary tenant success token outside the pool, for the set-up check. */
    private string $tenantAwareSecondaryCheckToken = '';

    /** @var string Mismatched token outside the pool, for the set-up check. */
    private string $rotationMismatchCheckToken = '';

    /** @var list<string> */
    private array $successTokens = [];

    /** @var int Current index into the success-token pool. */
    private int $successIndex = 0;

    /** @var list<string> */
    private array $tenantAwareSuccessTokens = [];

    /** @var int Current index into the tenant pool. */
    private int $tenantAwareSuccessIndex = 0;

    /** @var list<string> */
    private array $tenantAwareSecondarySuccessTokens = [];

    /** @var int Current index into the secondary pool. */
    private int $tenantAwareSecondarySuccessIndex = 0;

    /**
     * Seed the refresh benchmark fixtures, and check that each path reaches the
     * outcome it measures.
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

        $config = new ConfigRepository([
            'authentication' => [
                'device' => [
                    'model'                      => Device::class,
                    'table'                      => 'devices',
                    'last_used_throttle_seconds' => 60,
                ],
                'timebox' => [
                    'credentials_microseconds' => 400000,
                ],
            ],
        ]);

        $container = new Container;
        $container->instance('config', $config);
        Facade::setFacadeApplication($container);
        Container::setInstance($container);

        $this->resolver = new DefaultPrincipalResolver;
        $this->events   = new Dispatcher($container);
        $this->events->setTransactionManagerResolver(static fn (): null => null);
        $this->events->listen(
            DeviceAuthenticated::class,
            new RecordDeviceUsage,
        );

        $hasher = new BcryptHasher;

        $this->tokens = new JwtTokenService(
            JwtKeyring::fromKeyMap(['bench' => self::SECRET], 'bench', 'HS256'),
            'api',
            new TokenLifetimes(15, 60 * 24 * 30, 60 * 24 * 180, 30),
            30,
        );
        $container->instance(AudiencePolicy::class, new PermissiveAudiencePolicy($this->tokens->lifetimes()));
        $container->instance(AttemptLimiter::class, new UnlimitedAttemptLimiter);

        $this->provider            = new ModelProvider($hasher, StubPrincipal::class);
        $this->tenantAwareProvider = new ModelProvider($hasher, TenantAware3dIdentity::class);
        $this->timebox             = new Timebox;

        $this->createSchema();
        $this->seedFixtures($hasher);

        $this->assertEachPathReachesItsOutcome();
    }

    /**
     * Benchmark refresh success.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function runRefreshSuccess(): void
    {
        $token = $this->successTokens[$this->successIndex % count($this->successTokens)];
        $this->successIndex++;

        $this->makeGuard()->refresh($token);
    }

    /**
     * Benchmark the unknown-device failure path.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function runUnknownDeviceFailure(): void
    {
        $this->makeGuard()->refresh($this->unknownDeviceToken);
    }

    /**
     * Benchmark the rotation-mismatch failure path.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function runRotationMismatchFailure(): void
    {
        $token = $this->rotationMismatchTokens[$this->rotationMismatchIndex % count($this->rotationMismatchTokens)];
        $this->rotationMismatchIndex++;

        $this->makeGuard()->refresh($token);
    }

    /**
     * Benchmark tenant-aware 3D refresh success including tenant access.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function runThreeDimensionalRefreshTenantAccess(): void
    {
        $token = $this->tenantAwareSuccessTokens[$this->tenantAwareSuccessIndex % count($this->tenantAwareSuccessTokens)];
        $this->tenantAwareSuccessIndex++;

        $guard = $this->makeGuard($this->tenantAwareProvider);

        $guard->refresh($token);
        $guard->principal()?->getIdentity();
        $guard->tenant();
        $guard->type();
    }

    /**
     * Benchmark tenant-aware 3D refresh success for a secondary tenant hint.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function runThreeDimensionalRefreshSecondaryTenantAccess(): void
    {
        $token = $this->tenantAwareSecondarySuccessTokens[$this->tenantAwareSecondarySuccessIndex % count($this->tenantAwareSecondarySuccessTokens)];
        $this->tenantAwareSecondarySuccessIndex++;

        $guard = $this->makeGuard($this->tenantAwareProvider);

        $guard->refresh($token);
        $guard->principal()?->getIdentity();
        $guard->tenant();
        $guard->type();
    }

    /**
     * Create the shared tables once.
     *
     * @return void
     */
    private function createSchema(): void
    {
        BenchSchema::ensureIdentityTable('stub_principals');
        BenchSchema::ensureIdentityTable('tenant_aware_3d_identities');
        BenchSchema::ensureDeviceTable();
        BenchSchema::ensureTenantTables();
    }

    /**
     * Seed success and failure fixtures.
     *
     * @param  \Illuminate\Contracts\Hashing\Hasher  $hasher
     * @return void
     */
    private function seedFixtures(Hasher $hasher): void
    {
        $identity = $this->findOrCreatePrimaryIdentity($hasher);
        $this->seedSuccessTokens($identity);

        [$tenantAwareIdentity, $tenantAwarePrincipal, $secondaryPrincipal] = $this->seedTenantAwareFixtures($hasher);
        $this->seedTenantAwareSuccessTokens($tenantAwareIdentity, $tenantAwarePrincipal, $secondaryPrincipal);

        $this->seedFailureTokens($identity);
    }

    /**
     * Persist the primary 2D refresh identity if it does not already exist.
     *
     * @param  \Illuminate\Contracts\Hashing\Hasher  $hasher
     * @return \Tests\Unit\Stubs\StubPrincipal
     */
    private function findOrCreatePrimaryIdentity(Hasher $hasher): StubPrincipal
    {
        $identity = StubPrincipal::query()->first();

        if ($identity instanceof StubPrincipal) {
            return $identity;
        }

        $identity            = new StubPrincipal;
        $identity->email     = self::EMAIL;
        $identity->password  = $hasher->make(self::PASSWORD);
        $identity->is_active = true;
        $identity->save();

        return $identity;
    }

    /**
     * Pre-issue the mutable 2D refresh success token pool.
     *
     * @param  \Tests\Unit\Stubs\StubPrincipal  $identity
     * @return void
     */
    private function seedSuccessTokens(StubPrincipal $identity): void
    {
        if ($this->successTokens !== []) {
            return;
        }

        $this->successTokens = $this->issueRefreshTokenPool(
            'bench-refresh-success-',
            StubPrincipal::class,
            (string) $identity->getKey(), // @phpstan-ignore cast.string
            $identity,
        );

        $owner = (string) $identity->getKey(); // @phpstan-ignore cast.string

        [$this->successCheckToken] = $this->issueRefreshTokenPool('bench-refresh-check-', StubPrincipal::class, $owner, $identity, 1);
    }

    /**
     * Pre-issue a pool of refresh tokens, each bound to its own device row.
     *
     * @param  string  $prefix
     * @param  class-string  $ownerClass
     * @param  string  $ownerId
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  int  $size
     * @return list<string>
     */
    private function issueRefreshTokenPool(string $prefix, string $ownerClass, string $ownerId, Principal $principal, int $size = self::TOKEN_POOL_SIZE): array
    {
        $pool = [];

        for ($index = 0; $index < $size; $index++) {

            $rotationId = $prefix . $index;

            $device = new Device;
            $device->forceFill([
                ...BenchSchema::signedIn('api'),
                'authenticatable_type' => $ownerClass,
                'authenticatable_id'   => $ownerId,
                'client_name'          => $prefix . $index,
                'refresh_key'          => RefreshTokenHasher::hash($rotationId),
                'last_used_at'         => Carbon::now(),
            ])->save();

            $pool[] = $this->tokens->issueRefreshToken($device, $rotationId, $principal);
        }

        return $pool;
    }

    /**
     * Persist the tenant-aware identity plus staff and customer principals.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  \Illuminate\Contracts\Hashing\Hasher  $hasher
     * @return array{0: \Tests\Integration\Fixtures\TenantAware3dIdentity, 1: \Tests\Integration\Fixtures\TenantAware3dPrincipal, 2: \Tests\Integration\Fixtures\TenantAware3dPrincipal,}
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    private function seedTenantAwareFixtures(Hasher $hasher): array
    {
        $tenantAwareIdentity = TenantAware3dIdentity::query()->first();

        if (!$tenantAwareIdentity instanceof TenantAware3dIdentity) {

            $tenantAwareIdentity            = new TenantAware3dIdentity;
            $tenantAwareIdentity->email     = 'bench-refresh-tenant-aware@example.test';
            $tenantAwareIdentity->password  = $hasher->make(self::PASSWORD);
            $tenantAwareIdentity->is_active = true;
            $tenantAwareIdentity->save();
        }

        $tenantAwarePrincipal = TenantFixtures::seedTenantPrincipal(
            $tenantAwareIdentity,
            TenantFixtures::seedTenant('Bench Refresh Staff', 'staff'),
            'bench-refresh-tenant-actor',
        );

        $secondaryPrincipal = TenantFixtures::seedTenantPrincipal(
            $tenantAwareIdentity,
            TenantFixtures::seedTenant('Bench Refresh Customer', 'customer'),
            'bench-refresh-customer-actor',
        );

        return [$tenantAwareIdentity, $tenantAwarePrincipal, $secondaryPrincipal];
    }

    /**
     * Pre-issue the tenant-aware refresh success token pools.
     *
     * @param  \Tests\Integration\Fixtures\TenantAware3dIdentity  $identity
     * @param  \Tests\Integration\Fixtures\TenantAware3dPrincipal  $tenantAwarePrincipal
     * @param  \Tests\Integration\Fixtures\TenantAware3dPrincipal  $secondaryPrincipal
     * @return void
     */
    private function seedTenantAwareSuccessTokens(TenantAware3dIdentity $identity, TenantAware3dPrincipal $tenantAwarePrincipal, TenantAware3dPrincipal $secondaryPrincipal): void
    {
        if ($this->tenantAwareSuccessTokens === []) {
            $this->tenantAwareSuccessTokens = $this->issueRefreshTokenPool(
                'bench-refresh-tenant-success-',
                TenantAware3dIdentity::class,
                (string) $identity->getKey(), // @phpstan-ignore cast.string
                $tenantAwarePrincipal,
            );
        }

        if ($this->tenantAwareSecondarySuccessTokens !== []) {
            return;
        }

        $this->tenantAwareSecondarySuccessTokens = $this->issueRefreshTokenPool(
            'bench-refresh-tenant-secondary-success-',
            TenantAware3dIdentity::class,
            (string) $identity->getKey(), // @phpstan-ignore cast.string
            $secondaryPrincipal,
        );

        $owner = (string) $identity->getKey(); // @phpstan-ignore cast.string

        [$this->tenantAwareCheckToken]          = $this->issueRefreshTokenPool('bench-refresh-tenant-check-', TenantAware3dIdentity::class, $owner, $tenantAwarePrincipal, 1);
        [$this->tenantAwareSecondaryCheckToken] = $this->issueRefreshTokenPool('bench-refresh-secondary-check-', TenantAware3dIdentity::class, $owner, $secondaryPrincipal, 1);
    }

    /**
     * Seed the cheap failure fixtures used by the refresh runtime benches.
     *
     * @param  \Tests\Unit\Stubs\StubPrincipal  $identity
     * @return void
     */
    private function seedFailureTokens(StubPrincipal $identity): void
    {
        // A well-formed id that names no row, so the bench measures the lookup
        // rather than the shape check that rejects malformed ids before it.
        $missingDevice = new Device;
        $missingDevice->forceFill([...BenchSchema::signedIn('api'), 'id' => '0190f1d2-7c4e-7a3b-9f10-000000000000']);
        $this->unknownDeviceToken = $this->tokens->issueRefreshToken($missingDevice, 'bench-missing-device-rotation');

        if ($this->rotationMismatchTokens !== []) {
            return;
        }

        for ($index = 0; $index < self::TOKEN_POOL_SIZE; $index++) {
            $this->rotationMismatchTokens[] = $this->issueMismatchedToken($identity, 'bench-refresh-mismatch-' . $index);
        }

        $this->rotationMismatchCheckToken = $this->issueMismatchedToken($identity, 'bench-refresh-mismatch-check');
    }

    /**
     * Issue a refresh token whose rotation id is not its device's, for a device
     * of its own.
     *
     * @param  \Tests\Unit\Stubs\StubPrincipal  $identity
     * @param  string  $clientName
     * @return string
     */
    private function issueMismatchedToken(StubPrincipal $identity, string $clientName): string
    {
        $device = new Device;
        $device->forceFill([
            ...BenchSchema::signedIn('api'),
            'authenticatable_type' => StubPrincipal::class,
            'authenticatable_id'   => (string) $identity->getKey(), // @phpstan-ignore cast.string
            'client_name'          => $clientName,
            'refresh_key'          => RefreshTokenHasher::hash('stored-rotation-id'),
        ])->save();

        return $this->tokens->issueRefreshToken($device, 'tampered-rotation-id');
    }

    /**
     * Run each benchmarked path once and throw unless it reaches the outcome
     * its name describes: a successful refresh returns a pair (and a
     * tenant-aware one binds its tenant), an unknown device fails as
     * `device_unknown`, and a mismatched rotation id as `rotation_reuse`. Paths
     * that use a token up run on tokens outside the benchmark's pools.
     *
     * @return void
     *
     * @throws \LogicException
     * @throws \Random\RandomException
     */
    private function assertEachPathReachesItsOutcome(): void
    {
        BenchOutcome::assert('refresh success', $this->makeGuard()->refresh($this->successCheckToken) !== null);

        foreach ([$this->tenantAwareCheckToken, $this->tenantAwareSecondaryCheckToken] as $token) {

            $guard = $this->makeGuard($this->tenantAwareProvider);

            BenchOutcome::assert('tenant-aware 3D refresh', $guard->refresh($token) !== null && $guard->tenant() !== null);
        }

        $reasons = [];

        $this->events->listen(AuthenticationFailed::class, static function (AuthenticationFailed $failed) use (&$reasons): void {
            $reasons[] = $failed->reason;
        });

        $this->makeGuard()->refresh($this->unknownDeviceToken);
        $this->makeGuard()->refresh($this->rotationMismatchCheckToken);

        $this->events->forget(AuthenticationFailed::class);

        BenchOutcome::assert('unknown-device failure', ($reasons[0] ?? null) === FailureReason::DEVICE_UNKNOWN);
        BenchOutcome::assert('rotation-mismatch failure', ($reasons[1] ?? null) === FailureReason::ROTATION_REUSE);
    }

    /**
     * Instantiate a fresh JwtGuard for refresh benchmarking.
     *
     * @param  ?\SineMacula\Laravel\Authentication\Providers\ModelProvider  $provider
     * @return \SineMacula\Laravel\Authentication\Guards\JwtGuard
     */
    private function makeGuard(?ModelProvider $provider = null): JwtGuard
    {
        $provider ??= $this->provider;

        $exchange = new RefreshTokenExchange(
            $this->tokens,
            $provider,
            BenchDatabase::connectionResolver(),
            static fn (): null => null,
            $this->events,
            $this->resolver,
            'api',
        );

        return new JwtGuard(
            'api',
            $provider,
            $this->resolver,
            $this->events,
            Request::create('/bench/refresh', 'POST'),
            $this->timebox,
            $this->tokens,
            $exchange,
            fn (JwtGuard $guard, \Closure $timebox): SessionService => new SessionService(
                $guard,
                $timebox,
                $this->tokens,
                new Container,
                BenchDatabase::connectionResolver(),
                static fn (): null => null,
            ),
        );
    }
}
