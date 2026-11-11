<?php

declare(strict_types = 1);

namespace Tests\Performance;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\ApplicationAccess;
use SineMacula\Laravel\Authentication\Contracts\AttemptLimiter;
use SineMacula\Laravel\Authentication\Contracts\ExternalEvidencePolicy;
use SineMacula\Laravel\Authentication\Contracts\TenantAuthenticationPolicy;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\SessionRevoked;
use SineMacula\Laravel\Authentication\External\ExternalEvidence;
use SineMacula\Laravel\Authentication\Facades\Auth as PackageAuth;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Http\Enums\RefreshTokenSource;
use SineMacula\Laravel\Authentication\Http\PresentedRefreshToken;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenService;
use SineMacula\Laravel\Authentication\Jwt\RefreshRotationStore;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenExchange;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenHasher;
use SineMacula\Laravel\Authentication\Jwt\TokenPair;
use SineMacula\Laravel\Authentication\Models\Session;
use SineMacula\Laravel\Authentication\Proofs\Channel;
use SineMacula\Laravel\Authentication\Proofs\Enums\ChannelKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\Purpose;
use SineMacula\Laravel\Authentication\Proofs\Evaluation;
use SineMacula\Laravel\Authentication\Proofs\FirstFactor;
use SineMacula\Laravel\Authentication\Proofs\NewProof;
use SineMacula\Laravel\Authentication\Proofs\ObservedProperties;
use SineMacula\Laravel\Authentication\Proofs\ProofWriter;
use SineMacula\Laravel\Authentication\RateLimiting\AttemptSubject;
use SineMacula\Laravel\Authentication\RateLimiting\Enums\AttemptFlow;
use SineMacula\Laravel\Authentication\Requirements\Enums\RequirementKind;
use SineMacula\Laravel\Authentication\Requirements\Requirement;
use SineMacula\Laravel\Authentication\Requirements\RequirementPart;
use SineMacula\Laravel\Authentication\Sessions\RefreshResult;
use SineMacula\Laravel\Authentication\Tenancy\TenantRequirement;
use Tests\Concerns\InteractsWithSessionRecords;
use Tests\Fixtures\External\ScriptedEvidencePolicy;
use Tests\Fixtures\Sessions\GuardSessions;
use Tests\Fixtures\Sessions\RefusingApplicationAccess;
use Tests\Fixtures\Tenancy\ScriptedTenantAuthenticationPolicy;
use Tests\Integration\Fixtures\TenantAware3dIdentity;
use Tests\Integration\Fixtures\TenantAware3dPrincipal;
use Tests\Integration\Fixtures\TenantAware3dTenant;
use Tests\Unit\Stubs\StubPrincipal;

/**
 * Query-budget contracts for the refresh-token exchange.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(JwtGuard::class)]
#[CoversClass(RefreshTokenExchange::class)]
#[CoversClass(RefreshRotationStore::class)]
final class RefreshTokenExchangeQueryBudgetTest extends PerformanceContractTestCase
{
    use InteractsWithSessionRecords;

    /** @var string Guard name for standard refresh tests. */
    private const string GUARD = 'api';

    /** @var string Guard whose refresh token travels in the cookie. */
    private const string COOKIE_GUARD = 'browser';

    /** @var string The refresh cookie's name, derived from the guard. */
    private const string COOKIE_NAME = '__Secure-browser_refresh_token';

    /** @var int Runs of each path in the timing comparison. */
    private const int TIMED_RUNS = 5;

    /** @var int How many times slower than a rotation the other paths may be. */
    private const int TIMING_FACTOR = 3;

    /** @var string Guard name for tenant-aware refresh tests. */
    private const string TENANT_AWARE_GUARD = 'tenant_api';

    /**
     * Provision the identity table used by the refresh fixtures.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        Schema::create('stub_principals', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('email')->unique();
            $blueprint->string('password');
            $blueprint->boolean('is_active')->default(true);
            $blueprint->timestamps();
        });

        Schema::create('tenant_aware_3d_identities', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('email')->unique();
            $blueprint->string('password');
            $blueprint->boolean('is_active')->default(true);
            $blueprint->timestamps();
        });

        Schema::create('tenant_aware_3d_tenants', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('name');
            $blueprint->string('type');
            $blueprint->timestamps();
        });

        Schema::create('tenant_aware_3d_principals', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->unsignedInteger('identity_id');
            $blueprint->unsignedInteger('tenant_id');
            $blueprint->string('name');
            $blueprint->boolean('is_active')->default(true);
            $blueprint->timestamps();
        });
    }

    /**
     * Release the fixture table.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Schema::dropIfExists('tenant_aware_3d_principals');
        Schema::dropIfExists('tenant_aware_3d_tenants');
        Schema::dropIfExists('tenant_aware_3d_identities');
        Schema::dropIfExists('stub_principals');

        parent::tearDown();
    }

    /**
     * A successful refresh costs five reads and two writes, its last use seeded
     * inside the throttle window.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testRefreshSuccessUsesFiveReadsAndTwoWrites(): void
    {
        $identity   = $this->seedIdentity();
        $rotationId = 'refresh-success-rotation-id';

        $session = new Session;
        $session->forceFill([
            ...self::liveSession('api', $identity),
            'authenticatable_type' => StubPrincipal::class,
            'authenticatable_id'   => (string) $identity->getKey(), // @phpstan-ignore cast.string
            'refresh_key'          => RefreshTokenHasher::hash($rotationId),
            'last_used_at'         => $this->now,
        ])->save();

        $jwt = PackageAuth::jwt(self::GUARD);
        self::assertNotNull($jwt);

        $token = $jwt->issueRefreshToken($session, $rotationId, $identity)->reveal();
        $guard = $this->freshJwtGuard(self::GUARD);

        $result = $this->assertQueryBudget(
            5,
            2,
            static fn () => GuardSessions::of($guard)->refresh(PresentedRefreshToken::fromBody($token), self::requestClient($guard->getRequest()))->session?->tokens,
        );

        self::assertNotNull($result);
    }

    /**
     * Reading the token through the guard's transport adds no query: a refresh
     * with the token the request carries costs what `refresh()` costs.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testARefreshFromTheRequestCostsWhatARefreshCosts(): void
    {
        $identity   = $this->seedIdentity();
        $rotationId = 'refresh-from-request-rotation-id';

        $session = new Session;
        $session->forceFill([
            ...self::liveSession('api', $identity),
            'authenticatable_type' => StubPrincipal::class,
            'authenticatable_id'   => (string) $identity->getKey(), // @phpstan-ignore cast.string
            'refresh_key'          => RefreshTokenHasher::hash($rotationId),
            'last_used_at'         => $this->now,
        ])->save();

        $jwt = PackageAuth::jwt(self::GUARD);
        self::assertNotNull($jwt);

        app()->instance('request', Request::create('/auth/refresh', 'POST', ['refresh_token' => $jwt->issueRefreshToken($session, $rotationId, $identity)->reveal()]));

        $guard = $this->freshJwtGuard(self::GUARD);

        self::assertTrue(
            $this->assertQueryBudget(
                5,
                2,
                static fn () => GuardSessions::of($guard)->refresh(self::servedToken($guard->getName(), $guard->getRequest()), self::requestClient($guard->getRequest())),
            )?->isRefreshed(),
        );
    }

    /**
     * A refresh from the cookie, delivering the new token in it, costs no query
     * more.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testACookieRefreshCostsWhatARefreshCosts(): void
    {
        $identity   = $this->seedIdentity();
        $rotationId = 'cookie-refresh-rotation-id';

        $session = new Session;
        $session->forceFill([
            ...self::liveSession(self::COOKIE_GUARD, $identity),
            'authenticatable_type' => StubPrincipal::class,
            'authenticatable_id'   => (string) $identity->getKey(), // @phpstan-ignore cast.string
            'refresh_key'          => RefreshTokenHasher::hash($rotationId),
            'last_used_at'         => $this->now,
        ])->save();

        $jwt = PackageAuth::jwt(self::COOKIE_GUARD);
        self::assertNotNull($jwt);

        app()->instance('request', self::cookieRequest($jwt->issueRefreshToken($session, $rotationId, $identity)->reveal(), 'http://localhost'));

        $guard = $this->freshJwtGuard(self::COOKIE_GUARD);

        $result = $this->assertQueryBudget(
            5,
            2,
            static fn () => GuardSessions::of($guard)->refresh(self::servedToken($guard->getName(), $guard->getRequest()), self::requestClient($guard->getRequest())),
        );

        self::assertTrue($result?->isRefreshed());
        self::assertNull($result->session?->tokens->refreshToken);
        self::assertSame(self::COOKIE_NAME, $result->session?->tokens->refreshCookie?->name);
    }

    /**
     * A cookie sent from another site is refused before the exchange: no query,
     * and no limit counted.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testACrossSiteCookieRequestCostsNoQuery(): void
    {
        app()->instance('request', self::cookieRequest('a', 'https://elsewhere.example'));

        $guard = $this->freshJwtGuard(self::COOKIE_GUARD);

        self::assertSame(
            FailureReason::CROSS_SITE_REQUEST,
            $this->assertQueryBudget(
                0,
                0,
                static fn () => GuardSessions::of($guard)->refresh(self::servedToken($guard->getName(), $guard->getRequest()), self::requestClient($guard->getRequest())),
            )?->reason,
        );
    }

    /**
     * A cookie refresh from plain values costs what a refresh costs; one
     * refused before the exchange costs no query.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAPlainCookieRefreshCostsWhatARefreshCosts(): void
    {
        $identity   = $this->seedIdentity();
        $rotationId = 'plain-cookie-refresh-rotation-id';

        $session = new Session;
        $session->forceFill([
            ...self::liveSession(self::COOKIE_GUARD, $identity),
            'authenticatable_type' => StubPrincipal::class,
            'authenticatable_id'   => (string) $identity->getKey(), // @phpstan-ignore cast.string
            'refresh_key'          => RefreshTokenHasher::hash($rotationId),
            'last_used_at'         => $this->now,
        ])->save();

        $jwt = PackageAuth::jwt(self::COOKIE_GUARD);
        self::assertNotNull($jwt);

        $token     = $jwt->issueRefreshToken($session, $rotationId, $identity);
        $presented = new PresentedRefreshToken($token, RefreshTokenSource::COOKIE, [RefreshTokenSource::COOKIE]);
        $sameSite  = new ClientContext('192.0.2.44', 'Plain/1.0', 'http://localhost', 'http://localhost', ['x-requested-with']);

        app()->instance('request', Request::create('/elsewhere', 'POST'));

        $guard = $this->freshJwtGuard(self::COOKIE_GUARD);

        $crossSite = $this->assertQueryBudget(0, 0, static fn () => GuardSessions::of($guard)->refresh($presented, new ClientContext('192.0.2.44', 'Plain/1.0')));
        $conflict  = $this->assertQueryBudget(0, 0, static fn () => GuardSessions::of($guard)->refresh(
            new PresentedRefreshToken($token, RefreshTokenSource::COOKIE, [RefreshTokenSource::COOKIE, RefreshTokenSource::COOKIE]),
            $sameSite,
        ));

        $mismatch = $this->assertQueryBudget(0, 0, static fn () => GuardSessions::of($guard)->refresh(
            new PresentedRefreshToken($token, RefreshTokenSource::BODY, [RefreshTokenSource::BODY]),
            $sameSite,
        ));
        $handedIn = $this->assertQueryBudget(0, 0, static fn () => GuardSessions::of($guard)->refresh(FailureReason::TOKEN_INVALID, $sameSite));

        self::assertSame(FailureReason::CROSS_SITE_REQUEST, $crossSite->reason);
        self::assertSame(FailureReason::REFRESH_TOKEN_CONFLICT, $conflict->reason);
        self::assertSame(FailureReason::REFRESH_TRANSPORT_MISMATCH, $mismatch->reason);
        self::assertSame(FailureReason::TOKEN_INVALID, $handedIn->reason);
        self::assertNull($this->assertQueryBudget(0, 0, static fn () => GuardSessions::of($guard)->refresh(null, $sameSite)));

        $result = $this->assertQueryBudget(5, 2, static fn () => GuardSessions::of($guard)->refresh($presented, $sameSite));

        self::assertTrue($result->isRefreshed());
        self::assertSame(self::COOKIE_NAME, $result->session?->tokens->refreshCookie?->name);
    }

    /**
     * A body application's refresh from plain values, from a client without the
     * same-site facts, costs what a refresh costs.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAPlainBodyRefreshCostsWhatARefreshCosts(): void
    {
        $identity   = $this->seedIdentity();
        $rotationId = 'plain-body-refresh-rotation-id';

        $session = new Session;
        $session->forceFill([
            ...self::liveSession('api', $identity),
            'authenticatable_type' => StubPrincipal::class,
            'authenticatable_id'   => (string) $identity->getKey(), // @phpstan-ignore cast.string
            'refresh_key'          => RefreshTokenHasher::hash($rotationId),
            'last_used_at'         => $this->now,
        ])->save();

        $jwt = PackageAuth::jwt(self::GUARD);
        self::assertNotNull($jwt);

        $presented = new PresentedRefreshToken($jwt->issueRefreshToken($session, $rotationId, $identity), RefreshTokenSource::BODY, [RefreshTokenSource::BODY]);

        app()->instance('request', Request::create('/elsewhere', 'POST'));

        $guard = $this->freshJwtGuard(self::GUARD);

        $result = $this->assertQueryBudget(5, 2, static fn () => GuardSessions::of($guard)->refresh($presented, new ClientContext('192.0.2.44', 'Plain/1.0')));

        self::assertTrue($result->isRefreshed());
        self::assertNotNull($result->session?->tokens->refreshToken);
    }

    /**
     * A request the transport refuses is refused before the exchange: no query,
     * and no limit counted.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testARequestTheTransportRefusesCostsNoQuery(): void
    {
        app()->instance('request', Request::create('/auth/refresh', 'POST', ['refresh_token' => 'a'], [], [], ['HTTP_X_REFRESH_TOKEN' => 'a']));

        $guard = $this->freshJwtGuard(self::GUARD);

        self::assertSame(
            FailureReason::REFRESH_TOKEN_CONFLICT,
            $this->assertQueryBudget(
                0,
                0,
                static fn () => GuardSessions::of($guard)->refresh(self::servedToken($guard->getName(), $guard->getRequest()), self::requestClient($guard->getRequest())),
            )?->reason,
        );
    }

    /**
     * Unknown-session refresh failures should stop at the first session lookup,
     * then count the failure.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testUnknownSessionRefreshFailureStopsAtTheSessionLookup(): void
    {
        $missingSession = new Session;
        $missingSession->forceFill([...self::liveSession(), 'id' => '00000000-0000-0000-0000-000000000000']);

        $jwt = PackageAuth::jwt(self::GUARD);
        self::assertNotNull($jwt);

        $token = $jwt->issueRefreshToken($missingSession, 'missing-session-rotation')->reveal();

        $guard = $this->freshJwtGuard(self::GUARD);

        $result = $this->assertQueryBudget(
            2,
            4,
            static fn () => GuardSessions::of($guard)->refresh(PresentedRefreshToken::fromBody($token), self::requestClient($guard->getRequest()))->session?->tokens,
        );

        self::assertNull($result);
    }

    /**
     * A session id that cannot be a key fails before the session lookup.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testMalformedSessionIdRefreshFailureSkipsTheSessionLookup(): void
    {
        $malformedSession = new Session;
        $malformedSession->forceFill([...self::liveSession(), 'id' => 'not-a-uuid']);

        $jwt = PackageAuth::jwt(self::GUARD);
        self::assertNotNull($jwt);

        $token = $jwt->issueRefreshToken($malformedSession, 'malformed-session-rotation')->reveal();

        $guard = $this->freshJwtGuard(self::GUARD);

        $result = $this->assertQueryBudget(
            1,
            4,
            static fn () => GuardSessions::of($guard)->refresh(PresentedRefreshToken::fromBody($token), self::requestClient($guard->getRequest()))->session?->tokens,
        );

        self::assertNull($result);
    }

    /**
     * A replayed refresh token is judged from the session row and revoked in
     * one write.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testReplayRevocationReadsTheSessionAndRevokesItInOneWrite(): void
    {
        $identity = $this->seedIdentity();
        $session  = $this->seedSession($identity, ['refresh_key' => RefreshTokenHasher::hash('stored-rotation-id')]);

        $token = $this->tokens()->issueRefreshToken($session, 'replayed-rotation-id')->reveal();
        $guard = $this->freshJwtGuard(self::GUARD);

        self::assertNull(
            $this->assertQueryBudget(
                3,
                6,
                static fn () => GuardSessions::of($guard)->refresh(PresentedRefreshToken::fromBody($token), self::requestClient($guard->getRequest())),
            )->session,
        );
        self::assertSame('rotation_reuse', Session::query()->whereKey($session->getKey())->firstOrFail()->getRevokedReason());
    }

    /**
     * A grace retry reads five times and writes only the issuance guard.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testGraceRetryUsesFiveReadsAndWritesOnlyTheIssuanceGuard(): void
    {
        $identity = $this->seedIdentity();
        $session  = $this->seedSession($identity, [
            'refresh_key'          => RefreshTokenHasher::hash(RefreshTokenHasher::successor('previous-rotation-id')),
            'previous_refresh_key' => RefreshTokenHasher::hash('previous-rotation-id'),
            'refresh_rotated_at'   => $this->now->copy()->subSeconds(5),
            'last_used_at'         => $this->now,
        ]);

        $token = $this->tokens()->issueRefreshToken($session, 'previous-rotation-id', $identity)->reveal();
        $guard = $this->freshJwtGuard(self::GUARD);

        self::assertNotNull(
            $this->assertQueryBudget(
                5,
                1,
                static fn () => GuardSessions::of($guard)->refresh(PresentedRefreshToken::fromBody($token), self::requestClient($guard->getRequest())),
            )->session,
        );
    }

    /**
     * A refresh whose swap misses succeeds as a grace retry in seven reads and
     * two writes.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testLostRotationResolvedAsAGraceRetryUsesSevenReadsAndTwoWrites(): void
    {
        $identity = $this->seedIdentity();
        $session  = $this->seedSession($identity, [
            'refresh_key'  => RefreshTokenHasher::hash('raced-rotation-id'),
            'last_used_at' => $this->now,
        ]);

        $token = $this->tokens()->issueRefreshToken($session, 'raced-rotation-id', $identity)->reveal();
        $guard = $this->freshJwtGuard(self::GUARD);
        $ran   = false;

        DB::connection()->beforeExecuting(function (string $query) use (&$ran, $session): void {
            if ($ran || !str_contains($query, 'refresh_rotated_at')) {
                return;
            }

            $ran = true;

            // The winning request's rotation, through PDO so it goes uncounted.
            DB::connection()->getPdo()
                ->prepare('update authentication_sessions set refresh_key = ?, previous_refresh_key = ?, refresh_rotated_at = ? where id = ?')
                ->execute([
                    RefreshTokenHasher::hash(RefreshTokenHasher::successor('raced-rotation-id')),
                    RefreshTokenHasher::hash('raced-rotation-id'),
                    $this->now->format('Y-m-d H:i:s'),
                    $session->getKey(),
                ]);
        });

        self::assertNotNull(
            $this->assertQueryBudget(
                7,
                2,
                static fn () => GuardSessions::of($guard)->refresh(PresentedRefreshToken::fromBody($token), self::requestClient($guard->getRequest())),
            )->session,
        );
    }

    /**
     * A refresh for a session with no refresh credential stops at the session
     * lookup.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testMissingRefreshCredentialStopsAtTheSessionLookup(): void
    {
        $identity = $this->seedIdentity();
        $session  = $this->seedSession($identity, ['refresh_key' => null]);

        $token  = $this->tokens()->issueRefreshToken($session, 'any-rotation-id')->reveal();
        $guard  = $this->freshJwtGuard(self::GUARD);
        $events = $this->recordRefreshEvents();

        self::assertNull(
            $this->assertQueryBudget(
                3,
                5,
                static fn () => GuardSessions::of($guard)->refresh(PresentedRefreshToken::fromBody($token), self::requestClient($guard->getRequest())),
            )->session,
        );
        self::assertSame([[FailureReason::REFRESH_KEY_MISSING, $session->getKey()]], self::failures($events));
    }

    /**
     * A refresh replaying a token against a session revoked for reuse revokes
     * nothing again.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testRevokedSessionRefreshFailureStopsAtTheSessionLookup(): void
    {
        $identity = $this->seedIdentity();
        $session  = $this->seedSession($identity, [
            'refresh_key'          => null,
            'previous_refresh_key' => null,
            'revoked_at'           => $this->now->copy()->subMinute(),
            'revoked_reason'       => 'rotation_reuse',
        ]);

        $token  = $this->tokens()->issueRefreshToken($session, 'replayed-rotation-id', $identity)->reveal();
        $guard  = $this->freshJwtGuard(self::GUARD);
        $events = $this->recordRefreshEvents();

        self::assertNull(
            $this->assertQueryBudget(
                3,
                5,
                static fn () => GuardSessions::of($guard)->refresh(PresentedRefreshToken::fromBody($token), self::requestClient($guard->getRequest())),
            )->session,
        );
        self::assertSame([[FailureReason::SESSION_REVOKED, $session->getKey()]], self::failures($events));
    }

    /**
     * The grace and replay paths take no longer than a rotation.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Random\RandomException
     */
    public function testGraceAndReplayCostNoMoreThanARotation(): void
    {
        $identity = $this->seedIdentity();
        $fastest  = ['current' => PHP_INT_MAX, 'grace' => PHP_INT_MAX, 'replay' => PHP_INT_MAX];

        for ($run = 0; $run < self::TIMED_RUNS; $run++) {
            foreach (array_keys($fastest) as $path) {

                $token = $this->tokenForPath($identity, $path, "timed-{$path}-{$run}");
                $guard = $this->freshJwtGuard(self::GUARD);

                $started = hrtime(true);
                $result  = GuardSessions::of($guard)->refresh(PresentedRefreshToken::fromBody($token), self::requestClient($guard->getRequest()))->session?->tokens;
                $elapsed = hrtime(true) - $started;

                self::assertSame($path !== 'replay', $result !== null, $path);

                $fastest[$path] = min($fastest[$path], $elapsed);
            }
        }

        self::assertLessThan(self::TIMING_FACTOR * $fastest['current'], $fastest['grace']);
        self::assertLessThan(self::TIMING_FACTOR * $fastest['current'], $fastest['replay']);
    }

    /**
     * A refresh for an ended session stops at the session lookup and its
     * locking re-read.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testEndedSessionRefreshFailureStopsAtTheSessionLookup(): void
    {
        $identity   = $this->seedIdentity();
        $rotationId = 'ended-session-rotation-id';

        $session = new Session;
        $session->forceFill([
            ...self::liveSession('api', $identity),
            'authenticatable_type' => StubPrincipal::class,
            'authenticatable_id'   => (string) $identity->getKey(), // @phpstan-ignore cast.string
            'refresh_key'          => RefreshTokenHasher::hash($rotationId),
        ])->save();

        $jwt = PackageAuth::jwt(self::GUARD);
        self::assertNotNull($jwt);

        $token = $jwt->issueRefreshToken($session, $rotationId, $identity)->reveal();

        $session->forceFill(['idle_expires_at' => $this->now])->save();

        $guard  = $this->freshJwtGuard(self::GUARD);
        $events = $this->recordRefreshEvents();

        self::assertNull(
            $this->assertQueryBudget(
                3,
                5,
                static fn () => GuardSessions::of($guard)->refresh(PresentedRefreshToken::fromBody($token), self::requestClient($guard->getRequest())),
            )->session,
        );
        self::assertSame([[FailureReason::SESSION_EXPIRED, $session->getKey()]], self::failures($events));
    }

    /**
     * A refresh for another guard's session is refused from the session row.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testGuardMismatchRefreshFailureStopsAtTheSessionLookup(): void
    {
        $session = $this->seedSession($this->seedIdentity(), ['guard' => 'other', 'refresh_key' => RefreshTokenHasher::hash('other-guard-rotation-id')]);
        $token   = $this->tokens()->issueRefreshToken($session, 'other-guard-rotation-id')->reveal();
        $guard   = $this->freshJwtGuard(self::GUARD);
        $events  = $this->recordRefreshEvents();

        self::assertNull(
            $this->assertQueryBudget(
                2,
                4,
                static fn () => GuardSessions::of($guard)->refresh(PresentedRefreshToken::fromBody($token), self::requestClient($guard->getRequest())),
            )->session,
        );
        self::assertSame([[FailureReason::SESSION_GUARD_MISMATCH, $session->getKey()]], self::failures($events));
    }

    /**
     * A refresh whose session began with a method no longer allowed is refused
     * before any rotation write.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testDisallowedMethodRefreshFailureStopsBeforeTheRotation(): void
    {
        $identity = $this->seedIdentity();
        $session  = $this->seedSession($identity, ['sign_in_method' => 'sso', 'refresh_key' => RefreshTokenHasher::hash('sso-rotation-id')]);
        $token    = $this->tokens()->issueRefreshToken($session, 'sso-rotation-id', $identity)->reveal();
        $guard    = $this->freshJwtGuard(self::GUARD);
        $events   = $this->recordRefreshEvents();

        self::assertNull(
            $this->assertQueryBudget(
                4,
                5,
                static fn () => GuardSessions::of($guard)->refresh(PresentedRefreshToken::fromBody($token), self::requestClient($guard->getRequest())),
            )->session,
        );
        self::assertSame([[FailureReason::METHOD_NOT_ALLOWED, $session->getKey()]], self::failures($events));
    }

    /**
     * A refresh for a principal no longer admitted is refused before any
     * rotation write.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testIneligiblePrincipalRefreshFailureStopsBeforeTheRotation(): void
    {
        $identity = $this->seedIdentity();
        $session  = $this->seedSession($identity, ['refresh_key' => RefreshTokenHasher::hash('ineligible-rotation-id')]);
        $token    = $this->tokens()->issueRefreshToken($session, 'ineligible-rotation-id', $identity)->reveal();

        app()->instance(ApplicationAccess::class, new RefusingApplicationAccess(static fn (): bool => true));

        $guard  = $this->freshJwtGuard(self::GUARD);
        $events = $this->recordRefreshEvents();

        self::assertNull(
            $this->assertQueryBudget(
                4,
                5,
                static fn () => GuardSessions::of($guard)->refresh(PresentedRefreshToken::fromBody($token), self::requestClient($guard->getRequest())),
            )->session,
        );
        self::assertSame([[FailureReason::PRINCIPAL_INELIGIBLE, $session->getKey()]], self::failures($events));
    }

    /**
     * A rate-limited refresh is refused from the limits' read alone.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testRateLimitedRefreshIsRefusedFromTheLimitsAlone(): void
    {
        $session = $this->seedSession($this->seedIdentity(), ['refresh_key' => RefreshTokenHasher::hash('limited-rotation-id')]);
        $token   = $this->tokens()->issueRefreshToken($session, 'limited-rotation-id')->reveal();

        $limits = ['refresh' => ['per_identifier' => ['max' => 1, 'decay_seconds' => 60], 'per_ip' => null]];

        app(ConfigRepository::class)->set('auth.guards.' . self::GUARD . '.rate_limits', $limits);

        $guard = $this->freshJwtGuard(self::GUARD);

        app(AttemptLimiter::class)->recordFailure(new AttemptSubject(self::GUARD, AttemptFlow::REFRESH, (string) $session->getKey(), null, null)); // @phpstan-ignore cast.string

        $events   = $this->recordRefreshEvents();
        $sessions = GuardSessions::of($guard);
        $result   = $this->assertQueryBudget(1, 0, static fn (): RefreshResult => $sessions->refresh(PresentedRefreshToken::fromBody($token), self::requestClient()));

        self::assertSame(FailureReason::RATE_LIMITED, $result->reason);
        self::assertCount(1, $events);
        self::assertSame(FailureReason::RATE_LIMITED, $events[0]->reason ?? null);
    }

    /**
     * A tenant-aware 3D refresh costs six reads and writes the issuance guard
     * and the rotation.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testThreeDimensionalRefreshPathWithTenantAccessUsesSixReadsAndTwoWrites(): void
    {
        [$identity, $principal] = $this->seedTenantAwareThreeDimensionalFixtures();
        $rotationId             = 'refresh-tenant-aware-success';

        $session = new Session;
        $session->forceFill([
            ...self::liveSession(self::TENANT_AWARE_GUARD, $principal),
            'authenticatable_type' => TenantAware3dIdentity::class,
            'authenticatable_id'   => (string) $identity->getKey(), // @phpstan-ignore cast.string
            'refresh_key'          => RefreshTokenHasher::hash($rotationId),
            'last_used_at'         => $this->now,
        ])->save();

        $jwt = PackageAuth::jwt(self::TENANT_AWARE_GUARD);
        self::assertNotNull($jwt);

        $token = $jwt->issueRefreshToken($session, $rotationId, $principal)->reveal();
        $guard = $this->freshJwtGuard(self::TENANT_AWARE_GUARD);

        $result = $this->assertQueryBudget(6, 2, static function () use ($guard, $token): ?TokenPair {
            $tokens = GuardSessions::of($guard)->refresh(PresentedRefreshToken::fromBody($token), self::requestClient($guard->getRequest()))->session?->tokens;
            $guard->principal()?->getIdentity();
            $guard->tenant();

            return $tokens;
        });

        self::assertNotNull($result);
    }

    /**
     * A refresh for a secondary tenant hint costs what the primary tenant path
     * does.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testThreeDimensionalRefreshPathWithSecondaryTenantHintUsesSixReadsAndTwoWrites(): void
    {
        [$identity, , $secondaryPrincipal] = $this->seedTenantAwareThreeDimensionalFixturesWithSecondaryTenant();
        $rotationId                        = 'refresh-tenant-aware-secondary-success';

        $session = new Session;
        $session->forceFill([
            ...self::liveSession(self::TENANT_AWARE_GUARD, $secondaryPrincipal),
            'authenticatable_type' => TenantAware3dIdentity::class,
            'authenticatable_id'   => (string) $identity->getKey(), // @phpstan-ignore cast.string
            'refresh_key'          => RefreshTokenHasher::hash($rotationId),
            'last_used_at'         => $this->now,
        ])->save();

        $jwt = PackageAuth::jwt(self::TENANT_AWARE_GUARD);
        self::assertNotNull($jwt);

        $token = $jwt->issueRefreshToken($session, $rotationId, $secondaryPrincipal)->reveal();
        $guard = $this->freshJwtGuard(self::TENANT_AWARE_GUARD);

        $result = $this->assertQueryBudget(6, 2, static function () use ($guard, $token): ?TokenPair {
            $tokens = GuardSessions::of($guard)->refresh(PresentedRefreshToken::fromBody($token), self::requestClient($guard->getRequest()))->session?->tokens;
            $guard->principal()?->getIdentity();
            $guard->tenant();

            return $tokens;
        });

        self::assertNotNull($result);
        self::assertSame($secondaryPrincipal->getPrincipalIdentifier(), $guard->principal()?->getPrincipalIdentifier());
        self::assertSame($secondaryPrincipal->getTenant()?->getTenantIdentifier(), $guard->tenant()?->getTenantIdentifier());
    }

    /**
     * Rows of `[requirement, reason, writes]`: a tenant policy the session
     * falls short of, the reason (`null` for pending) and the writes.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Authentication\Tenancy\TenantRequirement, 1: ?\SineMacula\Laravel\Authentication\Events\Enums\FailureReason, 2: int}>
     */
    public static function provideTenantPoliciesTheSessionFallsShortOf(): iterable
    {
        yield 'a further factor' => [new TenantRequirement('v2', new Requirement(new RequirementPart)), null, 2];
        yield 'a connection' => [new TenantRequirement('v2', connections: ['conn-a']), FailureReason::SSO_REQUIRED, 6];
    }

    /**
     * A 3D refresh short of its tenant's policy reads the proof it is judged on
     * and writes its guard and one update.
     *
     * @param  \SineMacula\Laravel\Authentication\Tenancy\TenantRequirement  $requirement
     * @param  ?\SineMacula\Laravel\Authentication\Events\Enums\FailureReason  $reason
     * @param  int  $writes
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[DataProvider('provideTenantPoliciesTheSessionFallsShortOf')]
    public function testThreeDimensionalRefreshShortOfItsTenantsPolicyWritesItsGuardAndOneUpdate(TenantRequirement $requirement, ?FailureReason $reason, int $writes): void
    {
        [$identity, $principal] = $this->seedTenantAwareThreeDimensionalFixtures();
        $rotationId             = 'refresh-tenant-aware-short';

        $session = new Session;
        $session->forceFill([
            ...self::liveSession(self::TENANT_AWARE_GUARD, $principal),
            'authenticatable_type' => TenantAware3dIdentity::class,
            'authenticatable_id'   => (string) $identity->getKey(), // @phpstan-ignore cast.string
            'refresh_key'          => RefreshTokenHasher::hash($rotationId),
            'last_used_at'         => $this->now,
        ])->save();

        app()->instance(TenantAuthenticationPolicy::class, new ScriptedTenantAuthenticationPolicy($requirement));

        $jwt = PackageAuth::jwt(self::TENANT_AWARE_GUARD);
        self::assertNotNull($jwt);

        $token  = $jwt->issueRefreshToken($session, $rotationId, $principal)->reveal();
        $guard  = $this->freshJwtGuard(self::TENANT_AWARE_GUARD);
        $result = $this->assertQueryBudget(
            6,
            $writes,
            static fn (): RefreshResult => GuardSessions::of($guard)->refresh(PresentedRefreshToken::fromBody($token), self::requestClient($guard->getRequest())),
        );

        self::assertNull($result->session);
        self::assertSame($reason, $result->reason);
        self::assertSame($reason === null, $result->isPending());
    }

    /**
     * Rows of `[whether the session's accepted evidence meets the tenant's
     * factor, reads]`.
     *
     * @return iterable<string, array{0: bool, 1: int}>
     */
    public static function provideExternalEvidenceVerdicts(): iterable
    {
        yield 'met by the accepted evidence' => [true, 8];
        yield 'not met by it' => [false, 7];
    }

    /**
     * An external session's refresh under a tenant's factor reads its accepted
     * evidence once.
     *
     * @param  bool  $meets
     * @param  int  $reads
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideExternalEvidenceVerdicts')]
    public function testAnExternalSessionsRefreshUnderATenantsFactorReadsItsAcceptedEvidenceOnce(bool $meets, int $reads): void
    {
        [$identity, $principal] = $this->seedTenantAwareThreeDimensionalFixtures();
        $rotationId             = 'refresh-tenant-aware-external';
        $now                    = $this->now->toImmutable();

        $session = new Session;
        $session->forceFill([
            ...self::liveSession(self::TENANT_AWARE_GUARD, $principal),
            'authenticatable_type' => TenantAware3dIdentity::class,
            'authenticatable_id'   => (string) $identity->getKey(), // @phpstan-ignore cast.string
            'refresh_key'          => RefreshTokenHasher::hash($rotationId),
            'last_used_at'         => $this->now,
        ])->save();

        DB::table('authentication_proofs')->delete();

        ProofWriter::record($session, self::TENANT_AWARE_GUARD, new NewProof(
            ProofKind::FIRST_FACTOR,
            Purpose::SIGN_IN,
            'external_provider',
            new Channel(ChannelKind::EXTERNAL_PROVIDER, 'conn-a'),
            null,
            new ObservedProperties,
            new Evaluation(true, true),
            [FirstFactor::EXTERNAL_PROVIDER_METHOD],
            $now,
            new ExternalEvidence(['mfa'], null, $now),
        ));

        app()->instance(TenantAuthenticationPolicy::class, new ScriptedTenantAuthenticationPolicy(new TenantRequirement('v2', new Requirement(multifactor: new RequirementPart))));
        app()->instance(ExternalEvidencePolicy::class, new ScriptedEvidencePolicy($meets ? [RequirementKind::MULTIFACTOR] : []));

        $jwt = PackageAuth::jwt(self::TENANT_AWARE_GUARD);
        self::assertNotNull($jwt);

        $token  = $jwt->issueRefreshToken($session, $rotationId, $principal)->reveal();
        $guard  = $this->freshJwtGuard(self::TENANT_AWARE_GUARD);
        $result = $this->assertQueryBudget(
            $reads,
            2,
            static fn (): RefreshResult => GuardSessions::of($guard)->refresh(PresentedRefreshToken::fromBody($token), self::requestClient($guard->getRequest())),
        );

        self::assertSame([$meets, !$meets], [$result->isRefreshed(), $result->isPending()]);
    }

    /**
     * A failure on the 3D pid path must still stop before the rotation write;
     * it writes only the issuance guard and the failure's count.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testThreeDimensionalRefreshPidFailureStopsBeforeRotationWrite(): void
    {
        [
            $identity,
            $principal
        ]           = $this->seedTenantAwareThreeDimensionalFixtures('refresh-tenant-aware-failure@example.test', false);
        $rotationId = 'refresh-tenant-aware-failure';

        $session = new Session;
        $session->forceFill([
            ...self::liveSession(self::TENANT_AWARE_GUARD),
            'authenticatable_type' => TenantAware3dIdentity::class,
            'authenticatable_id'   => (string) $identity->getKey(), // @phpstan-ignore cast.string
            'refresh_key'          => RefreshTokenHasher::hash($rotationId),
            'last_used_at'         => $this->now,
        ])->save();

        $jwt = PackageAuth::jwt(self::TENANT_AWARE_GUARD);
        self::assertNotNull($jwt);

        $token = $jwt->issueRefreshToken($session, $rotationId, $principal)->reveal();
        $guard = $this->freshJwtGuard(self::TENANT_AWARE_GUARD);

        $result = $this->assertQueryBudget(5, 5, static function () use ($guard, $token): ?TokenPair {
            $tokens = GuardSessions::of($guard)->refresh(PresentedRefreshToken::fromBody($token), self::requestClient($guard->getRequest()))->session?->tokens;
            $guard->tenant();

            return $tokens;
        });

        self::assertNull($result);
    }

    /**
     * Configure the single JWT guard used by this test.
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

        /** @var \Illuminate\Config\Repository $config */
        $config = $app->make(ConfigRepository::class);

        $config->set('auth.defaults.guard', self::GUARD);

        $config->set('auth.guards.' . self::GUARD, [
            'driver'      => 'jwt',
            'provider'    => 'identities',
            'application' => ['methods' => ['password']],
        ]);

        $config->set('auth.guards.' . self::COOKIE_GUARD, [
            'driver'        => 'jwt',
            'provider'      => 'identities',
            'application'   => ['methods' => ['password']],
            'refresh_token' => ['transport' => 'cookie', 'cookie' => ['path' => '/auth']],
        ]);

        $config->set('auth.guards.' . self::TENANT_AWARE_GUARD, [
            'driver'      => 'jwt',
            'provider'    => 'tenant_aware_identities',
            'application' => ['methods' => ['password']],
        ]);

        $config->set('auth.providers.identities', [
            'driver' => 'model',
            'model'  => StubPrincipal::class,
        ]);

        $config->set('auth.providers.tenant_aware_identities', [
            'driver' => 'model',
            'model'  => TenantAware3dIdentity::class,
        ]);

        $config->set('authentication.session.last_used_throttle_seconds', 60);
    }

    /**
     * A refresh request to the cookie guard carrying the token in the refresh
     * cookie, from the origin, with the custom header.
     *
     * @param  string  $token
     * @param  string  $origin
     * @return \Illuminate\Http\Request
     */
    private static function cookieRequest(#[\SensitiveParameter] string $token, string $origin): Request
    {
        return Request::create('/auth/refresh', 'POST', [], [self::COOKIE_NAME => $token], [], [
            'HTTP_COOKIE'           => self::COOKIE_NAME . '=' . $token,
            'HTTP_ORIGIN'           => $origin,
            'HTTP_X_REQUESTED_WITH' => 'XMLHttpRequest',
        ]);
    }

    /**
     * Persist and return an active identity that is also the acting principal.
     *
     * @return \Tests\Unit\Stubs\StubPrincipal
     */
    private function seedIdentity(): StubPrincipal
    {
        $identity            = new StubPrincipal;
        $identity->email     = 'refresh-performance@example.test';
        $identity->password  = password_hash('correct horse battery staple', PASSWORD_BCRYPT);
        $identity->is_active = true;
        $identity->save();

        return $identity;
    }

    /**
     * Persist and return a tenant-aware 3D identity and hinted principal.
     *
     * @formatter:off
     *
     * @param  string  $email
     * @param  bool  $principalActive
     * @return array{0: \Tests\Integration\Fixtures\TenantAware3dIdentity, 1: \Tests\Integration\Fixtures\TenantAware3dPrincipal}
     *
     * @formatter:on
     */
    private function seedTenantAwareThreeDimensionalFixtures(string $email = 'refresh-tenant-aware@example.test', bool $principalActive = true): array
    {
        $identity            = new TenantAware3dIdentity;
        $identity->email     = $email;
        $identity->password  = password_hash('correct horse battery staple', PASSWORD_BCRYPT);
        $identity->is_active = true;
        $identity->save();

        $tenant       = new TenantAware3dTenant;
        $tenant->name = 'Refresh Staff';
        $tenant->type = 'staff';
        $tenant->save();

        $principal              = new TenantAware3dPrincipal;
        $principal->identity_id = $identity->getKey(); // @phpstan-ignore assign.propertyType
        $principal->tenant_id   = $tenant->getKey(); // @phpstan-ignore assign.propertyType
        $principal->name        = 'refresh-staff-actor';
        $principal->is_active   = $principalActive;
        $principal->save();

        return [$identity, $principal];
    }

    /**
     * Persist and return a tenant-aware 3D identity with active principals for
     * two separate tenant types.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  string  $email
     * @return array{0: \Tests\Integration\Fixtures\TenantAware3dIdentity, 1: \Tests\Integration\Fixtures\TenantAware3dPrincipal, 2: \Tests\Integration\Fixtures\TenantAware3dPrincipal}
     *
     * @formatter:on
     */
    private function seedTenantAwareThreeDimensionalFixturesWithSecondaryTenant(string $email = 'refresh-tenant-aware-secondary@example.test'): array
    {
        [$identity, $primaryPrincipal] = $this->seedTenantAwareThreeDimensionalFixtures($email);

        $secondaryTenant       = new TenantAware3dTenant;
        $secondaryTenant->name = 'Refresh Customer';
        $secondaryTenant->type = 'customer';
        $secondaryTenant->save();

        $secondaryPrincipal              = new TenantAware3dPrincipal;
        $secondaryPrincipal->identity_id = $identity->getKey(); // @phpstan-ignore assign.propertyType
        $secondaryPrincipal->tenant_id   = $secondaryTenant->getKey(); // @phpstan-ignore assign.propertyType
        $secondaryPrincipal->name        = 'refresh-customer-actor';
        $secondaryPrincipal->is_active   = true;
        $secondaryPrincipal->save();

        return [$identity, $primaryPrincipal, $secondaryPrincipal];
    }

    /**
     * Persist a live session owned by the identity, with any further state.
     *
     * @param  \Tests\Unit\Stubs\StubPrincipal  $identity
     * @param  array<string, mixed>  $state
     * @return \SineMacula\Laravel\Authentication\Models\Session
     */
    private function seedSession(StubPrincipal $identity, array $state): Session
    {
        $session = new Session;
        $session->forceFill([
            ...self::liveSession('api', $identity),
            'authenticatable_type' => StubPrincipal::class,
            'authenticatable_id'   => (string) $identity->getKey(), // @phpstan-ignore cast.string
            ...$state,
        ])->save();

        return $session;
    }

    /**
     * Record every `AuthenticationFailed` and `SessionRevoked` event dispatched
     * from here on.
     *
     * @return \ArrayObject<int, object>
     */
    private function recordRefreshEvents(): \ArrayObject
    {
        /** @var \ArrayObject<int, object> $events */
        $events = new \ArrayObject;

        Event::listen([AuthenticationFailed::class, SessionRevoked::class], static function (object $event) use ($events): void {
            $events->append($event);
        });

        return $events;
    }

    /**
     * The reason and session id of each recorded failure, and nothing for any
     * other recorded event.
     *
     * @param  \ArrayObject<int, object>  $events
     * @return list<array{0: \SineMacula\Laravel\Authentication\Events\Enums\FailureReason, 1: ?string}>
     */
    private static function failures(\ArrayObject $events): array
    {
        $failures = [];

        foreach ($events as $event) {

            if (!$event instanceof AuthenticationFailed) {
                continue;
            }

            $failures[] = [$event->reason, $event->context->sessionId];
        }

        return $failures;
    }

    /**
     * The `api` guard's token service.
     *
     * @return \SineMacula\Laravel\Authentication\Jwt\JwtTokenService
     */
    private function tokens(): JwtTokenService
    {
        $jwt = PackageAuth::jwt(self::GUARD);

        self::assertNotNull($jwt);

        return $jwt;
    }

    /**
     * A refresh token that takes the given path through the exchange, for a new
     * session of the identity.
     *
     * @param  \Tests\Unit\Stubs\StubPrincipal  $identity
     * @param  string  $path
     * @param  string  $rotationId
     * @return string
     */
    private function tokenForPath(StubPrincipal $identity, string $path, string $rotationId): string
    {
        $session = $this->seedSession($identity, match ($path) {
            'current' => ['refresh_key' => RefreshTokenHasher::hash($rotationId), 'last_used_at' => $this->now],
            'grace'   => [
                'refresh_key'          => RefreshTokenHasher::hash(RefreshTokenHasher::successor($rotationId)),
                'previous_refresh_key' => RefreshTokenHasher::hash($rotationId),
                'refresh_rotated_at'   => $this->now,
                'last_used_at'         => $this->now,
            ],
            default => ['refresh_key' => RefreshTokenHasher::hash('another-rotation-id')],
        });

        return $this->tokens()->issueRefreshToken($session, $rotationId, $identity)->reveal();
    }
}
