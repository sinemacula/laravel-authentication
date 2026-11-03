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
 * Query-budget contracts for the refresh-token exchange hot paths.
 *
 * Every refresh first reads its session's and its IP address's refresh limits
 * in one query. A failed refresh then counts the failure against both: on a
 * fresh window, for each counter, an update that changes nothing and the insert
 * that creates it, so four writes. A successful refresh writes nothing to the
 * limits.
 *
 * Every refresh that finds its session then writes the session's issuance
 * guard, one `UPDATE` by key, first in the transaction the exchange runs in, so
 * the access token it issues reads the session's proofs after any issuance or
 * proof change of the session that overlaps it, and takes its time after it:
 * one write more on every path past the session lookup, whatever it decides.
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
     * Refresh success should read its limits, do the session lookup and
     * authenticatable hydration and read the session's proofs for the new
     * access token's `auth_time` and `amr`, then the issuance guard and one CAS
     * write. The timestamp write is suppressed here by seeding `last_used_at`
     * inside the throttle window.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testRefreshSuccessUsesFourReadsAndTwoWrites(): void
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

        $result = $this->assertQueryBudget(4, 2, static fn () => GuardSessions::of($guard)->refresh($token)->session?->tokens);

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

        self::assertTrue($this->assertQueryBudget(4, 2, static fn () => GuardSessions::of($guard)->refreshFromRequest())?->isRefreshed());
    }

    /**
     * Reading the token from the refresh cookie, with its same-site checks and
     * its count of the request's cookies, and delivering the new refresh token
     * in the cookie, add no query either.
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

        $result = $this->assertQueryBudget(4, 2, static fn () => GuardSessions::of($guard)->refreshFromRequest());

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

        self::assertSame(FailureReason::CROSS_SITE_REQUEST, $this->assertQueryBudget(0, 0, static fn () => GuardSessions::of($guard)->refreshFromRequest())?->reason);
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

        self::assertSame(FailureReason::REFRESH_TOKEN_CONFLICT, $this->assertQueryBudget(0, 0, static fn () => GuardSessions::of($guard)->refreshFromRequest())?->reason);
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

        $result = $this->assertQueryBudget(2, 4, static fn () => GuardSessions::of($guard)->refresh($token)->session?->tokens);

        self::assertNull($result);
    }

    /**
     * A session id that cannot be a key of the session model is rejected before
     * the session lookup, so the failure costs only the limits' read and its
     * count.
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

        $result = $this->assertQueryBudget(1, 4, static fn () => GuardSessions::of($guard)->refresh($token)->session?->tokens);

        self::assertNull($result);
    }

    /**
     * A replayed refresh token is judged from the session row alone, before the
     * owner is loaded, and costs the session read plus the issuance guard and
     * the one guarded revocation write, besides the limits' read and the
     * failure's count.
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

        self::assertNull($this->assertQueryBudget(2, 6, static fn () => GuardSessions::of($guard)->refresh($token))->session);
        self::assertSame('rotation_reuse', Session::query()->whereKey($session->getKey())->firstOrFail()->getRevokedReason());
    }

    /**
     * A grace retry is answered from the limits, the session row, the owner and
     * the session's proofs, writing nothing but the issuance guard: the current
     * credential is re-issued, not rotated again.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testGraceRetryUsesFourReadsAndWritesOnlyTheIssuanceGuard(): void
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

        self::assertNotNull($this->assertQueryBudget(4, 1, static fn () => GuardSessions::of($guard)->refresh($token))->session);
    }

    /**
     * A refresh that loses its swap to a parallel refresh with the same token
     * pays the limits, session and owner reads, the issuance guard, the proofs
     * read of the pair it issued, the missed swap, and one locking re-read of
     * the session, then succeeds as a grace retry, reading the proofs again for
     * its pair.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testLostRotationResolvedAsAGraceRetryUsesSixReadsAndTwoWrites(): void
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

            // The winning request's rotation, written past the query log so
            // only this request's own queries count against its budget.
            DB::connection()->getPdo()
                ->prepare('update authentication_sessions set refresh_key = ?, previous_refresh_key = ?, refresh_rotated_at = ? where id = ?')
                ->execute([
                    RefreshTokenHasher::hash(RefreshTokenHasher::successor('raced-rotation-id')),
                    RefreshTokenHasher::hash('raced-rotation-id'),
                    $this->now->format('Y-m-d H:i:s'),
                    $session->getKey(),
                ]);
        });

        self::assertNotNull($this->assertQueryBudget(6, 2, static fn () => GuardSessions::of($guard)->refresh($token))->session);
    }

    /**
     * A refresh for a session that holds no refresh credential stops at the
     * session lookup and writes nothing but the issuance guard and the
     * failure's count.
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

        self::assertNull($this->assertQueryBudget(2, 5, static fn () => GuardSessions::of($guard)->refresh($token))->session);
        self::assertSame([[FailureReason::REFRESH_KEY_MISSING, $session->getKey()]], self::failures($events));
    }

    /**
     * A refresh replaying a token against a session already revoked for reuse
     * stops at the session lookup: it revokes nothing again, and writes nothing
     * but the issuance guard and the failure's count.
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

        self::assertNull($this->assertQueryBudget(2, 5, static fn () => GuardSessions::of($guard)->refresh($token))->session);
        self::assertSame([[FailureReason::SESSION_REVOKED, $session->getKey()]], self::failures($events));
    }

    /**
     * The grace and replay paths cost no more than a rotation: each compares at
     * most two digests and derives one successor, with no loop over past
     * rotations. Measured as the fastest of several runs of each path against
     * the fastest rotation, with a generous factor for noise.
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
                $result  = GuardSessions::of($guard)->refresh($token)->session?->tokens;
                $elapsed = hrtime(true) - $started;

                self::assertSame($path !== 'replay', $result !== null, $path);

                $fastest[$path] = min($fastest[$path], $elapsed);
            }
        }

        self::assertLessThan(self::TIMING_FACTOR * $fastest['current'], $fastest['grace']);
        self::assertLessThan(self::TIMING_FACTOR * $fastest['current'], $fastest['replay']);
    }

    /**
     * A refresh for a session that has ended stops at the session lookup: the
     * deadlines are read from the loaded row, and nothing but the issuance
     * guard and the failure's count is written.
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

        self::assertNull($this->assertQueryBudget(2, 5, static fn () => GuardSessions::of($guard)->refresh($token))->session);
        self::assertSame([[FailureReason::SESSION_EXPIRED, $session->getKey()]], self::failures($events));
    }

    /**
     * A refresh for a session of another guard is refused from the session row,
     * before the owner is loaded or its issuance guard written: the limits'
     * read, the session read, and the failure's count.
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

        self::assertNull($this->assertQueryBudget(2, 4, static fn () => GuardSessions::of($guard)->refresh($token))->session);
        self::assertSame([[FailureReason::SESSION_GUARD_MISMATCH, $session->getKey()]], self::failures($events));
    }

    /**
     * A refresh whose session began with a method the guard no longer allows is
     * refused once the owner is loaded, before any rotation write: only the
     * issuance guard and the failure's count are written.
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

        self::assertNull($this->assertQueryBudget(3, 5, static fn () => GuardSessions::of($guard)->refresh($token))->session);
        self::assertSame([[FailureReason::METHOD_NOT_ALLOWED, $session->getKey()]], self::failures($events));
    }

    /**
     * A refresh for a principal the application no longer admits is refused
     * once the owner is loaded, before any rotation write: only the issuance
     * guard and the failure's count are written.
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

        self::assertNull($this->assertQueryBudget(3, 5, static fn () => GuardSessions::of($guard)->refresh($token))->session);
        self::assertSame([[FailureReason::PRINCIPAL_INELIGIBLE, $session->getKey()]], self::failures($events));
    }

    /**
     * A refresh for a session that has used up its failures is refused from the
     * limits' read alone, with its wait and nothing written, so a flood of them
     * never reaches the session.
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
        $result   = $this->assertQueryBudget(1, 0, static fn (): RefreshResult => $sessions->refresh($token));

        self::assertSame(FailureReason::RATE_LIMITED, $result->reason);
        self::assertCount(1, $events);
        self::assertSame(FailureReason::RATE_LIMITED, $events[0]->reason ?? null);
    }

    /**
     * Tenant-aware 3D refresh success should pay exactly the limits' read, the
     * session read, the authenticatable read, the joined principal+tenant read,
     * the read of the session's proofs for the new access token's `auth_time`
     * and `amr`, and two writes: the issuance guard and the rotation.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testThreeDimensionalRefreshPathWithTenantAccessUsesFiveReadsAndTwoWrites(): void
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

        $result = $this->assertQueryBudget(5, 2, static function () use ($guard, $token): ?TokenPair {
            $tokens = GuardSessions::of($guard)->refresh($token)->session?->tokens;
            $guard->principal()?->getIdentity();
            $guard->tenant();

            return $tokens;
        });

        self::assertNotNull($result);
    }

    /**
     * A tenant-aware refresh for a secondary tenant hint should still pay the
     * same limits + session + identity + joined principal + proofs read budget
     * as the primary tenant path, and the same two writes.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testThreeDimensionalRefreshPathWithSecondaryTenantHintUsesFiveReadsAndTwoWrites(): void
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

        $result = $this->assertQueryBudget(5, 2, static function () use ($guard, $token): ?TokenPair {
            $tokens = GuardSessions::of($guard)->refresh($token)->session?->tokens;
            $guard->principal()?->getIdentity();
            $guard->tenant();

            return $tokens;
        });

        self::assertNotNull($result);
        self::assertSame($secondaryPrincipal->getPrincipalIdentifier(), $guard->principal()?->getPrincipalIdentifier());
        self::assertSame($secondaryPrincipal->getTenant()?->getTenantIdentifier(), $guard->tenant()?->getTenantIdentifier());
    }

    /**
     * Rows of `[requirement, reason, writes]`: a tenant policy the session no
     * longer meets, why the refresh is refused (`null` for a return to
     * pending), and what it writes.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Authentication\Tenancy\TenantRequirement, 1: ?\SineMacula\Laravel\Authentication\Events\Enums\FailureReason, 2: int}>
     */
    public static function provideTenantPoliciesTheSessionFallsShortOf(): iterable
    {
        yield 'a further factor' => [new TenantRequirement('v2', new Requirement(new RequirementPart)), null, 2];
        yield 'a connection' => [new TenantRequirement('v2', connections: ['conn-a']), FailureReason::SSO_REQUIRED, 6];
    }

    /**
     * A 3D refresh that falls short of its tenant's policy reads what a
     * rotation reads up to the principal and tenant, then the one proof or
     * provenance row the policy is judged on instead of the proofs a new access
     * token needs (a return to pending judges the identity's own requirement on
     * that same first factor and names it, reading it no more), and writes the
     * issuance guard and one update: the return to pending, which counts no
     * failure, or the revocation, then the refusal's count.
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
        $result = $this->assertQueryBudget(5, $writes, static fn (): RefreshResult => GuardSessions::of($guard)->refresh($token));

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
        yield 'met by the accepted evidence' => [true, 7];
        yield 'not met by it' => [false, 6];
    }

    /**
     * A 3D refresh of a session an external provider established, under a
     * tenant that requires a further factor, reads what a rotation reads up to
     * the principal and tenant, the first factor, then the session's accepted
     * evidence in one more read: met, it rotates and reads the proofs for the
     * new access token; not met, it returns the session to pending. Either way
     * it writes the issuance guard and one update.
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
        $result = $this->assertQueryBudget($reads, 2, static fn (): RefreshResult => GuardSessions::of($guard)->refresh($token));

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

        $result = $this->assertQueryBudget(4, 5, static function () use ($guard, $token): ?TokenPair {
            $tokens = GuardSessions::of($guard)->refresh($token)->session?->tokens;
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
