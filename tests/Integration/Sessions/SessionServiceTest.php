<?php

declare(strict_types = 1);

namespace Tests\Integration\Sessions;

use Carbon\CarbonImmutable;
use Firebase\JWT\JWT;
use Illuminate\Auth\Events\Login;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Route;
use Illuminate\Testing\TestResponse;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Contracts\AdditionalFactorPolicy;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\PrincipalResolver;
use SineMacula\Laravel\Authentication\Contracts\RequirementCheck;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\Enums\RevocationReason;
use SineMacula\Laravel\Authentication\Events\Refreshed;
use SineMacula\Laravel\Authentication\Events\SessionAuthenticated;
use SineMacula\Laravel\Authentication\Events\SessionCreated;
use SineMacula\Laravel\Authentication\Events\SessionRevoked;
use SineMacula\Laravel\Authentication\Events\SignedIn;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Factors\AdditionalFactorContext;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Http\PresentedRefreshToken;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenHasher;
use SineMacula\Laravel\Authentication\Models\Session;
use SineMacula\Laravel\Authentication\Proofs\Enums\Purpose;
use SineMacula\Laravel\Authentication\Requirements\Requirement;
use SineMacula\Laravel\Authentication\Requirements\RequirementPart;
use SineMacula\Laravel\Authentication\Secrets\Secret;
use SineMacula\Laravel\Authentication\Sessions\ProvenSessions;
use SineMacula\Laravel\Authentication\Sessions\SessionEstablishment;
use SineMacula\Laravel\Authentication\Sessions\SessionService;
use SineMacula\Laravel\Authentication\Sessions\SessionSummary;
use SineMacula\Laravel\Authentication\Sessions\SessionWriter;
use SineMacula\Laravel\Authentication\Sessions\SignedInSession;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use Tests\Concerns\InteractsWithProofs;
use Tests\Concerns\InteractsWithRateLimits;
use Tests\Concerns\InteractsWithSessions;
use Tests\Fixtures\Proofs\UndescribedFirstFactor;
use Tests\Fixtures\Tenancy\ProofJudgingRequirementCheck;
use Tests\Integration\Fixtures\ActivatableTenantMembership;
use Tests\TestCase;
use Tests\Unit\Stubs\StubFixedPrincipalResolver;

/**
 * End-to-end tests for sessions the session service starts against a real
 * database.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SessionService::class)]
#[CoversClass(SessionEstablishment::class)]
#[CoversClass(SessionWriter::class)]
#[CoversClass(ProvenSessions::class)]
#[CoversClass(SignedInSession::class)]
final class SessionServiceTest extends TestCase
{
    use InteractsWithProofs, InteractsWithRateLimits, InteractsWithSessions;

    /** @var \Carbon\CarbonImmutable Frozen clock reference. */
    private CarbonImmutable $now;

    /**
     * Freeze the clocks, create the tables and add a route behind the `auth`
     * middleware.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->freezeClocksAt(CarbonImmutable::createStrict(2026, 4, 6, 12, 0, 0));

        $this->createSessionTables();

        Route::middleware('auth:api')->get('/me', static fn (): array => [
            'identity' => Auth::identity()?->getAuthIdentifier(),
            'session'  => Auth::session()?->getSessionIdentifier(),
        ]);
    }

    /**
     * Release the clocks and drop the tables.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $this->dropSessionTables();

        Carbon::setTestNow();
        CarbonImmutable::setTestNow();

        JWT::$timestamp = null;

        parent::tearDown();
    }

    /**
     * A new session's access token authenticates and its refresh token
     * refreshes.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheFirstPairAuthenticatesAndRefreshes(): void
    {
        $identity = $this->seedIdentity();
        $session  = $this->signIn();

        $this->bearer($session->tokens->accessToken->reveal())
            ->assertOk()
            ->assertJson(['identity' => $identity->getKey(), 'session' => $session->record->getKey()]);

        $refreshed = self::sessionsOf($this->freshGuard())->refresh(
            self::bodyToken($session->tokens),
            self::requestClient(),
        )->session?->tokens;

        self::assertNotNull($refreshed);
        $this->bearer($refreshed->accessToken->reveal())->assertOk();
    }

    /**
     * Signing in again with the current refresh token replaces the session as
     * `superseded`.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testSigningInAgainWithTheCurrentRefreshTokenReplacesTheSession(): void
    {
        $this->seedIdentity();

        $first = $this->signIn(clientName: 'Laptop', platform: 'macOS');

        $rotated = self::sessionsOf($this->freshGuard())->refresh(
            PresentedRefreshToken::fromBody(self::revealed($first->tokens->refreshToken)),
            self::requestClient(),
        )->session?->tokens;

        self::assertNotNull($rotated);

        $current = self::sessionsOf($this->freshGuard())->refresh(PresentedRefreshToken::fromBody(self::revealed($rotated->refreshToken)), self::requestClient())->session?->tokens;

        self::assertNotNull($current);

        $this->advance(10 * 86400);

        $this->recordEvents([SessionRevoked::class, SessionCreated::class, SignedIn::class]);

        $again = $this->signIn(refreshToken: self::revealed($current->refreshToken), clientName: 'Renamed laptop', method: 'sso');

        self::assertNotSame($first->record->getKey(), $again->record->getKey());
        self::assertSame([SessionRevoked::class, SessionCreated::class, SignedIn::class], $this->recordedClasses());
        self::assertSame(RevocationReason::SUPERSEDED, $this->recordedEvent(SessionRevoked::class)->reason);
        self::assertSame(IdentifierCoercion::stringify($first->record->getKey()), $this->recordedEvent(SessionRevoked::class)->context->sessionId);
        self::assertSame(IdentifierCoercion::stringify($again->record->getKey()), $this->recordedEvent(SessionCreated::class)->context->sessionId);
        self::assertSame(IdentifierCoercion::stringify($again->record->getKey()), $this->recordedEvent(SignedIn::class)->context->sessionId);

        $previous = Session::query()->whereKey($first->record->getKey())->firstOrFail();

        self::assertSame(Carbon::now()->getTimestamp(), $previous->getRevokedAt()?->getTimestamp());
        self::assertSame('superseded', $previous->getRevokedReason());
        self::assertNull($previous->getRefreshKey());
        self::assertNull($previous->getPreviousRefreshKey());
        self::assertSame('password', $previous->getSignInMethod());

        $record = Session::query()->whereKey($again->record->getKey())->firstOrFail();
        $claims = Auth::manager()->jwt('api')->parse(self::revealed($again->tokens->refreshToken));

        self::assertIsString($claims['jti'] ?? null);
        self::assertTrue(RefreshTokenHasher::verify($claims['jti'], (string) $record->getRefreshKey()));
        self::assertNull($record->getPreviousRefreshKey());
        self::assertNull($record->getRefreshRotatedAt());
        self::assertNull($record->getRevokedAt());
        self::assertSame(Carbon::now()->getTimestamp(), $record->getSignedInAt()?->getTimestamp());
        self::assertSame(Carbon::now()->addDays(30)->getTimestamp(), $record->getIdleExpiresAt()?->getTimestamp());
        self::assertSame(Carbon::now()->addDays(180)->getTimestamp(), $record->getAbsoluteExpiresAt()?->getTimestamp());
        self::assertSame('sso', $record->getSignInMethod());
        self::assertSame('Renamed laptop', $record->client_name);
        self::assertSame('macOS', $record->platform);
        self::assertSame('api', $record->getGuard());
        self::assertSame(self::CLIENT_IP, $record->created_ip);
        self::assertSame(Carbon::now()->getTimestamp(), $record->getLastUsedAt()?->getTimestamp());
        self::assertSame(2, Session::query()->count());

        $this->bearer($again->tokens->accessToken->reveal())->assertOk()->assertJson(['session' => $record->getKey()]);

        $refused = self::sessionsOf($this->freshGuard())->refresh(PresentedRefreshToken::fromBody(self::revealed($current->refreshToken)), self::requestClient());

        self::assertSame(FailureReason::SESSION_REVOKED, $refused->reason);
        self::assertNull(Session::query()->whereKey($record->getKey())->firstOrFail()->getRevokedAt());
        self::assertSame('superseded', Session::query()->whereKey($first->record->getKey())->firstOrFail()->getRevokedReason());
    }

    /**
     * The replaced session's tokens stop working at once.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheReplacedSessionsTokensStopWorkingAtOnce(): void
    {
        $identity = $this->seedIdentity();

        $first = $this->signIn();

        $this->bearer($first->tokens->accessToken->reveal())->assertOk()->assertJson(['session' => $first->record->getKey()]);

        $again = $this->signIn(refreshToken: $first->tokens->refreshToken?->reveal());

        $this->bearer($first->tokens->accessToken->reveal())->assertUnauthorized();
        $this->bearer($again->tokens->accessToken->reveal())->assertOk()->assertJson(['session' => $again->record->getKey()]);

        self::assertSame(
            FailureReason::SESSION_REVOKED,
            self::sessionsOf($this->freshGuard())->refresh(self::bodyToken($first->tokens), self::requestClient())->reason,
        );
        $listed = Auth::sessions('api')->sessions($identity)->items();

        self::assertSame([IdentifierCoercion::stringify($again->record->getKey())], array_map(static fn (SessionSummary $summary): string => $summary->id, $listed));

        $refreshed = self::sessionsOf($this->freshGuard())->refresh(self::bodyToken($again->tokens), self::requestClient())->session;

        self::assertSame($again->record->getKey(), $refreshed?->record->getKey());
    }

    /**
     * Signing in again without a refresh token revokes nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testSigningInAgainWithoutAProofRevokesNothing(): void
    {
        $this->seedIdentity();

        $first = $this->signIn(clientName: 'Laptop', platform: 'macOS');

        $this->recordEvents([SessionRevoked::class]);

        $again = $this->signIn(clientName: 'Laptop', platform: 'macOS');

        self::assertNotSame($first->record->getKey(), $again->record->getKey());
        self::assertSame(2, Session::query()->whereNull('revoked_at')->count());
        self::assertSame([], $this->recordedClasses());
        $this->bearer($first->tokens->accessToken->reveal())->assertOk();
        $this->bearer($again->tokens->accessToken->reveal())->assertOk();
    }

    /**
     * An expired refresh token still proves its session for replacement.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnExpiredRefreshTokenStillProvesTheSession(): void
    {
        $this->seedIdentity();

        $first = $this->signIn();

        $this->advance(200 * 86400);

        self::assertNull(self::sessionsOf($this->freshGuard())->refresh(self::bodyToken($first->tokens), self::requestClient())->session);

        $again = $this->signIn(refreshToken: $first->tokens->refreshToken?->reveal());

        self::assertNotSame($first->record->getKey(), $again->record->getKey());
        self::assertSame('superseded', Session::query()->whereKey($first->record->getKey())->firstOrFail()->getRevokedReason());
        $this->bearer($again->tokens->accessToken->reveal())->assertOk();
    }

    /**
     * A refresh token the session has rotated past proves nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARotatedRefreshTokenProvesNothing(): void
    {
        $this->seedIdentity();

        $first     = $this->signIn();
        $refreshed = self::sessionsOf($this->freshGuard())->refresh(
            self::bodyToken($first->tokens),
            self::requestClient(),
        )->session?->tokens;

        self::assertNotNull($refreshed);

        $previous = $this->signIn(refreshToken: $first->tokens->refreshToken?->reveal());

        $this->advance(3600);

        self::sessionsOf($this->freshGuard())->refresh(self::bodyToken($refreshed), self::requestClient());

        $older = $this->signIn(refreshToken: $first->tokens->refreshToken?->reveal());

        self::assertNotSame($first->record->getKey(), $previous->record->getKey());
        self::assertNotSame($first->record->getKey(), $older->record->getKey());
        self::assertSame(3, Session::query()->whereNull('revoked_at')->count());
    }

    /**
     * A revoked session is never replaced.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARevokedSessionIsNeverReplaced(): void
    {
        $this->seedIdentity();

        $first = $this->signIn();

        Session::query()->whereKey($first->record->getKey())->update(['revoked_at' => Carbon::now(), 'revoked_reason' => 'revoked']);

        $before = (array) DB::table('authentication_sessions')->where('id', $first->record->getKey())->first();

        self::assertNotSame($first->record->getKey(), $this->signIn(refreshToken: $first->tokens->refreshToken?->reveal())->record->getKey());
        self::assertSame($before, (array) DB::table('authentication_sessions')->where('id', $first->record->getKey())->first());
    }

    /**
     * A refresh token proves a session only for its own owner, guard and
     * principal.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARefreshTokenProvesASessionOnlyForItsOwnerGuardAndPrincipal(): void
    {
        $this->seedIdentity();
        $this->seedIdentity('bea@example.test');

        $ada = $this->signIn();
        $row = (array) DB::table('authentication_sessions')->where('id', $ada->record->getKey())->first();

        self::assertNotSame($ada->record->getKey(), $this->signIn('bea@example.test', refreshToken: $ada->tokens->refreshToken?->reveal())->record->getKey());
        self::assertNotSame($ada->record->getKey(), $this->signIn(guard: 'admin', refreshToken: $ada->tokens->refreshToken?->reveal())->record->getKey());
        self::assertSame($row, (array) DB::table('authentication_sessions')->where('id', $ada->record->getKey())->first());

        $admin = $this->signIn(guard: 'admin');

        Session::query()->whereKey($admin->record->getKey())->update(['guard' => 'api']);

        $this->signIn(guard: 'admin', refreshToken: $admin->tokens->refreshToken?->reveal());

        self::assertNull(Session::query()->whereKey($admin->record->getKey())->firstOrFail()->getRevokedAt());

        [$member, $first, $tenant] = $this->seedMember();

        $second  = ActivatableTenantMembership::query()->create(['identity_id' => $member->getKey(), 'tenant_id' => $tenant->getKey()]);
        $session = $this->signIn('member@example.test', guard: 'members', principal: $first);
        $other   = $this->signIn('member@example.test', guard: 'members', refreshToken: $session->tokens->refreshToken?->reveal(), principal: $second);

        self::assertNotSame($session->record->getKey(), $other->record->getKey());
        self::assertNull(Session::query()->whereKey($session->record->getKey())->firstOrFail()->getRevokedAt());

        $same = $this->signIn('member@example.test', guard: 'members', refreshToken: $session->tokens->refreshToken?->reveal(), principal: $first);

        self::assertNotSame($session->record->getKey(), $same->record->getKey());
        self::assertSame('superseded', Session::query()->whereKey($session->record->getKey())->firstOrFail()->getRevokedReason());
        self::assertNull(Session::query()->whereKey($other->record->getKey())->firstOrFail()->getRevokedAt());
    }

    /**
     * A token that is not the guard's refresh token proves nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATokenThatIsNotARefreshTokenProvesNothing(): void
    {
        $this->seedIdentity();

        $first = $this->signIn();

        $this->signIn(refreshToken: 'not-a-jwt');
        $this->signIn(refreshToken: $first->tokens->accessToken->reveal());

        self::assertSame(3, Session::query()->whereNull('revoked_at')->count());
    }

    /**
     * A proven session that changes before replacement is left alone and the
     * sign-in reconsidered.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASessionChangedBeforeItIsReplacedIsReconsideredWithoutIt(): void
    {
        $this->seedIdentity();

        $first  = $this->signIn();
        $proven = [];

        $factors = \Mockery::mock(AdditionalFactorPolicy::class);
        $factors->shouldReceive('requirementFor')->twice()->andReturnUsing(function (AdditionalFactorContext $context) use (&$proven, $first): Requirement {

            $proven[] = $context->provenSession?->getSessionIdentifier();

            if ($context->provenSession !== null) {
                Session::query()->whereKey($first->record->getKey())->update(['refresh_key' => RefreshTokenHasher::hash('rotated-in-parallel')]);
            }

            return new Requirement;
        });

        app()->instance(AdditionalFactorPolicy::class, $factors);

        $again = $this->signIn(refreshToken: $first->tokens->refreshToken?->reveal());

        self::assertSame([$first->record->getKey(), null], $proven);
        self::assertNotSame($first->record->getKey(), $again->record->getKey());
        self::assertSame('email', Session::query()->whereKey($again->record->getKey())->value('sign_in_identifier_type'));
        self::assertSame(RefreshTokenHasher::hash('rotated-in-parallel'), Session::query()->whereKey($first->record->getKey())->firstOrFail()->getRefreshKey());
        self::assertNull(Session::query()->whereKey($first->record->getKey())->firstOrFail()->getRevokedAt());
    }

    /**
     * `SessionCreated`, `SignedIn` and the bind wait for the caller's commit.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testLifecycleEventsFollowTheCallersTransaction(): void
    {
        $this->seedIdentity();

        $this->recordEvents([SessionAuthenticated::class, SessionCreated::class, SignedIn::class]);

        DB::beginTransaction();

        $this->signIn();

        self::assertSame([], $this->recordedClasses());

        DB::commit();

        self::assertSame([SessionCreated::class, SignedIn::class, SessionAuthenticated::class], $this->recordedClasses());

        $this->recordEvents([SessionAuthenticated::class, SessionCreated::class, SignedIn::class]);

        DB::beginTransaction();

        $rolledBack = $this->signIn();

        DB::rollBack();

        self::assertSame([], $this->recordedClasses());
        self::assertNull(Session::query()->whereKey($rolledBack->record->getKey())->first());
    }

    /**
     * A deferred bind skips a guard whose request was rebound before the
     * commit.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testADeferredBindLeavesAGuardWhoseRequestWasRebound(): void
    {
        $this->seedIdentity();

        $guard = $this->freshGuard();

        DB::beginTransaction();

        self::assertTrue(self::sessionsOf($guard)->signIn('password', self::credentials(), self::requestContext())->isSignedIn());

        app()->instance('request', Request::create('/elsewhere', 'GET', server: ['REMOTE_ADDR' => '198.51.100.9']));

        DB::commit();

        self::assertFalse($guard->hasUser());
        self::assertNull($guard->session());
        self::assertSame([0, 0], [self::counterHits('api', 'sign_in', 'per_identifier', 'ada@example.test'), self::counterHits('api', 'sign_in', 'per_ip', self::CLIENT_IP)]);
        self::assertSame(1, Session::query()->count());
    }

    /**
     * A failure while issuing the first pair rolls the session back.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFailureWhileIssuingRollsTheSessionBack(): void
    {
        $this->seedIdentity();

        $principal = \Mockery::mock(Principal::class);
        $principal->shouldReceive('getPrincipalIdentifier')->andReturnNull();
        $principal->shouldReceive('getTenant')->andReturnNull();

        app()->instance(PrincipalResolver::class, new StubFixedPrincipalResolver($principal));

        try {
            $this->sessions()->signIn('password', self::credentials(), self::requestContext());
            self::fail('Expected issuing to fail.');
        } catch (\InvalidArgumentException $exception) {
            self::assertStringContainsString('`principal`', $exception->getMessage());
        }

        self::assertSame(0, Session::query()->count());
    }

    /**
     * A failure after revoking a proven session rolls the revocation back.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFailureAfterRevokingAProvenSessionRollsTheRevocationBack(): void
    {
        $this->seedIdentity();

        $first   = $this->signIn();
        $key     = Session::query()->whereKey($first->record->getKey())->firstOrFail()->getRefreshKey();
        $failure = new \ArrayObject(['armed' => true]);

        DB::listen(static function (QueryExecuted $query) use ($failure): void {
            if ($failure['armed'] && str_starts_with(strtolower($query->sql), 'insert into') && str_contains($query->sql, 'authentication_sessions')) {
                throw new \RuntimeException('failed after the swap');
            }
        });

        try {
            $this->signIn(refreshToken: $first->tokens->refreshToken?->reveal());
            self::fail('Expected the sign-in to fail after the swap.');
        } catch (\RuntimeException $exception) {
            self::assertSame('failed after the swap', $exception->getMessage());
        }

        $failure['armed'] = false;
        $record           = Session::query()->whereKey($first->record->getKey())->firstOrFail();

        self::assertSame($key, $record->getRefreshKey());
        self::assertNull($record->getRevokedAt());
        self::assertSame(1, Session::query()->count());
        self::assertNotNull(
            self::sessionsOf($this->freshGuard())->refresh(self::bodyToken($first->tokens), self::requestClient())->session,
        );
        self::assertNull(Session::query()->whereKey($first->record->getKey())->firstOrFail()->getRevokedAt());
    }

    /**
     * A throwing bind listener fails the sign-in after the session is reported.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAThrowingBindListenerStillLetsTheSessionBeReported(): void
    {
        $this->seedIdentity();

        $this->throwOnLogin();

        $this->recordEvents([SessionCreated::class, SignedIn::class]);

        self::assertSame('listener failed', $this->failedSignIn());
        self::assertSame(1, Session::query()->count());
        self::assertSame([SessionCreated::class, SignedIn::class], $this->recordedClasses());
    }

    /**
     * A throwing bind listener inside the caller's transaction runs only on
     * commit.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAThrowingBindListenerInsideTheCallersTransactionFollowsItsOutcome(): void
    {
        $this->seedIdentity();

        $this->throwOnLogin();

        $this->recordEvents([SessionCreated::class, SignedIn::class]);

        DB::beginTransaction();

        self::assertTrue($this->signIn()->record->exists);
        self::assertSame([], $this->recordedClasses());

        try {
            DB::commit();

            self::fail('Expected the bind listener to throw at the commit.');
        } catch (\RuntimeException $exception) {
            self::assertSame('listener failed', $exception->getMessage());
        }

        self::assertSame([SessionCreated::class, SignedIn::class], $this->recordedClasses());
        self::assertSame(1, Session::query()->count());
        self::assertSame(0, DB::transactionLevel());

        $this->recordEvents([SessionCreated::class, SignedIn::class]);

        DB::beginTransaction();

        $this->signIn();

        DB::rollBack();

        self::assertSame([], $this->recordedClasses());
        self::assertSame(1, Session::query()->count());
    }

    /**
     * A refresh whose bind listener throws follows the caller's transaction.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAThrowingBindListenerOnARefreshFollowsTheCallersTransaction(): void
    {
        $this->seedIdentity();

        $session = $this->signIn();
        $before  = Session::query()->whereKey($session->record->getKey())->firstOrFail()->getRefreshKey();

        $this->throwOnLogin();

        $this->recordEvents([Refreshed::class, SignedIn::class]);

        DB::beginTransaction();

        self::assertTrue(
            self::sessionsOf($this->freshGuard())->refresh(self::bodyToken($session->tokens), self::requestClient())->isRefreshed(),
        );
        self::assertSame([], $this->recordedClasses());

        DB::rollBack();

        self::assertSame([], $this->recordedClasses());
        self::assertSame($before, Session::query()->whereKey($session->record->getKey())->firstOrFail()->getRefreshKey());

        DB::beginTransaction();

        self::assertTrue(
            self::sessionsOf($this->freshGuard())->refresh(self::bodyToken($session->tokens), self::requestClient())->isRefreshed(),
        );

        try {
            DB::commit();
            self::fail('Expected the bind listener to throw from the commit.');
        } catch (\RuntimeException $exception) {
            self::assertSame('listener failed', $exception->getMessage());
        }

        self::assertSame([Refreshed::class, SignedIn::class], $this->recordedClasses());
        self::assertNotSame($before, Session::query()->whereKey($session->record->getKey())->firstOrFail()->getRefreshKey());
    }

    /**
     * A crafted client name and platform are stored cleaned.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACraftedClientDescriptionIsStoredCleaned(): void
    {
        $this->seedIdentity();

        $session = $this->signIn(clientName: "Lap\0top\xFF" . str_repeat('é', 300), platform: "\0");
        $record  = Session::query()->whereKey($session->record->getKey())->firstOrFail();

        self::assertSame('Laptop?' . str_repeat('é', 248), $record->client_name);
        self::assertNull($record->platform);
    }

    /**
     * A cookie application judges a pending session's satisfaction on the
     * client given.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACookieApplicationSatisfiesAPendingSessionForTheClientGiven(): void
    {
        config()->set('auth.guards.admin.refresh_token', ['transport' => 'cookie', 'cookie' => ['path' => '/auth']]);

        $identity = $this->seedIdentity();

        $this->requireAFurtherFactor();

        $pending = self::sessionsOf($this->freshGuard('admin'))->signIn('password', self::credentials(), self::requestContext());

        self::assertNotNull($pending->pending);
        self::assertNotNull($pending->credential);

        $credential = $pending->credential->reveal();
        $proof      = self::adapterProof($identity, 'admin', $pending->pending->id, Purpose::SIGN_IN);
        $proofs     = DB::table('authentication_proofs')->count();
        $crossSite  = self::crossSiteClient();

        $this->recordEvents([AuthenticationFailed::class, SignedIn::class]);

        self::assertSame(FailureReason::CROSS_SITE_REQUEST, self::sessionsOf($this->freshGuard('admin'))->satisfy($credential, $proof, $crossSite)->reason);
        self::assertSame($crossSite, $this->recordedEvent(AuthenticationFailed::class)->context->client);
        self::assertSame(['pending'], Session::query()->pluck('status')->all());
        self::assertSame($proofs, DB::table('authentication_proofs')->count());

        $sameSite = self::sameSiteClient();

        $this->recordEvents([SignedIn::class]);

        $activated = self::sessionsOf($this->crossSiteGuard('admin'))->satisfy($credential, $proof, $sameSite);
        $record    = Session::query()->sole();

        self::assertTrue($activated->isSignedIn());
        self::assertNotNull($activated->session?->tokens->refreshCookie);
        self::assertSame($sameSite, $this->recordedEvent(SignedIn::class)->context->client);
        self::assertSame('active', $record->status);
        self::assertSame([self::PLAIN_IP, self::PLAIN_AGENT], [$record->getRawOriginal('last_used_ip'), $record->getRawOriginal('last_used_user_agent')]);
    }

    /**
     * Configure the guards.
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

        self::configureSessionGuards($app->make(ConfigRepository::class));
    }

    /**
     * Move both clocks to the time, as `travel()` moves Laravel's.
     *
     * @param  \Carbon\CarbonImmutable  $time
     * @return void
     */
    private function freezeClocksAt(CarbonImmutable $time): void
    {
        $this->now = $time;

        Carbon::setTestNow($time);
        CarbonImmutable::setTestNow($time);

        JWT::$timestamp = $time->getTimestamp();
    }

    /**
     * Move both clocks forward by the seconds.
     *
     * @param  int  $seconds
     * @return void
     */
    private function advance(int $seconds): void
    {
        $this->freezeClocksAt($this->now->addSeconds($seconds));
    }

    /**
     * Sign in through the session service and return the session.
     *
     * @param  string  $email
     * @param  string  $guard
     * @param  ?string  $refreshToken
     * @param  ?string  $clientName
     * @param  ?string  $platform
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  string  $method
     * @return \SineMacula\Laravel\Authentication\Sessions\SignedInSession
     *
     * @throws \Throwable
     */
    private function signIn(
        string $email = 'ada@example.test',
        string $guard = 'api',
        #[\SensitiveParameter] ?string $refreshToken = null,
        ?string $clientName = null,
        ?string $platform = null,
        ?Principal $principal = null,
        string $method = 'password',
    ): SignedInSession {
        $sessions = $this->sessions($guard);
        $context  = new SignInContext(new ClientContext(self::CLIENT_IP, self::CLIENT_AGENT), $clientName, $platform, $principal, $refreshToken);

        $result = $method === 'password'
            ? $sessions->signIn('password', self::credentials($email), $context)
            : $sessions->start(UndescribedFirstFactor::of($this->identity($guard, $email)), null, $method, $context);

        self::assertNotNull($result->session, 'Expected the sign-in to start a session; it failed with ' . $result->reason?->value);

        return $result->session;
    }

    /**
     * Make every `Login` listener call throw.
     *
     * @return void
     */
    private function throwOnLogin(): void
    {
        Event::listen(Login::class, static function (): never {
            throw new \RuntimeException('listener failed');
        });
    }

    /**
     * Require a further factor of every sign-in.
     *
     * @return void
     */
    private function requireAFurtherFactor(): void
    {
        app()->instance(AdditionalFactorPolicy::class, new class implements AdditionalFactorPolicy {
            /**
             * Always require a further factor.
             *
             * @param  \SineMacula\Laravel\Authentication\Factors\AdditionalFactorContext  $context
             * @return \SineMacula\Laravel\Authentication\Requirements\Requirement
             */
            #[\Override]
            public function requirementFor(AdditionalFactorContext $context): Requirement
            {
                return new Requirement(new RequirementPart);
            }
        });
        app()->instance(RequirementCheck::class, new ProofJudgingRequirementCheck);
    }

    /**
     * Sign in, expecting a listener to throw, and return its message.
     *
     * @return string
     *
     * @throws \Throwable
     */
    private function failedSignIn(): string
    {
        try {
            $this->sessions()->signIn('password', self::credentials(), self::requestContext());
        } catch (\RuntimeException $exception) {
            return $exception->getMessage();
        }

        self::fail('Expected the listener to throw.');
    }

    /**
     * Look up the identity with the email through the guard's provider.
     *
     * @param  string  $guard
     * @param  string  $email
     * @return \SineMacula\Laravel\Authentication\Contracts\Identity
     */
    private function identity(string $guard, string $email): Identity
    {
        $identity = $this->freshGuard($guard)->getProvider()->retrieveByCredentials(['email' => $email]);

        self::assertInstanceOf(Identity::class, $identity);

        return $identity;
    }

    /**
     * Send a request with the bearer token to the protected route.
     *
     * @param  string  $token
     * @return \Illuminate\Testing\TestResponse<\Symfony\Component\HttpFoundation\Response>
     */
    private function bearer(#[\SensitiveParameter] string $token): TestResponse
    {
        return $this->withHeaders(['Authorization' => 'Bearer ' . $token])->getJson('/me');
    }

    /**
     * The secret in clear, which must be there.
     *
     * @param  ?\SineMacula\Laravel\Authentication\Secrets\Secret  $secret
     * @return string
     */
    private static function revealed(?Secret $secret): string
    {
        self::assertNotNull($secret);

        return $secret->reveal();
    }
}
