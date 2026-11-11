<?php

declare(strict_types = 1);

namespace Tests\Integration\Guards;

use Carbon\Carbon;
use Firebase\JWT\JWT;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Route;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversTrait;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Admission\ActivationPolicy;
use SineMacula\Laravel\Authentication\AuthManager;
use SineMacula\Laravel\Authentication\Contracts\PrincipalResolver;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Guards\Concerns\VerifiesPinnedContext;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Http\PresentedRefreshToken;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenService;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenExchange;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenHasher;
use SineMacula\Laravel\Authentication\Models\Session;
use SineMacula\Laravel\Authentication\Providers\ModelProvider;
use SineMacula\Laravel\Authentication\Resolvers\DefaultPrincipalResolver;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use Tests\Concerns\InteractsWithLaggingReplica;
use Tests\Concerns\InteractsWithSessionRecords;
use Tests\Fixtures\Sessions\GuardSessions;
use Tests\Integration\Fixtures\ActivatableTenant;
use Tests\Integration\Fixtures\ActivatableTenantMember;
use Tests\Integration\Fixtures\ActivatableTenantMembership;
use Tests\Integration\Fixtures\Coexist3dIdentity;
use Tests\Integration\Fixtures\Coexist3dPrincipal;
use Tests\Integration\Fixtures\EagerRevocationLogSession;
use Tests\Integration\Fixtures\OriginLogSession;
use Tests\Integration\Fixtures\RevocationLogIdentity;
use Tests\Integration\Fixtures\RevocationLogSession;
use Tests\Integration\Fixtures\SuspendableUser;
use Tests\Integration\Fixtures\TenantAware3dIdentity;
use Tests\Integration\Fixtures\TenantAware3dPrincipal;
use Tests\Integration\Fixtures\TenantAware3dTenant;
use Tests\TestCase;
use Tests\Unit\Stubs\StubPrincipal;

/**
 * Every read deciding authentication goes to the write connection, over a split
 * whose replica lags behind the primary.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(JwtGuard::class)]
#[CoversClass(JwtTokenService::class)]
#[CoversClass(RefreshTokenExchange::class)]
#[CoversClass(ModelProvider::class)]
#[CoversClass(DefaultPrincipalResolver::class)]
#[CoversClass(ActivationPolicy::class)]
#[CoversTrait(VerifiesPinnedContext::class)]
final class JwtGuardWriteConnectionIntegrationTest extends TestCase
{
    use InteractsWithLaggingReplica, InteractsWithSessionRecords;

    /** @var string Plaintext rotation id stored on the seeded session. */
    private const string ROTATION_ID = 'stored-rotation-id';

    /** @var string Plaintext password of the seeded identity. */
    private const string PASSWORD = 'correct horse battery staple';

    /**
     * Freeze the clocks and create the identity and principal tables on the
     * primary and the replica.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $now = Carbon::createStrict(2026, 4, 6, 12, 0, 0);

        Carbon::setTestNow($now);

        JWT::$timestamp = $now->getTimestamp();

        $this->createOnPrimaryAndReplica('stub_principals', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('email')->unique();
            $blueprint->string('password');
            $blueprint->boolean('is_active')->default(true);
            $blueprint->timestamps();
        });

        $this->createOnPrimaryAndReplica('coexist_3d_identities', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('email')->unique();
            $blueprint->string('password');
            $blueprint->boolean('is_active')->default(true);
            $blueprint->timestamps();
        });

        $this->createOnPrimaryAndReplica('coexist_3d_principals', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->unsignedInteger('identity_id');
            $blueprint->string('name');
            $blueprint->boolean('is_active')->default(true);
            $blueprint->timestamps();
        });

        $this->createTenantAwareTables();
        $this->createActivatableTenantTables();
    }

    /**
     * Release the frozen clocks and remove the temporary database files.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Carbon::setTestNow();

        JWT::$timestamp = null;

        parent::tearDown();

        $this->removeLaggingReplicaFiles();
    }

    /**
     * A bearer token for an identity and session only on the primary
     * authenticates.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testBearerReadsIdentityAndSessionFromTheWriteConnection(): void
    {
        $identity = $this->seedIdentity();
        $session  = $this->seedSession($identity);

        $token = $this->authManager()->jwt('api')->issueAccessToken($identity, $identity, null, $session)->reveal();

        $guard = $this->guardForRequest(Request::create('/me', 'GET', server: ['HTTP_AUTHORIZATION' => 'Bearer ' . $token]));

        self::assertTrue($identity->is($guard->user()));
        self::assertSame($session->getKey(), $guard->session()?->getSessionIdentifier());
    }

    /**
     * A session revoked on the primary rejects the bearer token.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testBearerRejectsSessionRevokedOnThePrimaryWhileTheReplicaLags(): void
    {
        $identity = $this->seedIdentity();
        $session  = $this->seedSession($identity);

        $this->copyRowToReplica('stub_principals', $identity->getKey());
        $this->copyRowToReplica('authentication_sessions', $session->getKey());

        Session::query()->whereKey($session->getKey())->update(['revoked_at' => Carbon::now()]);

        $token = $this->authManager()->jwt('api')->issueAccessToken($identity, $identity, null, $session)->reveal();

        $guard = $this->guardForRequest(Request::create('/me', 'GET', server: ['HTTP_AUTHORIZATION' => 'Bearer ' . $token]));

        self::assertNull($guard->user());
    }

    /**
     * A session that ended on the primary rejects the bearer token.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testBearerRejectsSessionThatEndedOnThePrimaryWhileTheReplicaLags(): void
    {
        $identity = $this->seedIdentity();
        $session  = $this->seedSession($identity);

        $this->copyRowToReplica('stub_principals', $identity->getKey());
        $this->copyRowToReplica('authentication_sessions', $session->getKey());

        $token = $this->authManager()->jwt('api')->issueAccessToken($identity, $identity, null, $session)->reveal();

        Session::query()->whereKey($session->getKey())->update(['idle_expires_at' => Carbon::now()]);

        $guard = $this->guardForRequest(Request::create('/me', 'GET', server: ['HTTP_AUTHORIZATION' => 'Bearer ' . $token]));

        self::assertNull($guard->user());
    }

    /**
     * A retry of the previous rotation id is recognised from the primary and
     * does not rotate.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testGraceRetryIsJudgedFromThePrimaryWhileTheReplicaLags(): void
    {
        $identity = $this->seedIdentity();
        $session  = $this->seedSession($identity);

        $session->forceFill(['last_used_at' => Carbon::now()])->save();

        $this->copyRowToReplica('stub_principals', $identity->getKey());
        $this->copyRowToReplica('authentication_sessions', $session->getKey());

        $this->rotateOnThePrimary($session, Carbon::now()->subSeconds(5));

        $refreshToken = $this->authManager()->jwt('api')->issueRefreshToken($session, self::ROTATION_ID, $identity)->reveal();
        $updates      = $this->recordUpdates();

        $pair = GuardSessions::of($this->guardForRequest(Request::create('/refresh', 'POST')))->refresh(
            PresentedRefreshToken::fromBody($refreshToken),
            self::requestClient(),
        )->session?->tokens;

        self::assertNotNull($pair);
        self::assertSame(RefreshTokenHasher::successor(self::ROTATION_ID), $this->authManager()->jwt('api')->parse(self::bodyRefreshToken($pair))['jti'] ?? null);
        self::assertCount(1, $updates);
        self::assertStringContainsString('issuance_sequence', $updates->getArrayCopy()[0]);
    }

    /**
     * A replay is recognised from the primary and revokes the session without
     * rotating.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testReplayIsJudgedFromThePrimaryWhileTheReplicaLags(): void
    {
        $identity = $this->seedIdentity();
        $session  = $this->seedSession($identity);

        $this->copyRowToReplica('stub_principals', $identity->getKey());
        $this->copyRowToReplica('authentication_sessions', $session->getKey());

        $this->rotateOnThePrimary($session, Carbon::now()->subHour());

        $refreshToken = $this->authManager()->jwt('api')->issueRefreshToken($session, self::ROTATION_ID, $identity)->reveal();
        $updates      = $this->recordUpdates();

        self::assertNull(
            GuardSessions::of($this->guardForRequest(Request::create('/refresh', 'POST')))->refresh(PresentedRefreshToken::fromBody($refreshToken), self::requestClient())->session,
        );
        self::assertCount(2, $updates);
        self::assertStringContainsString('issuance_sequence', $updates->getArrayCopy()[0]);
        self::assertStringContainsString('revoked_reason', $updates->getArrayCopy()[1]);
        self::assertSame('rotation_reuse', DB::connection(self::PRIMARY_CONNECTION)->table('authentication_sessions')->where('id', $session->getKey())->value('revoked_reason'));
    }

    /**
     * A session pinned on `attempt()` and revoked on the primary fails the
     * attempt.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAttemptRejectsPinnedSessionRevokedOnThePrimaryWhileTheReplicaLags(): void
    {
        $identity = $this->seedIdentity();
        $session  = $this->seedSession($identity);

        $identity->forceFill(['password' => app(Hasher::class)->make(self::PASSWORD)])->save();

        $this->copyRowToReplica('stub_principals', $identity->getKey());
        $this->copyRowToReplica('authentication_sessions', $session->getKey());

        $credentials = ['email' => 'writer@example.test', 'password' => self::PASSWORD];

        self::assertTrue($this->guardForRequest(Request::create('/sign-in', 'POST'))->attempt($credentials, null, $session));

        Session::query()->whereKey($session->getKey())->update(['revoked_at' => Carbon::now()]);

        $guard = $this->guardForRequest(Request::create('/sign-in', 'POST'));

        self::assertFalse($guard->attempt($credentials, null, $session));
        self::assertFalse($guard->hasUser());
    }

    /**
     * A revocation derived from another table is read inside the session
     * lookup's write-connection pin.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testBearerRejectsSessionWhoseRevocationIsRecordedOnThePrimaryWhileTheReplicaLags(): void
    {
        [$identity, $session] = $this->seedRevocationLogSession();

        $token   = $this->authManager()->jwt('revocation_log')->issueAccessToken($identity, $identity, null, $session)->reveal();
        $request = Request::create('/me', 'GET', server: ['HTTP_AUTHORIZATION' => 'Bearer ' . $token]);

        self::assertTrue($identity->is($this->guardForRequest($request, 'revocation_log')->user()));

        $this->recordRevocation($session);

        self::assertNull($this->guardForRequest($request, 'revocation_log')->user());
    }

    /**
     * An end derived from another table is read inside the session lookup's
     * write-connection pin.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testBearerRejectsSessionWhoseEndIsRecordedOnThePrimaryWhileTheReplicaLags(): void
    {
        [$identity, $session] = $this->seedRevocationLogSession();

        $token   = $this->authManager()->jwt('revocation_log')->issueAccessToken($identity, $identity, null, $session)->reveal();
        $request = Request::create('/me', 'GET', server: ['HTTP_AUTHORIZATION' => 'Bearer ' . $token]);

        self::assertTrue($identity->is($this->guardForRequest($request, 'revocation_log')->user()));

        $this->recordSessionEnd($session);

        self::assertNull($this->guardForRequest($request, 'revocation_log')->user());
    }

    /**
     * A pinned session whose derived end is on the primary only fails the
     * attempt.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAttemptRejectsPinnedSessionWhoseEndIsRecordedOnThePrimaryWhileTheReplicaLags(): void
    {
        [$identity, $session] = $this->seedRevocationLogSession();

        $identity->forceFill(['password' => app(Hasher::class)->make(self::PASSWORD)])->save();

        $credentials = ['email' => 'revocation-log@example.test', 'password' => self::PASSWORD];

        self::assertTrue($this->guardForRequest(Request::create('/sign-in', 'POST'), 'revocation_log')->attempt($credentials, null, $session));

        $this->recordSessionEnd($session);

        $guard = $this->guardForRequest(Request::create('/sign-in', 'POST'), 'revocation_log');

        self::assertFalse($guard->attempt($credentials, null, $session));
        self::assertFalse($guard->hasUser());
    }

    /**
     * Refresh of a session whose derived end is on the primary only fails with
     * `session_expired`.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testRefreshRejectsSessionWhoseEndIsRecordedOnThePrimaryWhileTheReplicaLags(): void
    {
        app(ConfigRepository::class)->set('authentication.session.model', RevocationLogSession::class);

        [$identity, $session] = $this->seedRevocationLogSession();

        $refreshToken = $this->authManager()->jwt('revocation_log')->issueRefreshToken($session, self::ROTATION_ID, $identity)->reveal();

        $this->recordSessionEnd($session);

        $reasons = [];

        Event::listen(AuthenticationFailed::class, static function (AuthenticationFailed $event) use (&$reasons): void {
            $reasons[] = $event->reason;
        });

        self::assertNull(
            GuardSessions::of(
                $this->guardForRequest(Request::create('/refresh', 'POST'), 'revocation_log'),
            )->refresh(PresentedRefreshToken::fromBody($refreshToken), self::requestClient())->session,
        );
        self::assertSame([FailureReason::SESSION_EXPIRED], $reasons);
    }

    /**
     * A rotated pair is capped at the session end the primary records.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testRotationCapsTheIssuedPairAtTheSessionEndRecordedOnThePrimary(): void
    {
        app(ConfigRepository::class)->set('authentication.session.model', RevocationLogSession::class);

        [$identity, $session] = $this->seedRevocationLogSession();

        $refreshToken = $this->authManager()->jwt('revocation_log')->issueRefreshToken($session, self::ROTATION_ID, $identity)->reveal();
        $sessionEnd   = Carbon::now()->addMinutes(3);

        $this->recordSessionEnd($session, $sessionEnd);
        $this->recordSessionEnd($session, Carbon::now()->subHour(), self::REPLICA_CONNECTION);

        $pair = GuardSessions::of(
            $this->guardForRequest(Request::create('/refresh', 'POST'), 'revocation_log'),
        )->refresh(PresentedRefreshToken::fromBody($refreshToken), self::requestClient())->session?->tokens;
        $tokens = $this->authManager()->jwt('revocation_log');
        $stored = DB::connection(self::PRIMARY_CONNECTION)->table('authentication_sessions')->where('id', $session->getKey())->value('refresh_key');

        self::assertNotNull($pair);
        self::assertSame($sessionEnd->getTimestamp(), $tokens->parse($pair->accessToken->reveal())['exp'] ?? null);
        self::assertSame($sessionEnd->getTimestamp(), $tokens->parse(self::bodyRefreshToken($pair))['exp'] ?? null);
        self::assertSame(RefreshTokenHasher::hash(RefreshTokenHasher::successor(self::ROTATION_ID)), $stored);
    }

    /**
     * A grace retry's pair is capped at the session end the primary records.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testGraceRetryCapsTheIssuedPairAtTheSessionEndRecordedOnThePrimary(): void
    {
        app(ConfigRepository::class)->set('authentication.session.model', RevocationLogSession::class);

        [$identity, $session] = $this->seedRevocationLogSession();

        $this->rotateOnThePrimary($session, Carbon::now()->subSeconds(5));

        $refreshToken = $this->authManager()->jwt('revocation_log')->issueRefreshToken($session, self::ROTATION_ID, $identity)->reveal();
        $sessionEnd   = Carbon::now()->addMinute();

        $this->recordSessionEnd($session, $sessionEnd);

        $pair = GuardSessions::of(
            $this->guardForRequest(Request::create('/refresh', 'POST'), 'revocation_log'),
        )->refresh(PresentedRefreshToken::fromBody($refreshToken), self::requestClient())->session?->tokens;
        $tokens = $this->authManager()->jwt('revocation_log');

        self::assertNotNull($pair);
        self::assertSame($sessionEnd->getTimestamp(), $tokens->parse($pair->accessToken->reveal())['exp'] ?? null);
        self::assertSame($sessionEnd->getTimestamp(), $tokens->parse(self::bodyRefreshToken($pair))['exp'] ?? null);
        self::assertSame(RefreshTokenHasher::successor(self::ROTATION_ID), $tokens->parse(self::bodyRefreshToken($pair))['jti'] ?? null);
    }

    /**
     * Sign-in tokens are capped at the session end the primary records.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testIssuanceCapsTokensAtTheSessionEndRecordedOnThePrimary(): void
    {
        [$identity, $session] = $this->seedRevocationLogSession();

        $sessionEnd = Carbon::now()->addMinute();

        $this->recordSessionEnd($session, $sessionEnd);

        $tokens = $this->authManager()->jwt('revocation_log');

        self::assertSame($sessionEnd->getTimestamp(), $tokens->parse($tokens->issueAccessToken($identity, $identity, null, $session)->reveal())['exp'] ?? null);
        self::assertSame($sessionEnd->getTimestamp(), $tokens->parse($tokens->issueRefreshToken($session, self::ROTATION_ID, $identity)->reveal())['exp'] ?? null);
    }

    /**
     * Session models that derive their revocation from `session_revocations`.
     *
     * @return iterable<string, array{0: class-string<\SineMacula\Laravel\Authentication\Models\Session>}>
     */
    public static function provideRevocationLogSessionModels(): iterable
    {
        yield from [
            'read of its own'       => [RevocationLogSession::class],
            'eager-loaded relation' => [EagerRevocationLogSession::class],
        ];
    }

    /**
     * Refresh of a session whose derived revocation is on the primary only
     * fails with `session_revoked`.
     *
     * @param  class-string<\SineMacula\Laravel\Authentication\Models\Session>  $model
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[DataProvider('provideRevocationLogSessionModels')]
    public function testRefreshRejectsSessionWhoseRevocationIsRecordedOnThePrimaryWhileTheReplicaLags(string $model): void
    {
        app(ConfigRepository::class)->set('authentication.session.model', $model);

        [$identity, $session] = $this->seedRevocationLogSession($model);

        $refreshToken = $this->authManager()->jwt('revocation_log')->issueRefreshToken($session, self::ROTATION_ID, $identity)->reveal();

        $this->recordRevocation($session);

        $reasons = [];

        Event::listen(AuthenticationFailed::class, static function (AuthenticationFailed $event) use (&$reasons): void {
            $reasons[] = $event->reason;
        });

        self::assertNull(
            GuardSessions::of(
                $this->guardForRequest(Request::create('/refresh', 'POST'), 'revocation_log'),
            )->refresh(PresentedRefreshToken::fromBody($refreshToken), self::requestClient())->session,
        );
        self::assertSame([FailureReason::SESSION_REVOKED], $reasons);
    }

    /**
     * A refresh that loses its compare-and-swap re-judges the session from the
     * primary.
     *
     * @param  class-string<\SineMacula\Laravel\Authentication\Models\Session>  $model
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[DataProvider('provideRevocationLogSessionModels')]
    public function testLostRotationIsJudgedFromThePrimaryWhileTheReplicaLags(string $model): void
    {
        app(ConfigRepository::class)->set('authentication.session.model', $model);

        [$identity, $session] = $this->seedRevocationLogSession($model);

        $refreshToken = $this->authManager()->jwt('revocation_log')->issueRefreshToken($session, self::ROTATION_ID, $identity)->reveal();
        $raced        = false;

        DB::connection()->beforeExecuting(function (string $query) use (&$raced, $session): void {
            if ($raced || !str_starts_with(strtolower($query), 'update') || !str_contains($query, 'refresh_rotated_at')) {
                return;
            }

            $raced = true;

            $this->rotateOnThePrimary($session, Carbon::now());
            $this->recordRevocation($session);
        });

        $reasons = [];

        Event::listen(AuthenticationFailed::class, static function (AuthenticationFailed $event) use (&$reasons): void {
            $reasons[] = $event->reason;
        });

        self::assertNull(
            GuardSessions::of(
                $this->guardForRequest(Request::create('/refresh', 'POST'), 'revocation_log'),
            )->refresh(PresentedRefreshToken::fromBody($refreshToken), self::requestClient())->session,
        );
        self::assertTrue($raced);
        self::assertSame([FailureReason::SESSION_REVOKED], $reasons);
    }

    /**
     * Origins the primary records that the guard refuses, with the refusal.
     *
     * @return iterable<string, array{0: array{guard: string, sign_in_method: string}, 1: \SineMacula\Laravel\Authentication\Events\Enums\FailureReason}>
     */
    public static function provideOriginsRecordedOnThePrimary(): iterable
    {
        yield from [
            'another guard'       => [['guard' => 'admin', 'sign_in_method' => 'password'], FailureReason::SESSION_GUARD_MISMATCH],
            'a disallowed method' => [['guard' => 'api', 'sign_in_method' => 'disabled'], FailureReason::METHOD_NOT_ALLOWED],
        ];
    }

    /**
     * Refresh is refused for a derived origin the primary records.
     *
     * @param  array{guard: string, sign_in_method: string}  $origin
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\FailureReason  $reason
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[DataProvider('provideOriginsRecordedOnThePrimary')]
    public function testRefreshJudgesTheOriginRecordedOnThePrimaryWhileTheReplicaLags(array $origin, FailureReason $reason): void
    {
        app(ConfigRepository::class)->set('authentication.session.model', OriginLogSession::class);

        $this->createOnPrimaryAndReplica('session_origins', static function (Blueprint $blueprint): void {
            $blueprint->uuid('session_id');
            $blueprint->string('guard');
            $blueprint->string('sign_in_method');
        });

        $identity = $this->seedIdentity();
        $session  = $this->seedSession($identity, OriginLogSession::class);

        DB::connection(self::REPLICA_CONNECTION)->table('session_origins')->insert(['session_id' => $session->getKey(), 'guard' => 'api', 'sign_in_method' => 'password']);
        DB::connection(self::PRIMARY_CONNECTION)->table('session_origins')->insert(['session_id' => $session->getKey(), ...$origin]);

        $refreshToken = $this->authManager()->jwt('api')->issueRefreshToken($session, self::ROTATION_ID, $identity)->reveal();
        $reasons      = [];

        Event::listen(AuthenticationFailed::class, static function (AuthenticationFailed $event) use (&$reasons): void {
            $reasons[] = $event->reason;
        });

        self::assertNull(
            GuardSessions::of($this->guardForRequest(Request::create('/refresh', 'POST')))->refresh(PresentedRefreshToken::fromBody($refreshToken), self::requestClient())->session,
        );
        self::assertSame([$reason], $reasons);
        $stored = DB::connection(self::PRIMARY_CONNECTION)->table('authentication_sessions')->where('id', $session->getKey())->value('refresh_key');

        self::assertSame(RefreshTokenHasher::hash(self::ROTATION_ID), $stored);
    }

    /**
     * A refresh for a session whose digest exists only on the primary rotates.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testRefreshReadsSessionAndIdentityFromTheWriteConnection(): void
    {
        $identity = $this->seedIdentity();
        $session  = $this->seedSession($identity);

        $refreshToken = $this->authManager()->jwt('api')->issueRefreshToken($session, self::ROTATION_ID, $identity)->reveal();

        $guard = $this->guardForRequest(Request::create('/refresh', 'POST'));

        self::assertNotNull(GuardSessions::of($guard)->refresh(PresentedRefreshToken::fromBody($refreshToken), self::requestClient($guard->getRequest()))->session);
        self::assertTrue($identity->is($guard->user()));
    }

    /**
     * A tenant deactivated on the primary rejects its members' bearer tokens.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testBearerRejectsMemberOfTenantDeactivatedOnThePrimaryWhileTheReplicaLags(): void
    {
        $tenant = new ActivatableTenant;
        $tenant->forceFill(['name' => 'Tenant', 'is_active' => true])->save();

        $member = new ActivatableTenantMember;
        $member->forceFill(['email' => 'member@example.test', 'password' => 'hashed'])->save();

        $membership = new ActivatableTenantMembership;
        $membership->forceFill(['identity_id' => $member->getKey(), 'tenant_id' => $tenant->getKey()])->save();

        $this->copyRowToReplica('activatable_tenants', $tenant->getKey());
        $this->copyRowToReplica('activatable_tenant_members', $member->getKey());
        $this->copyRowToReplica('activatable_tenant_memberships', $membership->getKey());

        $token   = $this->authManager()->jwt('members')->issueAccessToken($member, $membership, null, null)->reveal();
        $request = Request::create('/me', 'GET', server: ['HTTP_AUTHORIZATION' => 'Bearer ' . $token]);

        self::assertTrue($member->is($this->guardForRequest($request, 'members')->user()));

        ActivatableTenant::query()->whereKey($tenant->getKey())->update(['is_active' => false]);

        self::assertNull($this->guardForRequest($request, 'members')->user());
    }

    /**
     * A membership's tenant held only on the primary is loaded from the writer.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testIssuanceFindsThePrincipalsTenantOnTheWriteConnection(): void
    {
        $tenant = new ActivatableTenant;
        $tenant->forceFill(['name' => 'Tenant', 'is_active' => true])->save();

        $member = new ActivatableTenantMember;
        $member->forceFill(['email' => 'member@example.test', 'password' => 'hashed'])->save();

        $membership = new ActivatableTenantMembership;
        $membership->forceFill(['identity_id' => $member->getKey(), 'tenant_id' => $tenant->getKey()])->save();

        self::assertNull(ActivatableTenant::query()->find($tenant->getKey()));
        self::assertFalse($membership->relationLoaded('tenant'));

        $tokens = $this->authManager()->jwt('members');
        $token  = $tokens->issueAccessToken($member, $membership, $tenant, null)->reveal();

        self::assertSame(IdentifierCoercion::stringify($tenant->getKey()), $tokens->parse($token)['tenant_id'] ?? null);
    }

    /**
     * A membership pinned on `attempt()` binds when its member is only on the
     * primary.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAttemptReadsThePinnedPrincipalsOwnerFromTheWriteConnection(): void
    {
        $tenant = new ActivatableTenant;
        $tenant->forceFill(['name' => 'Tenant', 'is_active' => true])->save();

        $member = new ActivatableTenantMember;
        $member->forceFill(['email' => 'member@example.test', 'password' => app(Hasher::class)->make(self::PASSWORD)])->save();

        $membership = new ActivatableTenantMembership;
        $membership->forceFill(['identity_id' => $member->getKey(), 'tenant_id' => $tenant->getKey()])->save();

        $credentials = ['email' => 'member@example.test', 'password' => self::PASSWORD];
        $guard       = $this->guardForRequest(Request::create('/sign-in', 'POST'), 'members');

        self::assertTrue($guard->attempt($credentials, ActivatableTenantMembership::query()->useWritePdo()->findOrFail(self::modelKey($membership))));
        self::assertSame($membership->getKey(), $guard->principal()?->getPrincipalIdentifier());
    }

    /**
     * An identity suspended on the primary fails its own `isActive()` check.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testBearerRejectsIdentitySuspendedOnThePrimaryWhileTheReplicaLags(): void
    {
        $this->createOnPrimaryAndReplica('suspendable_users', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('email')->unique();
            $blueprint->string('password');
            $blueprint->timestamps();
        });

        $this->createOnPrimaryAndReplica('user_suspensions', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->unsignedInteger('user_id');
        });

        $user = new SuspendableUser;
        $user->forceFill(['email' => 'suspended@example.test', 'password' => 'hashed'])->save();

        $this->copyRowToReplica('suspendable_users', $user->getKey());

        $token   = $this->authManager()->jwt('suspendable')->issueAccessToken($user, $user, null, null)->reveal();
        $request = Request::create('/me', 'GET', server: ['HTTP_AUTHORIZATION' => 'Bearer ' . $token]);

        self::assertTrue($user->is($this->guardForRequest($request, 'suspendable')->user()));

        DB::connection(self::SPLIT_CONNECTION)->table('user_suspensions')->insert(['user_id' => $user->getKey()]);

        self::assertNull($this->guardForRequest($request, 'suspendable')->user());
    }

    /**
     * The model provider finds an identity by credentials when the row exists
     * only on the primary.
     *
     * @return void
     */
    public function testModelProviderReadsCredentialsFromTheWriteConnection(): void
    {
        $identity = $this->seedIdentity();

        $provider = new ModelProvider(app(Hasher::class), StubPrincipal::class);

        self::assertIsModel($identity, $provider->retrieveByCredentials(['email' => 'writer@example.test']));
    }

    /**
     * A credential closure that runs its own query reads the writer.
     *
     * @return void
     */
    public function testModelProviderRunsCredentialClosuresOnTheWriteConnection(): void
    {
        $identity = $this->seedSuspendableIdentity();
        $provider = new ModelProvider(app(Hasher::class), StubPrincipal::class);

        $credentials = ['email' => 'writer@example.test', 'unsuspended' => self::excludeSuspendedIdentities()];

        self::assertIsModel($identity, $provider->retrieveByCredentials($credentials));

        $this->suspend($identity);

        self::assertNull($provider->retrieveByCredentials($credentials));
    }

    /**
     * Signing in over HTTP is refused once the identity is suspended on the
     * primary.
     *
     * @return void
     */
    public function testSignInRejectsIdentitySuspendedOnThePrimaryWhileTheReplicaLags(): void
    {
        $identity = $this->seedSuspendableIdentity();

        $identity->forceFill(['password' => app(Hasher::class)->make(self::PASSWORD)])->save();

        Route::post('/sign-in', static fn (): array => [
            'signed_in' => Auth::guard('api')->attempt([
                'email'       => 'writer@example.test',
                'password'    => self::PASSWORD,
                'unsuspended' => self::excludeSuspendedIdentities(),
            ]),
            'identity' => Auth::guard('api')->id(),
        ]);

        $this->postJson('/sign-in')->assertOk()->assertExactJson(['signed_in' => true, 'identity' => $identity->getKey()]);

        $this->suspend($identity);

        $this->postJson('/sign-in')->assertOk()->assertExactJson(['signed_in' => false, 'identity' => null]);
    }

    /**
     * The default resolver finds a 3D principal held only on the primary.
     *
     * @return void
     */
    public function testDefaultResolverReadsPrincipalsFromTheWriteConnection(): void
    {
        $identity = new Coexist3dIdentity;
        $identity->forceFill([
            'email'    => 'writer-3d@example.test',
            'password' => 'hashed',
        ])->save();

        $principal = new Coexist3dPrincipal;
        $principal->forceFill([
            'identity_id' => $identity->getKey(),
            'name'        => 'membership',
        ])->save();

        $resolver = app(PrincipalResolver::class);

        self::assertIsModel($principal, $resolver->resolve($identity));
        self::assertIsModel($principal, $resolver->resolve($identity, $principal->getKey()));
    }

    /**
     * The default resolver runs `resolveHintedPrincipal()` on the writer.
     *
     * @return void
     */
    public function testDefaultResolverRunsTheHintedPrincipalHookOnTheWriteConnection(): void
    {
        $identity = new TenantAware3dIdentity;
        $identity->forceFill([
            'email'    => 'writer-tenant@example.test',
            'password' => 'hashed',
        ])->save();

        $tenant = new TenantAware3dTenant;
        $tenant->forceFill([
            'name' => 'Tenant',
            'type' => 'customer',
        ])->save();

        $principal = new TenantAware3dPrincipal;
        $principal->forceFill([
            'identity_id' => $identity->getKey(),
            'tenant_id'   => $tenant->getKey(),
            'name'        => 'membership',
        ])->save();

        $resolved = app(PrincipalResolver::class)->resolve($identity, $principal->getKey());

        self::assertInstanceOf(TenantAware3dPrincipal::class, $resolved);
        self::assertEquals($principal->getKey(), $resolved->getKey());
        self::assertTrue($resolved->relationLoaded('tenant'));
    }

    /**
     * Configure the `api` guard over the lagging split connection.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        /** @var \Illuminate\Config\Repository $config */
        $config = app(ConfigRepository::class);

        $this->configureLaggingReplica($config);

        $config->set('auth.guards.api', [
            'driver'      => 'jwt',
            'provider'    => 'identities',
            'application' => ['methods' => ['password']],
        ]);

        $config->set('auth.providers.identities', [
            'driver' => 'model',
            'model'  => StubPrincipal::class,
        ]);

        $config->set('auth.guards.members', [
            'driver'      => 'jwt',
            'provider'    => 'members',
            'application' => ['methods' => ['password']],
        ]);

        $config->set('auth.providers.members', [
            'driver' => 'model',
            'model'  => ActivatableTenantMember::class,
        ]);

        $config->set('auth.guards.revocation_log', [
            'driver'      => 'jwt',
            'provider'    => 'revocation_log',
            'application' => ['methods' => ['password']],
        ]);

        $config->set('auth.providers.revocation_log', [
            'driver' => 'model',
            'model'  => RevocationLogIdentity::class,
        ]);

        $config->set('auth.guards.suspendable', [
            'driver'      => 'jwt',
            'provider'    => 'suspendable',
            'application' => ['methods' => ['password']],
        ]);

        $config->set('auth.providers.suspendable', [
            'driver' => 'model',
            'model'  => SuspendableUser::class,
        ]);

        // Failed attempts wait out the timebox; keep it short.
        $config->set('authentication.timebox.credentials_microseconds', 1);
    }

    /**
     * Create the package tables on the primary and the replica instead of
     * migrating the default connection.
     *
     * @return void
     */
    #[\Override]
    protected function defineDatabaseMigrations(): void
    {
        $this->migratePackageTablesOnPrimaryAndReplica();
    }

    /**
     * Create the tenant-aware 3D fixture tables on the primary and the replica.
     *
     * @return void
     */
    private function createTenantAwareTables(): void
    {
        $this->createOnPrimaryAndReplica('tenant_aware_3d_identities', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('email')->unique();
            $blueprint->string('password');
            $blueprint->boolean('is_active')->default(true);
            $blueprint->timestamps();
        });

        $this->createOnPrimaryAndReplica('tenant_aware_3d_tenants', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('name');
            $blueprint->string('type');
            $blueprint->timestamps();
        });

        $this->createOnPrimaryAndReplica('tenant_aware_3d_principals', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->unsignedInteger('identity_id');
            $blueprint->unsignedInteger('tenant_id');
            $blueprint->string('name');
            $blueprint->boolean('is_active')->default(true);
            $blueprint->timestamps();
        });
    }

    /**
     * Create the activatable tenant fixture tables on the primary and the
     * replica.
     *
     * @return void
     */
    private function createActivatableTenantTables(): void
    {
        $this->createOnPrimaryAndReplica('activatable_tenants', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('name');
            $blueprint->boolean('is_active')->default(true);
            $blueprint->timestamps();
            $blueprint->softDeletes();
        });

        $this->createOnPrimaryAndReplica('activatable_tenant_members', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('email')->unique();
            $blueprint->string('password');
            $blueprint->timestamps();
        });

        $this->createOnPrimaryAndReplica('activatable_tenant_memberships', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->unsignedInteger('identity_id');
            $blueprint->unsignedInteger('tenant_id');
            $blueprint->timestamps();
        });
    }

    /**
     * Write an identity through the split connection, so it exists on the
     * primary only.
     *
     * @return \Tests\Unit\Stubs\StubPrincipal
     */
    private function seedIdentity(): StubPrincipal
    {
        $identity = new StubPrincipal;
        $identity->forceFill([
            'email'    => 'writer@example.test',
            'password' => 'hashed',
        ])->save();

        return $identity;
    }

    /**
     * Write a session with a refresh digest for the identity through the split
     * connection, so it exists on the primary only.
     *
     * @param  \Tests\Unit\Stubs\StubPrincipal  $identity
     * @param  class-string<\SineMacula\Laravel\Authentication\Models\Session>  $model
     * @return \SineMacula\Laravel\Authentication\Models\Session
     */
    private function seedSession(StubPrincipal $identity, string $model = Session::class): Session
    {
        $session = new $model;
        $session->forceFill([
            ...self::liveSession(),
            'authenticatable_type' => StubPrincipal::class,
            'authenticatable_id'   => (string) $identity->getKey(), // @phpstan-ignore cast.string
            'principal_type'       => $identity->getMorphClass(),
            'principal_id'         => (string) $identity->getKey(), // @phpstan-ignore cast.string
            'refresh_key'          => RefreshTokenHasher::hash(self::ROTATION_ID),
        ])->save();

        return $session;
    }

    /**
     * Write an identity with a `revocation_log` session whose revocation and
     * end come from other tables.
     *
     * @param  class-string<\SineMacula\Laravel\Authentication\Models\Session>  $model
     * @return array{0: \Tests\Integration\Fixtures\RevocationLogIdentity, 1: \SineMacula\Laravel\Authentication\Models\Session}
     */
    private function seedRevocationLogSession(string $model = RevocationLogSession::class): array
    {
        $this->createOnPrimaryAndReplica('session_revocations', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->uuid('session_id');
            $blueprint->timestamp('revoked_at');
        });

        $this->createOnPrimaryAndReplica('session_ends', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->uuid('session_id');
            $blueprint->dateTime('ended_at');
        });

        $identity = new RevocationLogIdentity;
        $identity->forceFill([
            'email'    => 'revocation-log@example.test',
            'password' => 'hashed',
        ])->save();

        $session = new $model;
        $session->forceFill([
            ...self::liveSession('revocation_log'),
            'authenticatable_type' => RevocationLogIdentity::class,
            'authenticatable_id'   => (string) $identity->getKey(), // @phpstan-ignore cast.string
            'principal_type'       => $identity->getMorphClass(),
            'principal_id'         => (string) $identity->getKey(), // @phpstan-ignore cast.string
            'refresh_key'          => RefreshTokenHasher::hash(self::ROTATION_ID),
        ])->save();

        return [$identity, $session];
    }

    /**
     * Seed an identity on the primary and the replica, and create the
     * `identity_suspensions` table on both.
     *
     * @return \Tests\Unit\Stubs\StubPrincipal
     */
    private function seedSuspendableIdentity(): StubPrincipal
    {
        $this->createOnPrimaryAndReplica('identity_suspensions', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->unsignedInteger('identity_id');
        });

        $identity = $this->seedIdentity();

        $this->copyRowToReplica('stub_principals', $identity->getKey());

        return $identity;
    }

    /**
     * Record a suspension of the identity through the split connection, so the
     * replica does not see it.
     *
     * @param  \Tests\Unit\Stubs\StubPrincipal  $identity
     * @return void
     */
    private function suspend(StubPrincipal $identity): void
    {
        DB::connection(self::SPLIT_CONNECTION)->table('identity_suspensions')->insert(['identity_id' => $identity->getKey()]);
    }

    /**
     * A credential closure that excludes suspended identities, deciding the
     * clause from a query it runs itself on the identity's connection.
     *
     * @return \Closure(\Illuminate\Database\Eloquent\Builder<\Illuminate\Database\Eloquent\Model>): void
     */
    private static function excludeSuspendedIdentities(): \Closure
    {
        return static function (Builder $query): void {

            $suspended = $query->getModel()->getConnection()->table('identity_suspensions')->pluck('identity_id')->all();

            $query->whereNotIn('id', $suspended);
        };
    }

    /**
     * Record a revocation of the session through the split connection, so the
     * replica does not see it.
     *
     * @param  \SineMacula\Laravel\Authentication\Models\Session  $session
     * @return void
     */
    private function recordRevocation(Session $session): void
    {
        DB::connection(self::SPLIT_CONNECTION)->table('session_revocations')->insert([
            'session_id' => $session->getKey(),
            'revoked_at' => Carbon::now(),
        ]);
    }

    /**
     * Record the end of the session at the given time, defaulting to now.
     *
     * @param  \SineMacula\Laravel\Authentication\Models\Session  $session
     * @param  ?\Carbon\Carbon  $endedAt
     * @param  string  $connection
     * @return void
     */
    private function recordSessionEnd(Session $session, ?Carbon $endedAt = null, string $connection = self::SPLIT_CONNECTION): void
    {
        DB::connection($connection)->table('session_ends')->insert([
            'session_id' => $session->getKey(),
            'ended_at'   => $endedAt ?? Carbon::now(),
        ]);
    }

    /**
     * Resolve the package auth manager with no cached guards.
     *
     * @return \SineMacula\Laravel\Authentication\AuthManager
     */
    private function authManager(): AuthManager
    {
        $manager = app('auth');

        assert($manager instanceof AuthManager);

        $manager->forgetGuards();

        return $manager;
    }

    /**
     * Resolve a fresh JWT guard bound to the supplied request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  string  $name
     * @return \SineMacula\Laravel\Authentication\Guards\JwtGuard
     */
    private function guardForRequest(Request $request, string $name = 'api'): JwtGuard
    {
        app()->instance('request', $request);

        $guard = $this->authManager()->guard($name);

        assert($guard instanceof JwtGuard);

        return $guard;
    }

    /**
     * Rotate the session on the primary from `ROTATION_ID` to its successor at
     * the given time, leaving the replica behind.
     *
     * @param  \SineMacula\Laravel\Authentication\Models\Session  $session
     * @param  \Carbon\Carbon  $rotatedAt
     * @return void
     */
    private function rotateOnThePrimary(Session $session, Carbon $rotatedAt): void
    {
        Session::query()->whereKey($session->getKey())->update([
            'refresh_key'          => RefreshTokenHasher::hash(RefreshTokenHasher::successor(self::ROTATION_ID)),
            'previous_refresh_key' => RefreshTokenHasher::hash(self::ROTATION_ID),
            'refresh_rotated_at'   => $rotatedAt,
        ]);
    }

    /**
     * Record the SQL of every update of the sessions table from here on.
     *
     * @return \ArrayObject<int, string>
     */
    private function recordUpdates(): \ArrayObject
    {
        /** @var \ArrayObject<int, string> $updates */
        $updates = new \ArrayObject;

        DB::listen(static function (QueryExecuted $query) use ($updates): void {
            if (!str_starts_with(strtolower($query->sql), 'update "authentication_sessions"')) {
                return;
            }

            $updates->append($query->sql);
        });

        return $updates;
    }
}
