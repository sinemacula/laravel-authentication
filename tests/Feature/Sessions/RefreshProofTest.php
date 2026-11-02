<?php

declare(strict_types = 1);

namespace Tests\Feature\Sessions;

use Carbon\Carbon;
use Carbon\CarbonImmutable;
use Firebase\JWT\JWT;
use Illuminate\Auth\Events\Failed;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\ConnectionResolverInterface;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Database\AfterCommit;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\Enums\AuthenticationFlow;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\Enums\RevocationReason;
use SineMacula\Laravel\Authentication\Events\SessionRevoked;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Jwt\Enums\Claims;
use SineMacula\Laravel\Authentication\Jwt\Enums\RotationMatch;
use SineMacula\Laravel\Authentication\Jwt\Enums\TokenType;
use SineMacula\Laravel\Authentication\Jwt\RefreshRotationStore;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenHasher;
use SineMacula\Laravel\Authentication\Models\Session;
use SineMacula\Laravel\Authentication\Sessions\ProvenRefresh;
use SineMacula\Laravel\Authentication\Sessions\RefreshProof;
use SineMacula\Laravel\Authentication\Sessions\SignedInSession;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use SineMacula\Laravel\Authentication\Support\PrincipalReference;
use Tests\Concerns\InteractsWithSessions;
use Tests\TestCase;
use Tests\Unit\Stubs\PlainPrincipalFixture;

/**
 * Feature tests of proving, from a refresh token, the session a client holds
 * now, without rotating it: the current token and, inside the grace window, the
 * one it replaced prove the session; every other token is refused with the
 * reason a refresh would give, in an `AuthenticationFailed` of the flow asked
 * for that is returned and not dispatched; and a replay revokes the session,
 * reported once the revocation commits.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RefreshProof::class)]
#[CoversClass(ProvenRefresh::class)]
final class RefreshProofTest extends TestCase
{
    use InteractsWithSessions;

    /** @var list<class-string> Every event a proof could dispatch. */
    private const array EVENTS = [SessionRevoked::class, AuthenticationFailed::class, Failed::class];

    /** @var string A rotation id the tests store the digest of, so they can issue tokens that carry it. */
    private const string KNOWN_ROTATION = 'known-rotation-id';

    /**
     * Freeze the clock and create the tables.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->moveTo(CarbonImmutable::createStrict(2026, 4, 6, 12, 0, 0));

        $this->createSessionTables();
    }

    /**
     * Release the clock and drop the tables.
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
     * The session's current refresh token, as a secret or in clear, proves the
     * session as its current rotation, with the principal the token names; the
     * session is left exactly as it was and nothing is dispatched.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheCurrentTokenProvesItsSessionWithoutRotatingIt(): void
    {
        $this->seedIdentity();

        $session = $this->signedIn();
        $token   = $session->tokens->refreshToken;
        $before  = $this->row($session);

        self::assertNotNull($token);

        $principal = Auth::jwt('api')->parse($token)[Claims::PRINCIPAL->value] ?? null;

        self::assertNotNull($principal);

        $this->recordEvents(self::EVENTS);

        foreach ([$token, $token->reveal()] as $presented) {

            $proven = $this->proof()->prove($presented, AuthenticationFlow::SIGN_OUT, CarbonImmutable::now());

            self::assertInstanceOf(ProvenRefresh::class, $proven);
            self::assertSame($session->record->getKey(), $proven->session->getKey());
            self::assertSame(RotationMatch::CURRENT, $proven->match);
            self::assertSame($principal, $proven->principalHint);
        }

        self::assertSame($before, $this->row($session));
        self::assertSame([], $this->recordedClasses());
    }

    /**
     * The token a refresh replaced still proves the session inside the grace
     * window, as the previous rotation, without revoking it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheReplacedTokenProvesTheSessionInsideTheGraceWindow(): void
    {
        $this->seedIdentity();

        $session   = $this->signedIn();
        $replaced  = (string) $session->tokens->refreshToken?->reveal();
        $refreshed = $this->sessions()->refresh($replaced);

        self::assertTrue($refreshed->isRefreshed());

        $this->moveTo(CarbonImmutable::now()->addSeconds(10));
        $this->recordEvents(self::EVENTS);

        $proven = $this->proof()->prove($replaced, AuthenticationFlow::SIGN_OUT, CarbonImmutable::now());

        self::assertInstanceOf(ProvenRefresh::class, $proven);
        self::assertSame(RotationMatch::PREVIOUS, $proven->match);
        self::assertNull($this->row($session)['revoked_at']);
        self::assertSame([], $this->recordedClasses());
    }

    /**
     * The replaced token presented after the grace window is a replay: it is
     * refused as `rotation_reuse`, the session is revoked for it and reported
     * once by `SessionRevoked`, both naming the owner and the principal the
     * session records, and the session's current token is refused as revoked
     * from then on.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAReplayAfterTheGraceWindowRevokesTheSession(): void
    {
        $identity = $this->seedIdentity();
        $owner    = IdentifierCoercion::stringify($identity->getAuthIdentifier());

        $session   = $this->signedIn();
        $replaced  = (string) $session->tokens->refreshToken?->reveal();
        $refreshed = $this->sessions()->refresh($replaced)->session;

        self::assertNotNull($refreshed);

        $this->moveTo(CarbonImmutable::now()->addMinutes(2));
        $this->recordEvents(self::EVENTS);

        $failed = $this->proof()->prove($replaced, AuthenticationFlow::SIGN_OUT, CarbonImmutable::now());

        self::assertInstanceOf(AuthenticationFailed::class, $failed);
        self::assertSame([AuthenticationFlow::SIGN_OUT, FailureReason::ROTATION_REUSE], [$failed->flow, $failed->reason]);
        self::assertSame([$owner, $owner], [$failed->context->identityId, $failed->context->principalId]);
        self::assertSame([SessionRevoked::class], $this->recordedClasses());

        $revoked = $this->recordedEvent(SessionRevoked::class);

        self::assertSame(RevocationReason::ROTATION_REUSE, $revoked->reason);
        self::assertSame(IdentifierCoercion::stringify($session->record->getKey()), $revoked->context->sessionId);
        self::assertSame('api', $revoked->context->guard);
        self::assertSame([$owner, $owner], [$revoked->context->identityId, $revoked->context->principalId]);
        $revokedAt = $this->row($session)['revoked_at'];

        self::assertIsString($revokedAt);
        self::assertEquals(CarbonImmutable::now(), CarbonImmutable::parse($revokedAt));
        self::assertSame('rotation_reuse', $this->row($session)['revoked_reason']);

        $current = $this->proof()->prove((string) $refreshed->tokens->refreshToken?->reveal(), AuthenticationFlow::SIGN_OUT, CarbonImmutable::now());

        self::assertInstanceOf(AuthenticationFailed::class, $current);
        self::assertSame(FailureReason::SESSION_REVOKED, $current->reason);
        self::assertCount(1, $this->recordedEvents(SessionRevoked::class));
    }

    /**
     * Every token that proves no session is refused with the reason a refresh
     * gives it, in an `AuthenticationFailed` of the flow asked for (`sign_out`,
     * or `refresh`), for this guard, naming the session when the token names
     * one; the event is returned, not dispatched, and no session is revoked.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testEveryRefusalIsReturnedWithItsFlowAndReason(): void
    {
        $identity = $this->seedIdentity();
        $other    = $this->seedIdentity('grace@example.test');

        $unknown  = $this->signedIn();
        $revoked  = $this->signedIn();
        $pending  = $this->signedIn();
        $expired  = $this->signedIn();
        $keyless  = $this->signedIn();
        $switched = $this->signedIn();
        $admin    = $this->signedIn('admin');

        Session::query()->whereKey($unknown->record->getKey())->delete();
        Session::query()->whereKey($revoked->record->getKey())->update(['revoked_at' => CarbonImmutable::now(), 'revoked_reason' => 'signed_out']);
        Session::query()->whereKey($pending->record->getKey())->update(['status' => 'pending']);
        Session::query()->whereKey($expired->record->getKey())->update(['idle_expires_at' => CarbonImmutable::now()->subMinute()]);
        Session::query()->whereKey($keyless->record->getKey())->update(['refresh_key' => null]);
        Session::query()->whereKey($switched->record->getKey())->update(['refresh_key' => RefreshTokenHasher::hash(self::KNOWN_ROTATION)]);

        $tokens = Auth::jwt('api');
        $cases  = [
            'not a token'        => ['not-a-token', FailureReason::TOKEN_INVALID, null],
            'a non-string jti'   => [$this->refreshTokenWithRotationId(12345, 'a-session-id'), FailureReason::TOKEN_INVALID, 'a-session-id'],
            'an access token'    => [$unknown->tokens->accessToken->reveal(), FailureReason::TOKEN_INVALID, null],
            'an unknown session' => [$unknown->tokens->refreshToken?->reveal(), FailureReason::SESSION_UNKNOWN, $unknown],
            'another guard'      => [$tokens->issueRefreshToken($admin->record, self::KNOWN_ROTATION, $identity)->reveal(), FailureReason::SESSION_GUARD_MISMATCH, $admin],
            'a revoked session'  => [$revoked->tokens->refreshToken?->reveal(), FailureReason::SESSION_REVOKED, $revoked],
            'a pending session'  => [$pending->tokens->refreshToken?->reveal(), FailureReason::SESSION_PENDING, $pending],
            'an expired session' => [$expired->tokens->refreshToken?->reveal(), FailureReason::SESSION_EXPIRED, $expired],
            'no refresh key'     => [$keyless->tokens->refreshToken?->reveal(), FailureReason::REFRESH_KEY_MISSING, $keyless],
            'another principal'  => [$tokens->issueRefreshToken($switched->record, self::KNOWN_ROTATION, $other)->reveal(), FailureReason::SESSION_PRINCIPAL_MISMATCH, $switched],
        ];

        $this->recordEvents(self::EVENTS);

        foreach ($cases as $case => [$token, $reason, $named]) {

            $failed = $this->proof()->prove((string) $token, AuthenticationFlow::SIGN_OUT, CarbonImmutable::now());

            self::assertInstanceOf(AuthenticationFailed::class, $failed, $case);
            self::assertSame([AuthenticationFlow::SIGN_OUT, $reason], [$failed->flow, $failed->reason], $case);
            self::assertSame('api', $failed->context->guard, $case);
            self::assertSame(self::CLIENT_IP, $failed->context->client->ip, $case);
            self::assertSame($named instanceof SignedInSession ? IdentifierCoercion::stringify($named->record->getKey()) : $named, $failed->context->sessionId, $case);
        }

        $refresh = $this->proof()->prove('not-a-token', AuthenticationFlow::REFRESH, CarbonImmutable::now());

        self::assertInstanceOf(AuthenticationFailed::class, $refresh);
        self::assertSame(AuthenticationFlow::REFRESH, $refresh->flow);
        self::assertSame([], $this->recordedClasses());
        self::assertSame(1, Session::query()->whereNotNull('revoked_at')->count());
    }

    /**
     * A token that names no principal proves the session whatever principal the
     * session records: the principal is the caller's to admit.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATokenNamingNoPrincipalProvesTheSession(): void
    {
        $this->seedIdentity();

        $session = $this->signedIn();

        Session::query()->whereKey($session->record->getKey())->update(['refresh_key' => RefreshTokenHasher::hash(self::KNOWN_ROTATION)]);

        $token  = Auth::jwt('api')->issueRefreshToken($session->record, self::KNOWN_ROTATION);
        $proven = $this->proof()->prove($token, AuthenticationFlow::SIGN_OUT, CarbonImmutable::now());

        self::assertInstanceOf(ProvenRefresh::class, $proven);
        self::assertNull($proven->principalHint);
        self::assertSame(RotationMatch::CURRENT, $proven->match);
    }

    /**
     * The token names its principal by identifier alone, so a token naming a
     * principal of another class with the recorded principal's identifier (as a
     * token from before a switch between two such principals is, inside the
     * grace window) proves the session: a sign-out may revoke it, since the
     * same token revokes it as a replay once the window closes, and a caller
     * that acts as the principal checks its type itself.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATokenNamingAnotherClassWithTheRecordedIdentifierProvesTheSession(): void
    {
        $identity = $this->seedIdentity();
        $session  = $this->signedIn();

        Session::query()->whereKey($session->record->getKey())->update(['refresh_key' => RefreshTokenHasher::hash(self::KNOWN_ROTATION)]);

        $named  = new PlainPrincipalFixture($identity->getKey());
        $token  = Auth::jwt('api')->issueRefreshToken($session->record, self::KNOWN_ROTATION, $named);
        $proven = $this->proof()->prove($token, AuthenticationFlow::SIGN_OUT, CarbonImmutable::now());

        self::assertTrue(PrincipalReference::isRecordedOn($session->record, $session->principal));
        self::assertFalse(PrincipalReference::isRecordedOn($session->record, $named));
        self::assertInstanceOf(ProvenRefresh::class, $proven);
        self::assertTrue(IdentifierCoercion::matches($identity->getKey(), $proven->principalHint));
        self::assertSame(RotationMatch::CURRENT, $proven->match);
    }

    /**
     * A replay inside the caller's transaction is reported once the transaction
     * commits, and not at all when it rolls back, which undoes the revocation
     * too.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAReplaysReportWaitsForTheCallersCommit(): void
    {
        $this->seedIdentity();

        $committed  = $this->replayable();
        $rolledBack = $this->replayable();

        $this->recordEvents(self::EVENTS);

        DB::transaction(function () use ($committed): void {

            $this->assertReplayRefused($committed);

            self::assertSame([], $this->recordedClasses());
        });

        self::assertSame([SessionRevoked::class], $this->recordedClasses());

        try {
            DB::transaction(function () use ($rolledBack): never {

                $this->assertReplayRefused($rolledBack);

                throw new \RuntimeException('rolled back');
            });
        } catch (\RuntimeException $exception) {
            self::assertSame('rolled back', $exception->getMessage());
        }

        self::assertCount(1, $this->recordedEvents(SessionRevoked::class));
        self::assertSame(1, Session::query()->whereNotNull('revoked_at')->count());
    }

    /**
     * A replay of a session another writer revoked after the proof read it is
     * still refused as `rotation_reuse`, but the revocation the other writer
     * made stands and is not reported again.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAReplayOfASessionRevokedMeanwhileIsNotReportedAgain(): void
    {
        $this->seedIdentity();

        $replayed = $this->replayable();
        $armed    = new \ArrayObject(['armed' => true]);

        DB::listen(static function (QueryExecuted $query) use ($armed): void {

            if ($armed['armed'] !== true || !str_starts_with(strtolower(ltrim($query->sql)), 'select') || !str_contains($query->sql, 'authentication_sessions')) {
                return;
            }

            $armed['armed'] = false;

            DB::table('authentication_sessions')->update(['revoked_at' => CarbonImmutable::now(), 'revoked_reason' => 'revoked']);
        });

        $this->recordEvents(self::EVENTS);
        $this->assertReplayRefused($replayed);

        self::assertFalse($armed['armed']);
        self::assertSame([], $this->recordedClasses());
        self::assertSame('revoked', Session::query()->whereKey($replayed[0]->record->getKey())->value('revoked_reason'));
    }

    /**
     * Configure the session guards.
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
     * Assert the replayed token of the pair is refused as `rotation_reuse`.
     *
     * @param  array{0: \SineMacula\Laravel\Authentication\Sessions\SignedInSession, 1: string}  $replayed
     * @return void
     *
     * @throws \Throwable
     */
    private function assertReplayRefused(array $replayed): void
    {
        $failed = $this->proof()->prove($replayed[1], AuthenticationFlow::SIGN_OUT, CarbonImmutable::now());

        self::assertInstanceOf(AuthenticationFailed::class, $failed);
        self::assertSame(FailureReason::ROTATION_REUSE, $failed->reason);
    }

    /**
     * A session whose refresh token was rotated more than the grace window ago,
     * with the token the rotation replaced.
     *
     * @return array{0: \SineMacula\Laravel\Authentication\Sessions\SignedInSession, 1: string}
     *
     * @throws \Throwable
     */
    private function replayable(): array
    {
        $session  = $this->signedIn();
        $replaced = (string) $session->tokens->refreshToken?->reveal();

        Session::query()->whereKey($session->record->getKey())->update([
            'previous_refresh_key' => RefreshTokenHasher::hash('a-replaced-rotation-id'),
            'refresh_key'          => RefreshTokenHasher::hash('the-current-rotation-id'),
            'refresh_rotated_at'   => CarbonImmutable::now()->subMinutes(5),
        ]);

        return [$session, $replaced];
    }

    /**
     * A refresh proof for the `api` guard, as the session service builds it.
     *
     * @return \SineMacula\Laravel\Authentication\Sessions\RefreshProof
     */
    private function proof(): RefreshProof
    {
        $connections  = app(ConnectionResolverInterface::class);
        $transactions = static fn (): mixed => app()->bound('db.transactions') ? app('db.transactions') : null;

        return new RefreshProof($this->freshGuard()->context(), Auth::jwt('api'), new RefreshRotationStore($connections), new AfterCommit($transactions));
    }

    /**
     * Sign the identity with the email in on the guard.
     *
     * @param  string  $guard
     * @param  string  $email
     * @return \SineMacula\Laravel\Authentication\Sessions\SignedInSession
     *
     * @throws \Throwable
     */
    private function signedIn(string $guard = 'api', string $email = 'ada@example.test'): SignedInSession
    {
        $session = $this->sessions($guard)->signIn('password', self::credentials($email))->session;

        self::assertNotNull($session);

        return $session;
    }

    /**
     * A refresh token of the `api` guard, signed with its key, whose `jti` is
     * the value given.
     *
     * @param  mixed  $rotationId
     * @param  string  $sessionId
     * @return string
     */
    private function refreshTokenWithRotationId(mixed $rotationId, string $sessionId): string
    {
        $now = CarbonImmutable::now()->getTimestamp();

        return JWT::encode([
            Claims::ISSUER->value     => self::JWT_ISSUER,
            Claims::AUDIENCE->value   => self::JWT_AUDIENCE,
            Claims::CLIENT_ID->value  => 'api',
            Claims::SESSION_ID->value => $sessionId,
            Claims::JWT_ID->value     => $rotationId,
            Claims::ISSUED_AT->value  => $now,
            Claims::EXPIRES_AT->value => $now + 3600,
        ], 'test-secret-key-with-at-least-32-bytes!', 'HS256', 'test-kid', ['typ' => TokenType::REFRESH->value]);
    }

    /**
     * The session's stored row.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignedInSession  $session
     * @return array<string, mixed>
     */
    private function row(SignedInSession $session): array
    {
        return (array) DB::table('authentication_sessions')->where('id', $session->record->getKey())->sole();
    }

    /**
     * The recorded events of the class.
     *
     * @param  class-string  $class
     * @return list<object>
     */
    private function recordedEvents(string $class): array
    {
        return array_values(array_filter($this->recorded, static fn (object $event): bool => $event instanceof $class));
    }

    /**
     * Move the clock, and the token library's, to the moment.
     *
     * @param  \Carbon\CarbonImmutable  $now
     * @return void
     */
    private function moveTo(CarbonImmutable $now): void
    {
        Carbon::setTestNow($now);
        CarbonImmutable::setTestNow($now);

        JWT::$timestamp = $now->getTimestamp();
    }
}
