<?php

declare(strict_types = 1);

namespace Tests\Integration\Guards;

use Carbon\Carbon;
use Firebase\JWT\JWT;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Authentication\AuthManager;
use SineMacula\Laravel\Authentication\Concerns\ActsAsSession;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Http\PresentedRefreshToken;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenHasher;
use Tests\Concerns\InteractsWithSessionRecords;
use Tests\Fixtures\Sessions\GuardSessions;
use Tests\Integration\Fixtures\UncastSession;
use Tests\Integration\Fixtures\UncastSessionIdentity;
use Tests\TestCase;

/**
 * A revoked session is rejected on every path even when its model uses the
 * `ActsAsSession` trait without a `datetime` cast on `revoked_at`, so the
 * column reads back as the raw string the database stores.
 *
 * Each test revokes the session the way the refresh exchange does, writing the
 * revocation time through the query builder and clearing the refresh digest.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(JwtGuard::class)]
#[CoversTrait(ActsAsSession::class)]
final class UncastRevokedSessionIntegrationTest extends TestCase
{
    use InteractsWithSessionRecords;

    /** @var string Plaintext password of the seeded identity. */
    private const string PASSWORD = 'correct horse battery staple';

    /** @var string Plaintext rotation id the session's refresh digest is built from. */
    private const string ROTATION_ID = 'plain-rotation-id';

    /**
     * Freeze the clocks and create the identity table.
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

        Schema::create('uncast_session_identities', static function (Blueprint $blueprint): void {
            $blueprint->uuid('id')->primary();
            $blueprint->string('email')->unique();
            $blueprint->string('password');
            $blueprint->timestamps();
        });
    }

    /**
     * Release the frozen clocks and drop the identity table.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Schema::dropIfExists('uncast_session_identities');

        Carbon::setTestNow();

        JWT::$timestamp = null;

        parent::tearDown();
    }

    /**
     * An access token naming the revoked session no longer authenticates.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testBearerRejectsTheRevokedSession(): void
    {
        [$identity, $session] = $this->seedIdentityWithSession();

        $token = $this->authManager()->jwt('api')->issueAccessToken($identity, $identity, null, $session)->reveal();

        self::assertTrue($this->guardForRequest($this->bearerRequest($token))->check());

        $this->revoke($session);

        self::assertFalse($this->guardForRequest($this->bearerRequest($token))->check());
    }

    /**
     * Pinning the session on `attempt()` signs in while it is live, and fails
     * with `session_mismatch` once it is revoked.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAttemptRejectsTheRevokedSessionWhenPinned(): void
    {
        [$identity, $session] = $this->seedIdentityWithSession();

        $credentials = ['email' => $identity->email, 'password' => self::PASSWORD];

        self::assertTrue($this->guardForRequest(Request::create('/sign-in', 'POST'))->attempt($credentials, null, $session));

        $this->revoke($session);

        Event::fake([AuthenticationFailed::class]);

        $guard = $this->guardForRequest(Request::create('/sign-in', 'POST'));

        self::assertFalse($guard->attempt($credentials, null, $session));
        self::assertFalse($guard->hasUser());

        Event::assertDispatched(
            AuthenticationFailed::class,
            static fn (AuthenticationFailed $event): bool => $event->reason === FailureReason::SESSION_MISMATCH,
        );
    }

    /**
     * Refreshing with the revoked session's refresh token fails with
     * `session_revoked`.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testRefreshRejectsTheRevokedSessionWithSessionRevokedReason(): void
    {
        [, $session] = $this->seedIdentityWithSession();

        $refreshToken = $this->authManager()->jwt('api')->issueRefreshToken($session, self::ROTATION_ID)->reveal();

        $this->revoke($session);

        Event::fake([AuthenticationFailed::class]);

        self::assertNull(
            GuardSessions::of($this->guardForRequest(Request::create('/refresh', 'POST')))->refresh(PresentedRefreshToken::fromBody($refreshToken), self::requestClient())->session,
        );

        Event::assertDispatched(
            AuthenticationFailed::class,
            static fn (AuthenticationFailed $event): bool => $event->reason === FailureReason::SESSION_REVOKED,
        );
    }

    /**
     * Configure the JWT guard over the uncast session model.
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

        $config->set('authentication.session.model', UncastSession::class);
        $config->set('auth.guards.api', ['driver' => 'jwt', 'provider' => 'identities', 'application' => ['methods' => ['password']]]);
        $config->set('auth.providers.identities', ['driver' => 'model', 'model' => UncastSessionIdentity::class]);

        // Failed attempts wait out the timebox; keep it short.
        $config->set('authentication.timebox.credentials_microseconds', 1);
    }

    /**
     * Persist an identity with one live session holding a refresh digest.
     *
     * @return array{0: \Tests\Integration\Fixtures\UncastSessionIdentity, 1: \Tests\Integration\Fixtures\UncastSession}
     */
    private function seedIdentityWithSession(): array
    {
        $identity = new UncastSessionIdentity;
        $identity->forceFill([
            'email'    => 'uncast@example.test',
            'password' => app(Hasher::class)->make(self::PASSWORD),
        ])->save();

        $session = $identity->sessions()->make();
        $session->forceFill([...self::liveSession(principal: $identity), 'refresh_key' => RefreshTokenHasher::hash(self::ROTATION_ID)])->save();

        return [$identity, $session];
    }

    /**
     * Revoke the session as the refresh exchange does: set the revocation time
     * and clear the refresh digest through the query builder.
     *
     * @param  \Tests\Integration\Fixtures\UncastSession  $session
     * @return void
     */
    private function revoke(UncastSession $session): void
    {
        DB::table('authentication_sessions')
            ->where('id', $session->getKey())
            ->update(['refresh_key' => null, 'revoked_at' => Carbon::now()]);
    }

    /**
     * Build a request carrying the bearer token.
     *
     * @param  string  $token
     * @return \Illuminate\Http\Request
     */
    private function bearerRequest(string $token): Request
    {
        return Request::create('/me', 'GET', server: ['HTTP_AUTHORIZATION' => 'Bearer ' . $token]);
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
     * @return \SineMacula\Laravel\Authentication\Guards\JwtGuard
     */
    private function guardForRequest(Request $request): JwtGuard
    {
        app()->instance('request', $request);

        $guard = $this->authManager()->guard('api');

        assert($guard instanceof JwtGuard);

        return $guard;
    }
}
