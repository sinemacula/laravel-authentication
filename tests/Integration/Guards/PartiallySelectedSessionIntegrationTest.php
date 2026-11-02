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
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Authentication\AuthManager;
use SineMacula\Laravel\Authentication\Concerns\ActsAsSession;
use SineMacula\Laravel\Authentication\Guards\Concerns\VerifiesPinnedContext;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenExchange;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenHasher;
use SineMacula\Laravel\Authentication\Models\Session;
use Tests\Concerns\InteractsWithSessionRecords;
use Tests\Fixtures\Sessions\GuardSessions;
use Tests\Integration\Fixtures\PartiallySelectedSession;
use Tests\Integration\Fixtures\PartiallySelectedSessionIdentity;
use Tests\TestCase;

/**
 * A revoked session loaded without its revocation column fails every
 * authentication path loudly instead of reading the missing value as "not
 * revoked", so a partial select surfaces as a misconfiguration rather than
 * admitting a revoked session.
 *
 * The bearer and pinned-session paths load the session through an identity
 * whose `sessions()` relation leaves `revoked_at` out; the refresh path loads
 * it through a session model whose global scope does.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(JwtGuard::class)]
#[CoversClass(RefreshTokenExchange::class)]
#[CoversTrait(ActsAsSession::class)]
#[CoversTrait(VerifiesPinnedContext::class)]
final class PartiallySelectedSessionIntegrationTest extends TestCase
{
    use InteractsWithSessionRecords;

    /** @var string Plaintext password of the seeded identity. */
    private const string PASSWORD = 'correct horse battery staple';

    /** @var string Plaintext rotation id the session's refresh digest is built from. */
    private const string ROTATION_ID = 'plain-rotation-id';

    /** @var string Message of the misconfiguration report. */
    private const string NOT_LOADED = 'its `revoked_at` attribute is not loaded';

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

        Schema::create('partially_selected_session_identities', static function (Blueprint $blueprint): void {
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
        Schema::dropIfExists('partially_selected_session_identities');

        Carbon::setTestNow();

        JWT::$timestamp = null;

        parent::tearDown();
    }

    /**
     * A bearer request naming a revoked session the relation loads without its
     * revocation column answers with a server error carrying the report, not
     * with the identity.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testBearerAnswersARevokedSessionLoadedWithoutItsRevocationWithAServerError(): void
    {
        [$identity, $session] = $this->seedIdentityWithRevokedSession();

        $token = $this->authManager()->jwt('api')->issueAccessToken($identity, $identity, null, $session)->reveal();

        Route::middleware('auth:api')->get('/me', static fn (): string => 'ok');

        $response = $this->withHeaders(['Authorization' => 'Bearer ' . $token])->getJson('/me');

        $response->assertInternalServerError();

        self::assertInstanceOf(\LogicException::class, $response->exception);
        self::assertStringContainsString(self::NOT_LOADED, $response->exception->getMessage());
    }

    /**
     * Pinning a revoked session the relation loads without its revocation
     * column reports the misconfiguration instead of signing in.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAttemptReportsAPinnedRevokedSessionLoadedWithoutItsRevocation(): void
    {
        [$identity, $session] = $this->seedIdentityWithRevokedSession();

        $guard = $this->guardForRequest(Request::create('/sign-in', 'POST'));

        try {
            $guard->attempt(['email' => $identity->email, 'password' => self::PASSWORD], null, $session);

            self::fail('The unloaded revocation column should have been reported.');
        } catch (\LogicException $exception) {
            self::assertStringContainsString(self::NOT_LOADED, $exception->getMessage());
        }

        self::assertFalse($guard->hasUser());
    }

    /**
     * Refreshing with the refresh token of a revoked session that the session
     * model loads without its revocation column reports the misconfiguration,
     * and leaves the stored digest untouched.
     *
     * @return void
     *
     * @throws \Random\RandomException
     * @throws \Throwable
     */
    public function testRefreshReportsARevokedSessionLoadedWithoutItsRevocation(): void
    {
        app(ConfigRepository::class)->set('authentication.session.model', PartiallySelectedSession::class);

        [$identity, $session] = $this->seedIdentityWithRevokedSession();

        $refreshToken = $this->authManager()->jwt('api')->issueRefreshToken($session, self::ROTATION_ID, $identity)->reveal();
        $guard        = $this->guardForRequest(Request::create('/refresh', 'POST'));

        try {
            GuardSessions::of($guard)->refresh($refreshToken);

            self::fail('The unloaded revocation column should have been reported.');
        } catch (\LogicException $exception) {
            self::assertStringContainsString(self::NOT_LOADED, $exception->getMessage());
        }

        self::assertFalse($guard->hasUser());
        self::assertSame(
            RefreshTokenHasher::hash(self::ROTATION_ID),
            DB::table('authentication_sessions')->where('id', $session->getKey())->value('refresh_key'),
        );
    }

    /**
     * Configure the JWT guard over the identity with the narrowed relation.
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

        $config->set('auth.defaults.guard', 'api');
        $config->set('auth.guards.api', ['driver' => 'jwt', 'provider' => 'identities', 'application' => ['methods' => ['password']]]);
        $config->set('auth.providers.identities', ['driver' => 'model', 'model' => PartiallySelectedSessionIdentity::class]);

        // Failed attempts wait out the timebox; keep it short.
        $config->set('authentication.timebox.credentials_microseconds', 1);
    }

    /**
     * Persist an identity with one session that holds a refresh digest and is
     * revoked.
     *
     * @return array{0: \Tests\Integration\Fixtures\PartiallySelectedSessionIdentity, 1: \SineMacula\Laravel\Authentication\Models\Session}
     */
    private function seedIdentityWithRevokedSession(): array
    {
        $identity = new PartiallySelectedSessionIdentity;
        $identity->forceFill([
            'email'    => 'partial-session@example.test',
            'password' => app(Hasher::class)->make(self::PASSWORD),
        ])->save();

        $session = new Session;
        $session->forceFill([
            ...self::liveSession(),
            'authenticatable_type' => PartiallySelectedSessionIdentity::class,
            'authenticatable_id'   => $identity->getKey(),
            'refresh_key'          => RefreshTokenHasher::hash(self::ROTATION_ID),
            'revoked_at'           => Carbon::now(),
        ])->save();

        return [$identity, $session];
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
