<?php

declare(strict_types = 1);

namespace Tests\Integration\Sessions;

use Carbon\CarbonImmutable;
use Firebase\JWT\JWT;
use Illuminate\Auth\Events\Logout;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Foundation\Application;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\SessionRevoked;
use SineMacula\Laravel\Authentication\Http\Enums\RefreshTokenSource;
use SineMacula\Laravel\Authentication\Http\PresentedRefreshToken;
use SineMacula\Laravel\Authentication\Sessions\RefreshProof;
use SineMacula\Laravel\Authentication\Sessions\SessionService;
use SineMacula\Laravel\Authentication\Sessions\SessionSignOut;
use Tests\Concerns\InteractsWithSessions;
use Tests\TestCase;

/**
 * Integration tests of signing out by refresh token against the database.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SessionSignOut::class)]
#[CoversClass(RefreshProof::class)]
final class SessionSignOutTest extends TestCase
{
    use InteractsWithSessions;

    /** @var list<class-string> Every event a sign-out could dispatch. */
    private const array EVENTS = [SessionRevoked::class, Logout::class, AuthenticationFailed::class];

    /**
     * Freeze the clocks and create the tables.
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
     * A sign-out writes the revocation and its reason and clears the refresh
     * digests.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASignOutWritesTheRevocationAndItsReason(): void
    {
        $this->seedIdentity();

        $token  = $this->signedIn();
        $before = (array) DB::table('authentication_sessions')->sole();

        $this->moveTo(CarbonImmutable::now()->addMinute());

        self::assertTrue($this->sessions()->signOutWith(PresentedRefreshToken::fromBody($token), self::requestClient())->isSignedOut());

        $after = (array) DB::table('authentication_sessions')->sole();

        self::assertSame('signed_out', $after['revoked_reason']);
        self::assertIsString($after['revoked_at']);
        self::assertEquals(CarbonImmutable::now(), CarbonImmutable::parse($after['revoked_at']));
        self::assertSame([null, null], [$after['refresh_key'], $after['previous_refresh_key']]);

        $written = ['revoked_at', 'revoked_reason', 'refresh_key', 'previous_refresh_key', 'updated_at'];

        self::assertEquals(array_diff_key($before, array_flip($written)), array_diff_key($after, array_flip($written)));
    }

    /**
     * A token a refresh just replaced still signs the session out within the
     * grace window.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATokenARefreshJustReplacedStillSignsTheSessionOut(): void
    {
        $this->seedIdentity();

        $replaced  = $this->signedIn();
        $refreshed = $this->sessions()->refresh(PresentedRefreshToken::fromBody($replaced), self::requestClient())->session?->tokens->refreshToken?->reveal();

        self::assertIsString($refreshed);

        $this->moveTo(CarbonImmutable::now()->addSeconds(5));

        self::assertTrue($this->sessions()->signOutWith(PresentedRefreshToken::fromBody($replaced), self::requestClient())->isSignedOut());
        self::assertSame('signed_out', DB::table('authentication_sessions')->value('revoked_reason'));
        self::assertSame(FailureReason::SESSION_REVOKED, $this->sessions()->refresh(PresentedRefreshToken::fromBody($refreshed), self::requestClient())->reason);
    }

    /**
     * A rotation between the proof and the revocation still signs the session
     * out.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARotationBetweenTheProofAndTheRevocationStillSignsOut(): void
    {
        $this->seedIdentity();

        $token = $this->signedIn();

        /** @var \ArrayObject<string, bool|string|null> $armed */
        $armed = new \ArrayObject(['armed' => true, 'issued' => null]);

        DB::listen(function (QueryExecuted $query) use ($token, $armed): void {

            if ($armed['armed'] !== true || !str_starts_with(strtolower(ltrim($query->sql)), 'select') || !str_contains($query->sql, 'authentication_sessions')) {
                return;
            }

            $armed['armed'] = false;

            $armed['issued'] = $this->sessions()->refresh(PresentedRefreshToken::fromBody($token), self::requestClient())->session?->tokens->refreshToken?->reveal();
        });

        $this->recordEvents([SessionRevoked::class, Logout::class]);

        self::assertTrue($this->sessions()->signOutWith(PresentedRefreshToken::fromBody($token), self::requestClient())->isSignedOut());
        self::assertIsString($armed['issued']);
        self::assertSame([SessionRevoked::class, Logout::class], $this->recordedClasses());
        self::assertSame('signed_out', DB::table('authentication_sessions')->value('revoked_reason'));
        self::assertSame(FailureReason::SESSION_REVOKED, $this->sessions()->refresh(PresentedRefreshToken::fromBody($armed['issued']), self::requestClient())->reason);
    }

    /**
     * Two sign-outs with the same token revoke and report once.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTwoSignOutsRevokeOnce(): void
    {
        $this->seedIdentity();

        $token = $this->signedIn();

        $this->recordEvents(self::EVENTS);

        self::assertTrue($this->sessions()->signOutWith(PresentedRefreshToken::fromBody($token), self::requestClient())->isSignedOut());

        $second = $this->sessions()->signOutWith(PresentedRefreshToken::fromBody($token), self::requestClient());

        self::assertFalse($second->isSignedOut());
        self::assertSame(FailureReason::SESSION_REVOKED, $second->reason);
        self::assertSame([SessionRevoked::class, Logout::class, AuthenticationFailed::class], $this->recordedClasses());
    }

    /**
     * A session revoked after the proof keeps the other writer's revocation.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASessionRevokedAfterTheProofIsNotRevokedAgain(): void
    {
        $this->seedIdentity();

        $token    = $this->signedIn();
        $sessions = $this->sessions();
        $armed    = new \ArrayObject(['armed' => true]);

        DB::listen(static function (QueryExecuted $query) use ($armed): void {

            if ($armed['armed'] !== true || !str_starts_with(strtolower(ltrim($query->sql)), 'select') || !str_contains($query->sql, 'authentication_sessions')) {
                return;
            }

            $armed['armed'] = false;

            DB::table('authentication_sessions')->update(['revoked_at' => CarbonImmutable::now(), 'revoked_reason' => 'revoked']);
        });

        $this->recordEvents(self::EVENTS);

        $result = $sessions->signOutWith(PresentedRefreshToken::fromBody($token), self::requestClient());

        self::assertFalse($armed['armed']);
        self::assertFalse($result->isSignedOut());
        self::assertFalse($result->isFailed());
        self::assertSame([], $this->recordedClasses());
        self::assertSame('revoked', DB::table('authentication_sessions')->value('revoked_reason'));
    }

    /**
     * A sign-out inside the caller's transaction is reported once it commits.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheRevocationIsReportedOnceTheCallerCommits(): void
    {
        $this->seedIdentity();

        $token = $this->signedIn();

        $this->recordEvents([SessionRevoked::class]);

        DB::transaction(function () use ($token): void {

            self::assertTrue($this->sessions()->signOutWith(PresentedRefreshToken::fromBody($token), self::requestClient())->isSignedOut());
            self::assertSame([], $this->recordedClasses());
        });

        self::assertSame([SessionRevoked::class], $this->recordedClasses());
    }

    /**
     * A cookie application's plain sign-out writes the revocation once.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPlainSignOutWritesTheRevocationOnce(): void
    {
        $this->seedIdentity();

        $cookie = $this->sessions('admin')->signIn('password', self::credentials(), self::requestContext())->session?->tokens->refreshCookie?->cookie()->getValue();

        self::assertIsString($cookie);

        $presented = self::presentedToken($cookie, RefreshTokenSource::COOKIE);
        $client    = self::sameSiteClient();

        $this->recordEvents(self::EVENTS);

        DB::transaction(function () use ($presented, $client): void {
            self::assertTrue($this->crossSiteSessions()->signOutWith($presented, $client)->isSignedOut());
            self::assertSame([Logout::class], $this->recordedClasses());
        });

        $after = (array) DB::table('authentication_sessions')->sole();

        self::assertSame('signed_out', $after['revoked_reason']);
        self::assertSame([null, null], [$after['refresh_key'], $after['previous_refresh_key']]);
        self::assertSame([Logout::class, SessionRevoked::class], $this->recordedClasses());
        self::assertSame($client, $this->recordedEvent(SessionRevoked::class)->context->client);

        $second = $this->crossSiteSessions()->signOutWith($presented, $client);

        self::assertSame([false, FailureReason::SESSION_REVOKED], [$second->isSignedOut(), $second->reason]);
        self::assertCount(1, array_filter($this->recorded, static fn (object $event): bool => $event instanceof SessionRevoked));
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

        $config = $app->make(ConfigRepository::class);

        self::configureSessionGuards($config);

        $config->set('auth.guards.admin.refresh_token', ['transport' => 'cookie', 'cookie' => ['path' => '/auth']]);
    }

    /**
     * The cookie application's session service for a cross-site request without
     * a refresh token.
     *
     * @return \SineMacula\Laravel\Authentication\Sessions\SessionService
     */
    private function crossSiteSessions(): SessionService
    {
        return self::sessionsOf($this->crossSiteGuard('admin'));
    }

    /**
     * Sign the seeded identity in on `api` and return its refresh token.
     *
     * @return string
     *
     * @throws \Throwable
     */
    private function signedIn(): string
    {
        $token = $this->sessions()->signIn('password', self::credentials(), self::requestContext())->session?->tokens->refreshToken?->reveal();

        self::assertIsString($token);

        return $token;
    }

    /**
     * Move the clocks, and the token library's, to the moment.
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
