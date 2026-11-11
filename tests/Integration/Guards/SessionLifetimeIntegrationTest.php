<?php

declare(strict_types = 1);

namespace Tests\Integration\Guards;

use Carbon\Carbon;
use Carbon\CarbonInterface;
use Firebase\JWT\JWT;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use Illuminate\Testing\TestResponse;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversTrait;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\AuthManager;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Guards\Concerns\VerifiesPinnedContext;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Http\PresentedRefreshToken;
use SineMacula\Laravel\Authentication\Jwt\Enums\Claims;
use SineMacula\Laravel\Authentication\Jwt\Enums\TokenType;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenService;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenExchange;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenHasher;
use SineMacula\Laravel\Authentication\Jwt\TokenLifetimes;
use SineMacula\Laravel\Authentication\Models\Session;
use Tests\Concerns\InspectsIssuanceGuards;
use Tests\Fixtures\Sessions\GuardSessions;
use Tests\TestCase;
use Tests\Unit\Stubs\StubPrincipal;

/**
 * Tests idle and absolute session lifetimes on the shipped sessions table.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(JwtGuard::class)]
#[CoversClass(JwtTokenService::class)]
#[CoversClass(RefreshTokenExchange::class)]
#[CoversClass(TokenLifetimes::class)]
#[CoversTrait(VerifiesPinnedContext::class)]
final class SessionLifetimeIntegrationTest extends TestCase
{
    use InspectsIssuanceGuards;

    /** @var string Plaintext rotation id of the session's first refresh token. */
    private const string ROTATION_ID = 'first-rotation-id';

    /** @var string Password of the seeded identity. */
    private const string PASSWORD = 'correct horse battery staple';

    /** @var string Guard whose idle lifetime is shorter than its access lifetime. */
    private const string BRIEF = 'brief';

    /** @var \Carbon\Carbon When the session starts. */
    private Carbon $signedInAt;

    /**
     * Freeze the clocks, create the identity table, and register a route behind
     * the `auth` middleware.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->signedInAt = Carbon::createStrict(2026, 4, 6, 12, 0, 0);

        $this->moveClockTo($this->signedInAt);

        Schema::create('stub_principals', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('email')->unique();
            $blueprint->string('password');
            $blueprint->boolean('is_active')->default(true);
            $blueprint->timestamps();
        });

        Route::middleware('auth:api')->get('/me', static fn (): array => ['session' => Auth::session()?->getSessionIdentifier()]);
        Route::middleware('auth:' . self::BRIEF)->get('/brief', static fn (): array => ['session' => Auth::session()?->getSessionIdentifier()]);
    }

    /**
     * Release the frozen clocks and drop the identity table.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Schema::dropIfExists('stub_principals');

        Carbon::setTestNow();
        JWT::$timestamp = null;

        parent::tearDown();
    }

    /**
     * A session stamped from the guard's lifetimes can be issued for without a
     * reload.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testSessionStampedFromTheGuardLifetimesCanBeIssuedForAtOnce(): void
    {
        [$identity, $session] = $this->signIn();

        $refresh = $this->claims($this->tokens()->issueRefreshToken($session, self::ROTATION_ID, $identity)->reveal(), TokenType::REFRESH);
        $access  = $this->claims($this->tokens()->issueAccessToken($identity, $identity, null, $session)->reveal(), TokenType::ACCESS);

        self::assertSame($this->signedInAt->getTimestamp() + 3600, $refresh[Claims::EXPIRES_AT->value]);
        self::assertSame($this->signedInAt->getTimestamp() + 300, $access[Claims::EXPIRES_AT->value]);
        self::assertSame($this->signedInAt->getTimestamp() + 36000, $this->stored($session)->getAbsoluteExpiresAt()?->getTimestamp());
    }

    /**
     * Rows of `[seconds to the idle deadline, seconds to the absolute deadline
     * or null for none, seconds the access token lasts]`.
     *
     * @return iterable<string, array{0: int, 1: ?int, 2: int}>
     */
    public static function provideSessionEnds(): iterable
    {
        yield from [
            'session outlasts the token' => [86400, 86400, 300],
            'absolute deadline first'    => [3600, 120, 120],
            'absolute deadline in 1 s'   => [3600, 1, 1],
            'idle deadline first'        => [120, 36000, 120],
            'idle deadline in 1 s'       => [1, 36000, 1],
            'no absolute deadline'       => [86400, null, 300],
            'no absolute, idle first'    => [120, null, 120],
        ];
    }

    /**
     * An access token never expires after its session's first deadline.
     *
     * @param  int  $idleIn
     * @param  ?int  $absoluteIn
     * @param  int  $expiresIn
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[DataProvider('provideSessionEnds')]
    public function testAnAccessTokenNeverOutlivesItsSession(int $idleIn, ?int $absoluteIn, int $expiresIn): void
    {
        [$identity, $session] = $this->signIn();

        $this->setDeadlines($session, $this->signedInAt->copy()->addSeconds($idleIn), $absoluteIn === null ? null : $this->signedInAt->copy()->addSeconds($absoluteIn));

        $access = $this->claims($this->issue(TokenType::ACCESS, $identity, $this->stored($session)), TokenType::ACCESS);

        self::assertSame($this->signedInAt->getTimestamp() + $expiresIn, $access[Claims::EXPIRES_AT->value]);
    }

    /**
     * Rows of `[token type]`.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Authentication\Jwt\Enums\TokenType}>
     */
    public static function provideTokenTypes(): iterable
    {
        yield from [
            'access token'  => [TokenType::ACCESS],
            'refresh token' => [TokenType::REFRESH],
        ];
    }

    /**
     * No token is issued from the second the idle deadline is reached.
     *
     * @param  \SineMacula\Laravel\Authentication\Jwt\Enums\TokenType  $type
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[DataProvider('provideTokenTypes')]
    public function testNoTokenIsIssuedFromTheSecondTheIdleDeadlineIsReached(TokenType $type): void
    {
        [$identity, $session] = $this->signIn();

        $idle = $this->signedInAt->copy()->addHour();

        $this->moveClockTo($idle->copy()->subSecond());

        self::assertSame($idle->getTimestamp(), $this->claims($this->issue($type, $identity, $session), $type)[Claims::EXPIRES_AT->value]);

        $this->moveClockTo($idle);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Cannot issue a token for a session that has ended or that has no idle deadline.');

        $this->issue($type, $identity, $session);
    }

    /**
     * Issuing for a session loaded without its deadline columns throws.
     *
     * @param  \SineMacula\Laravel\Authentication\Jwt\Enums\TokenType  $type
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[DataProvider('provideTokenTypes')]
    public function testIssuingReportsASessionLoadedWithoutItsDeadlines(TokenType $type): void
    {
        [$identity, $session] = $this->signIn();

        $partial = Session::query()->select(['id', 'authenticatable_type', 'authenticatable_id'])->findOrFail(self::modelKey($session));

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('its `idle_expires_at` attribute is not loaded');

        $this->issue($type, $identity, $partial);
    }

    /**
     * A refresh moves the idle deadline and keeps the absolute deadline.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testRefreshMovesTheIdleDeadlineAndKeepsTheAbsoluteDeadline(): void
    {
        [$identity, $session] = $this->signIn();

        $token = $this->tokens()->issueRefreshToken($session, self::ROTATION_ID, $identity)->reveal();

        $later = $this->signedInAt->copy()->addMinutes(40);

        $this->moveClockTo($later);

        $pair = GuardSessions::of($this->guard())->refresh(PresentedRefreshToken::fromBody($token), self::requestClient())->session?->tokens;

        self::assertNotNull($pair);

        $stored = $this->stored($session);

        self::assertSame($later->getTimestamp() + 3600, $stored->getIdleExpiresAt()?->getTimestamp());
        self::assertSame($this->signedInAt->getTimestamp() + 36000, $stored->getAbsoluteExpiresAt()?->getTimestamp());
        self::assertSame($later->getTimestamp() + 3600, $this->claims(self::bodyRefreshToken($pair), TokenType::REFRESH)[Claims::EXPIRES_AT->value]);
        self::assertSame($later->getTimestamp() + 300, $this->claims($pair->accessToken->reveal(), TokenType::ACCESS)[Claims::EXPIRES_AT->value]);
    }

    /**
     * A session that records no first factor is never refreshed, and nothing of
     * its rotation is written.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASessionThatRecordsNoFirstFactorIsNeverRefreshed(): void
    {
        $this->recordsSessionProofs = false;

        [$identity, $session] = $this->signIn();

        $token   = $this->tokens()->issueRefreshToken($session, self::ROTATION_ID, $identity)->reveal();
        $columns = ['refresh_key', 'previous_refresh_key', 'refresh_rotated_at', 'idle_expires_at'];
        $before  = (array) DB::table('authentication_sessions')->where('id', $session->getKey())->first($columns);

        $this->moveClockTo($this->signedInAt->copy()->addMinute());

        try {
            GuardSessions::of($this->guard())->refresh(PresentedRefreshToken::fromBody($token), self::requestClient());
            self::fail('Expected a session without a first factor to be refused a token.');
        } catch (\LogicException $exception) {
            self::assertSame('The session records no counting first factor, so no access token can say when or how it authenticated.', $exception->getMessage());
        }

        self::assertSame(0, DB::table('authentication_proofs')->count());
        self::assertSame($before, (array) DB::table('authentication_sessions')->where('id', $session->getKey())->first($columns));
    }

    /**
     * Access tokens never outlive an idle lifetime shorter than their own.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAccessTokensNeverOutliveAnIdleLifetimeShorterThanTheirOwn(): void
    {
        [$identity, $session] = $this->signIn(self::BRIEF);

        $access  = $this->tokens(self::BRIEF)->issueAccessToken($identity, $identity, null, $session)->reveal();
        $refresh = $this->tokens(self::BRIEF)->issueRefreshToken($session, self::ROTATION_ID, $identity)->reveal();
        $idle    = $this->signedInAt->getTimestamp() + 120;

        self::assertSame($idle, $this->claims($access, TokenType::ACCESS, self::BRIEF)[Claims::EXPIRES_AT->value]);
        self::assertSame($idle, $this->claims($refresh, TokenType::REFRESH, self::BRIEF)[Claims::EXPIRES_AT->value]);

        $refreshedAt = $this->signedInAt->copy()->addSeconds(90);

        $this->moveClockTo($refreshedAt);

        $this->bearer($access, '/brief')->assertOk()->assertExactJson(['session' => $session->getKey()]);

        $pair = GuardSessions::of($this->guard(self::BRIEF))->refresh(PresentedRefreshToken::fromBody($refresh), self::requestClient())->session?->tokens;

        self::assertNotNull($pair);
        self::assertSame($refreshedAt->getTimestamp() + 120, $this->claims($pair->accessToken->reveal(), TokenType::ACCESS, self::BRIEF)[Claims::EXPIRES_AT->value]);

        $this->moveClockTo($refreshedAt->copy()->addSeconds(119));

        $this->bearer($pair->accessToken->reveal(), '/brief')->assertOk()->assertExactJson(['session' => $session->getKey()]);

        $this->moveClockTo($refreshedAt->copy()->addSeconds(120));

        $this->bearer($pair->accessToken->reveal(), '/brief')->assertUnauthorized();
    }

    /**
     * A session kept alive by refreshing still ends at its absolute deadline.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testRefreshNeverExtendsTheSessionPastItsAbsoluteDeadline(): void
    {
        [$identity, $session] = $this->signIn();

        $absolute = $this->signedInAt->copy()->addHours(10);
        $token    = $this->tokens()->issueRefreshToken($session, self::ROTATION_ID, $identity)->reveal();

        foreach (range(50, 550, 50) as $minutes) {

            $this->moveClockTo($this->signedInAt->copy()->addMinutes($minutes));

            $pair = GuardSessions::of($this->guard())->refresh(PresentedRefreshToken::fromBody($token), self::requestClient())->session?->tokens;

            self::assertNotNull($pair);

            $token = self::bodyRefreshToken($pair);
        }

        $nearTheEnd = $absolute->copy()->subMinutes(2);

        $this->moveClockTo($nearTheEnd);

        $pair = GuardSessions::of($this->guard())->refresh(PresentedRefreshToken::fromBody($token), self::requestClient())->session?->tokens;

        self::assertNotNull($pair);
        self::assertSame($absolute->getTimestamp(), $this->stored($session)->getIdleExpiresAt()?->getTimestamp());
        self::assertSame($absolute->getTimestamp(), $this->stored($session)->getAbsoluteExpiresAt()?->getTimestamp());
        self::assertSame($absolute->getTimestamp(), $this->claims(self::bodyRefreshToken($pair), TokenType::REFRESH)[Claims::EXPIRES_AT->value]);
        self::assertSame($absolute->getTimestamp(), $this->claims($pair->accessToken->reveal(), TokenType::ACCESS)[Claims::EXPIRES_AT->value]);

        $this->moveClockTo($absolute);

        self::assertSame(FailureReason::SESSION_EXPIRED, $this->refreshFailure(self::bodyRefreshToken($pair)));
    }

    /**
     * Rows of `[seconds after sign-in to the idle deadline, seconds after
     * sign-in to the absolute deadline, seconds after sign-in to refresh at,
     * whether the refresh succeeds]` around each boundary second.
     *
     * @return iterable<string, array{0: int, 1: int, 2: int, 3: bool}>
     */
    public static function provideDeadlineBoundaries(): iterable
    {
        yield from [
            'one second before the idle deadline'     => [600, 36000, 599, true],
            'at the idle deadline'                    => [600, 36000, 600, false],
            'after the idle deadline'                 => [600, 36000, 601, false],
            'one second before the absolute deadline' => [36000, 600, 599, true],
            'at the absolute deadline'                => [36000, 600, 600, false],
        ];
    }

    /**
     * A refresh fails without revoking from the second either deadline is
     * reached.
     *
     * @param  int  $idleIn
     * @param  int  $absoluteIn
     * @param  int  $refreshIn
     * @param  bool  $succeeds
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[DataProvider('provideDeadlineBoundaries')]
    public function testRefreshFailsFromTheSecondEitherDeadlineIsReached(int $idleIn, int $absoluteIn, int $refreshIn, bool $succeeds): void
    {
        [$identity, $session] = $this->signIn();

        $this->setDeadlines($session, $this->signedInAt->copy()->addSeconds($idleIn), $this->signedInAt->copy()->addSeconds($absoluteIn));

        $token = $this->tokens()->issueRefreshToken($this->stored($session), self::ROTATION_ID, $identity)->reveal();

        $this->moveClockTo($this->signedInAt->copy()->addSeconds($refreshIn));

        $before = $this->storedRow($session);

        if ($succeeds) {
            self::assertNotNull(GuardSessions::of($this->guard())->refresh(PresentedRefreshToken::fromBody($token), self::requestClient())->session);

            return;
        }

        self::assertSame(FailureReason::SESSION_EXPIRED, $this->refreshFailure($token));
        self::assertSame(self::withoutIssuanceGuard($before), self::withoutIssuanceGuard($this->storedRow($session)));
        self::assertSame(1, self::issuanceGuardWrites($session->getKey()));
        self::assertNull($this->stored($session)->getRevokedAt());
    }

    /**
     * An unexpired access token for a session that has ended is rejected.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testBearerRejectsASessionThatHasEnded(): void
    {
        [$identity, $session] = $this->signIn();

        $token = $this->tokens()->issueAccessToken($identity, $identity, null, $session)->reveal();

        $this->bearer($token)->assertOk()->assertExactJson(['session' => $session->getKey()]);

        $this->setDeadlines($session, $this->signedInAt, $this->signedInAt->copy()->addHours(10));

        $this->bearer($token)->assertUnauthorized();
    }

    /**
     * An access token inside the JWT leeway is rejected once its session's
     * absolute deadline has passed.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testLeewayDoesNotOutliveTheAbsoluteDeadline(): void
    {
        [$identity, $session] = $this->signIn();

        $absolute = $this->signedInAt->copy()->addMinutes(2);

        $this->setDeadlines($session, $absolute, $absolute);

        $token = $this->tokens()->issueAccessToken($identity, $identity, null, $this->stored($session))->reveal();

        self::assertSame($absolute->getTimestamp(), $this->claims($token, TokenType::ACCESS)[Claims::EXPIRES_AT->value]);

        $this->moveClockTo($absolute->copy()->addSeconds(10));

        self::assertNotNull($this->tokens()->parse($token, TokenType::ACCESS));

        $this->bearer($token)->assertUnauthorized();
    }

    /**
     * A session that has ended cannot be pinned on sign-in.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAttemptCannotPinASessionThatHasEnded(): void
    {
        [$identity, $session] = $this->signIn();

        $credentials = ['email' => $identity->email, 'password' => self::PASSWORD];

        self::assertTrue($this->guard()->attempt($credentials, null, $session));

        $this->setDeadlines($session, $this->signedInAt->copy()->addHour(), $this->signedInAt);

        self::assertFalse($this->guard()->attempt($credentials, null, $session));
    }

    /**
     * A deadline moved before the rotation commits fails the refresh as
     * `rotation_conflict` without revoking.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testRotationConflictsWhenADeadlineMovesBeforeItCommits(): void
    {
        [$identity, $session] = $this->signIn();

        $token     = $this->tokens()->issueRefreshToken($session, self::ROTATION_ID, $identity)->reveal();
        $shortened = $this->signedInAt->copy()->addHours(2);

        $this->beforeTheRotation(fn () => $this->setDeadlines($session, $this->signedInAt->copy()->addHour(), $shortened));

        self::assertSame(FailureReason::ROTATION_CONFLICT, $this->refreshFailure($token));
        self::assertNull($this->stored($session)->getRevokedAt());
        self::assertSame(RefreshTokenHasher::hash(self::ROTATION_ID), $this->stored($session)->getRefreshKey());

        $pair = GuardSessions::of($this->guard())->refresh(PresentedRefreshToken::fromBody($token), self::requestClient())->session?->tokens;

        self::assertNotNull($pair);
        self::assertSame($shortened->getTimestamp(), $this->stored($session)->getAbsoluteExpiresAt()?->getTimestamp());
        self::assertSame($this->signedInAt->getTimestamp() + 3600, $this->claims(self::bodyRefreshToken($pair), TokenType::REFRESH)[Claims::EXPIRES_AT->value]);
    }

    /**
     * Configure the `api` guard with short lifetimes.
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
        $config->set('auth.providers.identities', ['driver' => 'model', 'model' => StubPrincipal::class]);
        $config->set('auth.guards.api', [
            'driver'      => 'jwt',
            'provider'    => 'identities',
            'application' => ['methods' => ['password']],
            'jwt'         => [
                'access_ttl_minutes'           => 5,
                'refresh_idle_ttl_minutes'     => 60,
                'refresh_absolute_ttl_minutes' => 600,
                'leeway_seconds'               => 30,
            ],
        ]);
        $config->set('auth.guards.' . self::BRIEF, [
            'driver'      => 'jwt',
            'provider'    => 'identities',
            'application' => ['methods' => ['password']],
            'jwt'         => [
                'access_ttl_minutes'           => 5,
                'refresh_idle_ttl_minutes'     => 2,
                'refresh_absolute_ttl_minutes' => 600,
                'leeway_seconds'               => 30,
            ],
        ]);
    }

    /**
     * Persist an identity and sign it in on a new session stamped with the
     * guard's lifetimes.
     *
     * @param  string  $guard
     * @return array{0: \Tests\Unit\Stubs\StubPrincipal, 1: \SineMacula\Laravel\Authentication\Models\Session}
     */
    private function signIn(string $guard = 'api'): array
    {
        $identity            = new StubPrincipal;
        $identity->email     = 'session@example.test';
        $identity->password  = app(Hasher::class)->make(self::PASSWORD);
        $identity->is_active = true;
        $identity->save();

        $lifetimes = $this->tokens($guard)->lifetimes();
        $absolute  = $lifetimes->absoluteDeadline(Carbon::now());

        $session = new Session(['client_name' => 'Phone', 'platform' => 'iOS']);

        $session->forceFill([
            'authenticatable_type' => StubPrincipal::class,
            'authenticatable_id'   => (string) $identity->getKey(), // @phpstan-ignore cast.string
            'principal_type'       => $identity->getMorphClass(),
            'principal_id'         => (string) $identity->getKey(), // @phpstan-ignore cast.string
            'guard'                => $guard,
            'status'               => 'active',
            'tenant_id'            => null,
            'switched_at'          => null,
            'sign_in_method'       => 'password',
            'refresh_key'          => RefreshTokenHasher::hash(self::ROTATION_ID),
            'signed_in_at'         => Carbon::now(),
            'idle_expires_at'      => $lifetimes->idleDeadline(Carbon::now(), $absolute),
            'absolute_expires_at'  => $absolute,
        ])->save();

        return [$identity, $session];
    }

    /**
     * Overwrite a session's deadlines on the row, `null` for no absolute one.
     *
     * @param  \SineMacula\Laravel\Authentication\Models\Session  $session
     * @param  \Carbon\CarbonInterface  $idle
     * @param  ?\Carbon\CarbonInterface  $absolute
     * @return void
     */
    private function setDeadlines(Session $session, CarbonInterface $idle, ?CarbonInterface $absolute): void
    {
        Session::query()->whereKey($session->getKey())->update([
            'idle_expires_at'     => $idle,
            'absolute_expires_at' => $absolute,
        ]);
    }

    /**
     * Run a callback once, just before the rotation's compare-and-swap update
     * executes.
     *
     * @param  \Closure(): void  $callback
     * @return void
     */
    private function beforeTheRotation(\Closure $callback): void
    {
        $ran = false;

        DB::connection()->beforeExecuting(static function (string $query) use (&$ran, $callback): void {
            if ($ran || !str_starts_with(strtolower($query), 'update') || !str_contains($query, 'refresh_key')) {
                return;
            }

            $ran = true;

            $callback();
        });
    }

    /**
     * Refresh with a token that must fail, and return the reason.
     *
     * @param  string  $token
     * @return ?\SineMacula\Laravel\Authentication\Events\Enums\FailureReason
     *
     * @throws \Random\RandomException
     */
    private function refreshFailure(#[\SensitiveParameter] string $token): ?FailureReason
    {
        $reasons = [];

        Event::listen(AuthenticationFailed::class, static function (AuthenticationFailed $event) use (&$reasons): void {
            $reasons[] = $event->reason;
        });

        self::assertNull(GuardSessions::of($this->guard())->refresh(PresentedRefreshToken::fromBody($token), self::requestClient())->session);

        return $reasons[0] ?? null;
    }

    /**
     * Send a bearer request to a protected route.
     *
     * @param  string  $token
     * @param  string  $path
     * @return \Illuminate\Testing\TestResponse<\Symfony\Component\HttpFoundation\Response>
     */
    private function bearer(#[\SensitiveParameter] string $token, string $path = '/me'): TestResponse
    {
        return $this->withHeaders(['Authorization' => 'Bearer ' . $token])->getJson($path);
    }

    /**
     * Issue a token of the given type for the session.
     *
     * @param  \SineMacula\Laravel\Authentication\Jwt\Enums\TokenType  $type
     * @param  \Tests\Unit\Stubs\StubPrincipal  $identity
     * @param  \SineMacula\Laravel\Authentication\Models\Session  $session
     * @return string
     *
     * @throws \Random\RandomException
     */
    private function issue(TokenType $type, StubPrincipal $identity, Session $session): string
    {
        return $type === TokenType::ACCESS
            ? $this->tokens()->issueAccessToken($identity, $identity, null, $session)->reveal()
            : $this->tokens()->issueRefreshToken($session, self::ROTATION_ID, $identity)->reveal();
    }

    /**
     * Decode a token's claims through the guard's token service.
     *
     * @param  string  $token
     * @param  \SineMacula\Laravel\Authentication\Jwt\Enums\TokenType  $type
     * @param  string  $guard
     * @return array<string, mixed>
     */
    private function claims(#[\SensitiveParameter] string $token, TokenType $type, string $guard = 'api'): array
    {
        $claims = $this->tokens($guard)->parse($token, $type);

        self::assertIsArray($claims);

        return $claims;
    }

    /**
     * Reload a session from the database.
     *
     * @param  \SineMacula\Laravel\Authentication\Models\Session  $session
     * @return \SineMacula\Laravel\Authentication\Models\Session
     */
    private function stored(Session $session): Session
    {
        return Session::query()->whereKey($session->getKey())->firstOrFail();
    }

    /**
     * Read a session's raw row.
     *
     * @param  \SineMacula\Laravel\Authentication\Models\Session  $session
     * @return array<string, mixed>
     */
    private function storedRow(Session $session): array
    {
        return (array) DB::table('authentication_sessions')->where('id', $session->getKey())->first();
    }

    /**
     * Move the application and JWT clocks to the given time.
     *
     * @param  \Carbon\Carbon  $at
     * @return void
     */
    private function moveClockTo(Carbon $at): void
    {
        Carbon::setTestNow($at);

        JWT::$timestamp = $at->getTimestamp();
    }

    /**
     * The given guard's token service.
     *
     * @param  string  $guard
     * @return \SineMacula\Laravel\Authentication\Jwt\JwtTokenService
     */
    private function tokens(string $guard = 'api'): JwtTokenService
    {
        $tokens = Auth::jwt($guard);

        self::assertNotNull($tokens);

        return $tokens;
    }

    /**
     * A fresh instance of the given guard.
     *
     * @param  string  $name
     * @return \SineMacula\Laravel\Authentication\Guards\JwtGuard
     */
    private function guard(string $name = 'api'): JwtGuard
    {
        $manager = app('auth');

        assert($manager instanceof AuthManager);

        $manager->forgetGuards();

        $guard = $manager->guard($name);

        assert($guard instanceof JwtGuard);

        return $guard;
    }
}
