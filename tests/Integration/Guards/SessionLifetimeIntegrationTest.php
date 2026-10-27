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
use SineMacula\Laravel\Authentication\Events\Enums\RefreshFailureReason;
use SineMacula\Laravel\Authentication\Events\RefreshFailed;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Guards\Concerns\VerifiesPinnedContext;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Jwt\Enums\Claims;
use SineMacula\Laravel\Authentication\Jwt\Enums\TokenType;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenService;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenExchange;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenHasher;
use SineMacula\Laravel\Authentication\Jwt\TokenLifetimes;
use SineMacula\Laravel\Authentication\Models\Device;
use Tests\TestCase;
use Tests\Unit\Stubs\StubPrincipal;

/**
 * End-to-end tests for idle and absolute session lifetimes on the shipped
 * devices table: a refresh moves the idle deadline forward but never past the
 * absolute deadline, which never moves; tokens mirror the deadlines; and a
 * session past either deadline is over on every path, the bearer path, sign-in
 * pins, and refresh, whatever its tokens say.
 *
 * The `api` guard uses 5-minute access tokens, a 1-hour idle lifetime, a
 * 10-hour absolute lifetime, and 30 seconds of leeway. The `brief` guard keeps
 * the access lifetime and the leeway but has a 2-minute idle lifetime, shorter
 * than its access tokens'.
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
    /** @var string Plaintext rotation id of the device's first refresh token. */
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

        Route::middleware('auth:api')->get('/me', static fn (): array => ['device' => Auth::device()?->getDeviceIdentifier()]);
        Route::middleware('auth:' . self::BRIEF)->get('/brief', static fn (): array => ['device' => Auth::device()?->getDeviceIdentifier()]);
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
     * A device created with deadlines stamped from the guard's lifetimes can be
     * issued for straight away, without a reload: `forceFill()` keeps the
     * deadlines in the model's attributes. The refresh token expires at the
     * idle deadline and the access token after the access lifetime.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testDeviceStampedFromTheGuardLifetimesCanBeIssuedForAtOnce(): void
    {
        [$identity, $device] = $this->signIn();

        $refresh = $this->claims($this->tokens()->issueRefreshToken($device, self::ROTATION_ID, $identity), TokenType::REFRESH);
        $access  = $this->claims($this->tokens()->issueAccessToken($identity, $identity, $device), TokenType::ACCESS);

        self::assertSame($this->signedInAt->getTimestamp() + 3600, $refresh[Claims::EXPIRES_AT->value]);
        self::assertSame($this->signedInAt->getTimestamp() + 300, $access[Claims::EXPIRES_AT->value]);
        self::assertSame($this->signedInAt->getTimestamp() + 36000, $this->stored($device)->getAbsoluteExpiresAt()?->getTimestamp());
    }

    /**
     * Rows of `[token type]`: each kind of token the guard's service issues.
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
     * A device stamped from the guard's lifetimes is issued for up to the last
     * second before its idle deadline, with the token expiring at that
     * deadline; from the deadline on, issuing through `Auth::jwt()` refuses.
     *
     * @param  \SineMacula\Laravel\Authentication\Jwt\Enums\TokenType  $type
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[DataProvider('provideTokenTypes')]
    public function testNoTokenIsIssuedFromTheSecondTheIdleDeadlineIsReached(TokenType $type): void
    {
        [$identity, $device] = $this->signIn();

        $idle = $this->signedInAt->copy()->addHour();

        $this->moveClockTo($idle->copy()->subSecond());

        self::assertSame($idle->getTimestamp(), $this->claims($this->issue($type, $identity, $device), $type)[Claims::EXPIRES_AT->value]);

        $this->moveClockTo($idle);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Cannot issue a token for a device whose session has ended or that has no idle and absolute deadlines.');

        $this->issue($type, $identity, $device);
    }

    /**
     * A device loaded without its deadline columns cannot be issued for: the
     * missing deadline is reported rather than read as "no session" or as a
     * live one.
     *
     * @param  \SineMacula\Laravel\Authentication\Jwt\Enums\TokenType  $type
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[DataProvider('provideTokenTypes')]
    public function testIssuingReportsADeviceLoadedWithoutItsDeadlines(TokenType $type): void
    {
        [$identity, $device] = $this->signIn();

        $partial = Device::query()->select(['id', 'authenticatable_type', 'authenticatable_id'])->findOrFail($device->getKey());

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('its `idle_expires_at` attribute is not loaded');

        $this->issue($type, $identity, $partial);
    }

    /**
     * A refresh moves the idle deadline to the idle lifetime from now, keeps
     * the absolute deadline exactly where the sign-in put it, and issues a
     * refresh token that expires at the new idle deadline.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testRefreshMovesTheIdleDeadlineAndKeepsTheAbsoluteDeadline(): void
    {
        [$identity, $device] = $this->signIn();

        $token = $this->tokens()->issueRefreshToken($device, self::ROTATION_ID, $identity);

        $later = $this->signedInAt->copy()->addMinutes(40);

        $this->moveClockTo($later);

        $pair = $this->guard()->refresh($token);

        self::assertNotNull($pair);

        $stored = $this->stored($device);

        self::assertSame($later->getTimestamp() + 3600, $stored->getIdleExpiresAt()?->getTimestamp());
        self::assertSame($this->signedInAt->getTimestamp() + 36000, $stored->getAbsoluteExpiresAt()?->getTimestamp());
        self::assertSame($later->getTimestamp() + 3600, $this->claims($pair->refreshToken, TokenType::REFRESH)[Claims::EXPIRES_AT->value]);
        self::assertSame($later->getTimestamp() + 300, $this->claims($pair->accessToken, TokenType::ACCESS)[Claims::EXPIRES_AT->value]);
    }

    /**
     * With an idle lifetime shorter than the access lifetime, an access token
     * expires at the session's idle deadline rather than after the access
     * lifetime, since the bearer path rejects it from that second: no token
     * outlives the session. A client that refreshes before the deadline keeps
     * the session alive, and each new access token stops at the new deadline.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAccessTokensNeverOutliveAnIdleLifetimeShorterThanTheirOwn(): void
    {
        [$identity, $device] = $this->signIn(self::BRIEF);

        $access  = $this->tokens(self::BRIEF)->issueAccessToken($identity, $identity, $device);
        $refresh = $this->tokens(self::BRIEF)->issueRefreshToken($device, self::ROTATION_ID, $identity);
        $idle    = $this->signedInAt->getTimestamp() + 120;

        self::assertSame($idle, $this->claims($access, TokenType::ACCESS, self::BRIEF)[Claims::EXPIRES_AT->value]);
        self::assertSame($idle, $this->claims($refresh, TokenType::REFRESH, self::BRIEF)[Claims::EXPIRES_AT->value]);

        $refreshedAt = $this->signedInAt->copy()->addSeconds(90);

        $this->moveClockTo($refreshedAt);

        $this->bearer($access, '/brief')->assertOk()->assertExactJson(['device' => $device->getKey()]);

        $pair = $this->guard(self::BRIEF)->refresh($refresh);

        self::assertNotNull($pair);
        self::assertSame($refreshedAt->getTimestamp() + 120, $this->claims($pair->accessToken, TokenType::ACCESS, self::BRIEF)[Claims::EXPIRES_AT->value]);

        $this->moveClockTo($refreshedAt->copy()->addSeconds(119));

        $this->bearer($pair->accessToken, '/brief')->assertOk()->assertExactJson(['device' => $device->getKey()]);

        $this->moveClockTo($refreshedAt->copy()->addSeconds(120));

        $this->bearer($pair->accessToken, '/brief')->assertUnauthorized();
    }

    /**
     * A session kept alive by refreshing every 50 minutes still ends at its
     * absolute deadline: near it, a refresh sets the idle deadline to the
     * absolute one, both new tokens expire no later than it, and from that
     * second on the session cannot be refreshed.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testRefreshNeverExtendsTheSessionPastItsAbsoluteDeadline(): void
    {
        [$identity, $device] = $this->signIn();

        $absolute = $this->signedInAt->copy()->addHours(10);
        $token    = $this->tokens()->issueRefreshToken($device, self::ROTATION_ID, $identity);

        foreach (range(50, 550, 50) as $minutes) {

            $this->moveClockTo($this->signedInAt->copy()->addMinutes($minutes));

            $pair = $this->guard()->refresh($token);

            self::assertNotNull($pair);

            $token = $pair->refreshToken;
        }

        $nearTheEnd = $absolute->copy()->subMinutes(2);

        $this->moveClockTo($nearTheEnd);

        $pair = $this->guard()->refresh($token);

        self::assertNotNull($pair);
        self::assertSame($absolute->getTimestamp(), $this->stored($device)->getIdleExpiresAt()?->getTimestamp());
        self::assertSame($absolute->getTimestamp(), $this->stored($device)->getAbsoluteExpiresAt()?->getTimestamp());
        self::assertSame($absolute->getTimestamp(), $this->claims($pair->refreshToken, TokenType::REFRESH)[Claims::EXPIRES_AT->value]);
        self::assertSame($absolute->getTimestamp(), $this->claims($pair->accessToken, TokenType::ACCESS)[Claims::EXPIRES_AT->value]);

        $this->moveClockTo($absolute);

        self::assertSame(RefreshFailureReason::SESSION_EXPIRED, $this->refreshFailure($pair->refreshToken));
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
     * A refresh at or after either deadline fails with `session_expired`,
     * writes nothing, and does not revoke the device: expiry is not revocation.
     * One second earlier, the same refresh succeeds.
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
        [$identity, $device] = $this->signIn();

        $this->setDeadlines($device, $this->signedInAt->copy()->addSeconds($idleIn), $this->signedInAt->copy()->addSeconds($absoluteIn));

        $token = $this->tokens()->issueRefreshToken($this->stored($device), self::ROTATION_ID, $identity);

        $this->moveClockTo($this->signedInAt->copy()->addSeconds($refreshIn));

        $before = $this->storedRow($device);

        if ($succeeds) {
            self::assertNotNull($this->guard()->refresh($token));

            return;
        }

        self::assertSame(RefreshFailureReason::SESSION_EXPIRED, $this->refreshFailure($token));
        self::assertSame($before, $this->storedRow($device));
        self::assertNull($this->stored($device)->getRevokedAt());
    }

    /**
     * An access token naming a device whose session has ended is rejected
     * through the middleware at once, even while the token itself has not
     * expired: shortening a deadline cuts access immediately.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testBearerRejectsADeviceWhoseSessionHasEnded(): void
    {
        [$identity, $device] = $this->signIn();

        $token = $this->tokens()->issueAccessToken($identity, $identity, $device);

        $this->bearer($token)->assertOk()->assertExactJson(['device' => $device->getKey()]);

        $this->setDeadlines($device, $this->signedInAt, $this->signedInAt->copy()->addHours(10));

        $this->bearer($token)->assertUnauthorized();
    }

    /**
     * JWT leeway never stretches a session: an access token past its expiry but
     * inside the leeway still parses, yet is rejected once its device's
     * absolute deadline has passed.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testLeewayDoesNotOutliveTheAbsoluteDeadline(): void
    {
        [$identity, $device] = $this->signIn();

        $absolute = $this->signedInAt->copy()->addMinutes(2);

        $this->setDeadlines($device, $absolute, $absolute);

        $token = $this->tokens()->issueAccessToken($identity, $identity, $this->stored($device));

        self::assertSame($absolute->getTimestamp(), $this->claims($token, TokenType::ACCESS)[Claims::EXPIRES_AT->value]);

        $this->moveClockTo($absolute->copy()->addSeconds(10));

        self::assertNotNull($this->tokens()->parse($token, TokenType::ACCESS));

        $this->bearer($token)->assertUnauthorized();
    }

    /**
     * A device whose session has ended cannot be pinned on sign-in.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAttemptCannotPinADeviceWhoseSessionHasEnded(): void
    {
        [$identity, $device] = $this->signIn();

        $credentials = ['email' => $identity->email, 'password' => self::PASSWORD];

        self::assertTrue($this->guard()->attempt($credentials, null, $device));

        $this->setDeadlines($device, $this->signedInAt->copy()->addHour(), $this->signedInAt);

        self::assertFalse($this->guard()->attempt($credentials, null, $device));
    }

    /**
     * The rotation compares both deadlines with what it read: a deadline moved
     * by another writer between the read and the rotation, even to a time still
     * in the future, makes the rotation miss. The token is still the current
     * one, so that proves nothing: the refresh fails as `rotation_conflict`
     * without writing or revoking, and a retry succeeds under the moved
     * deadline.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testRotationConflictsWhenADeadlineMovesBeforeItCommits(): void
    {
        [$identity, $device] = $this->signIn();

        $token     = $this->tokens()->issueRefreshToken($device, self::ROTATION_ID, $identity);
        $shortened = $this->signedInAt->copy()->addHours(2);

        $this->beforeTheRotation(fn () => $this->setDeadlines($device, $this->signedInAt->copy()->addHour(), $shortened));

        self::assertSame(RefreshFailureReason::ROTATION_CONFLICT, $this->refreshFailure($token));
        self::assertNull($this->stored($device)->getRevokedAt());
        self::assertSame(RefreshTokenHasher::hash(self::ROTATION_ID), $this->stored($device)->getRefreshKey());

        $pair = $this->guard()->refresh($token);

        self::assertNotNull($pair);
        self::assertSame($shortened->getTimestamp(), $this->stored($device)->getAbsoluteExpiresAt()?->getTimestamp());
        self::assertSame($this->signedInAt->getTimestamp() + 3600, $this->claims($pair->refreshToken, TokenType::REFRESH)[Claims::EXPIRES_AT->value]);
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
            'driver'   => 'jwt',
            'provider' => 'identities',
            'jwt'      => [
                'access_ttl_minutes'           => 5,
                'refresh_idle_ttl_minutes'     => 60,
                'refresh_absolute_ttl_minutes' => 600,
                'leeway_seconds'               => 30,
            ],
        ]);
        $config->set('auth.guards.' . self::BRIEF, [
            'driver'   => 'jwt',
            'provider' => 'identities',
            'jwt'      => [
                'access_ttl_minutes'           => 5,
                'refresh_idle_ttl_minutes'     => 2,
                'refresh_absolute_ttl_minutes' => 600,
                'leeway_seconds'               => 30,
            ],
        ]);
    }

    /**
     * Persist an identity and sign it in on a new device, stamped with the
     * guard's lifetimes as an application does before the device is created by
     * the package.
     *
     * @param  string  $guard
     * @return array{0: \Tests\Unit\Stubs\StubPrincipal, 1: \SineMacula\Laravel\Authentication\Models\Device}
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

        $device = new Device(['client_name' => 'Phone', 'platform' => 'iOS']);

        $device->forceFill([
            'authenticatable_type' => StubPrincipal::class,
            'authenticatable_id'   => (string) $identity->getKey(), // @phpstan-ignore cast.string
            'guard'                => $guard,
            'sign_in_method'       => 'password',
            'refresh_key'          => RefreshTokenHasher::hash(self::ROTATION_ID),
            'idle_expires_at'      => $lifetimes->idleDeadline(Carbon::now(), $absolute),
            'absolute_expires_at'  => $absolute,
        ])->save();

        return [$identity, $device];
    }

    /**
     * Overwrite a device's deadlines on the row.
     *
     * @param  \SineMacula\Laravel\Authentication\Models\Device  $device
     * @param  \Carbon\CarbonInterface  $idle
     * @param  \Carbon\CarbonInterface  $absolute
     * @return void
     */
    private function setDeadlines(Device $device, CarbonInterface $idle, CarbonInterface $absolute): void
    {
        Device::query()->whereKey($device->getKey())->update([
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
     * @return ?\SineMacula\Laravel\Authentication\Events\Enums\RefreshFailureReason
     *
     * @throws \Random\RandomException
     */
    private function refreshFailure(#[\SensitiveParameter] string $token): ?RefreshFailureReason
    {
        $reasons = [];

        Event::listen(RefreshFailed::class, static function (RefreshFailed $event) use (&$reasons): void {
            $reasons[] = $event->reason;
        });

        self::assertNull($this->guard()->refresh($token));

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
     * Issue a token of the given type for the device through the `api` guard's
     * token service.
     *
     * @param  \SineMacula\Laravel\Authentication\Jwt\Enums\TokenType  $type
     * @param  \Tests\Unit\Stubs\StubPrincipal  $identity
     * @param  \SineMacula\Laravel\Authentication\Models\Device  $device
     * @return string
     *
     * @throws \Random\RandomException
     */
    private function issue(TokenType $type, StubPrincipal $identity, Device $device): string
    {
        return $type === TokenType::ACCESS
            ? $this->tokens()->issueAccessToken($identity, $identity, $device)
            : $this->tokens()->issueRefreshToken($device, self::ROTATION_ID, $identity);
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
     * Reload a device from the database.
     *
     * @param  \SineMacula\Laravel\Authentication\Models\Device  $device
     * @return \SineMacula\Laravel\Authentication\Models\Device
     */
    private function stored(Device $device): Device
    {
        return Device::query()->whereKey($device->getKey())->firstOrFail();
    }

    /**
     * Read a device's raw row.
     *
     * @param  \SineMacula\Laravel\Authentication\Models\Device  $device
     * @return array<string, mixed>
     */
    private function storedRow(Device $device): array
    {
        return (array) DB::table('devices')->where('id', $device->getKey())->first();
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
