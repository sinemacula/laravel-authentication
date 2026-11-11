<?php

declare(strict_types = 1);

namespace Tests\Integration\Guards;

use Carbon\Carbon;
use Carbon\CarbonImmutable;
use Firebase\JWT\JWT;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\ConnectionResolverInterface;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversTrait;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\AuthManager;
use SineMacula\Laravel\Authentication\Concerns\ActsAsSession;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Http\PresentedRefreshToken;
use SineMacula\Laravel\Authentication\Jwt\Enums\Claims;
use SineMacula\Laravel\Authentication\Jwt\Enums\TokenType;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenService;
use SineMacula\Laravel\Authentication\Jwt\RefreshRotationStore;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenExchange;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenHasher;
use SineMacula\Laravel\Authentication\Listeners\RecordSessionUsage;
use SineMacula\Laravel\Authentication\Models\Session;
use Tests\Fixtures\Sessions\GuardSessions;
use Tests\TestCase;
use Tests\Unit\Stubs\StubPrincipal;

/**
 * Tests session times stored around the hour that repeats when the clocks go
 * back, on the shipped sessions table of each engine.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(JwtTokenService::class)]
#[CoversClass(RefreshRotationStore::class)]
#[CoversClass(RefreshTokenExchange::class)]
#[CoversClass(RecordSessionUsage::class)]
#[CoversTrait(ActsAsSession::class)]
final class RepeatedHourStorageIntegrationTest extends TestCase
{
    /** @var string Plaintext rotation id of the session's first refresh token. */
    private const string ROTATION_ID = 'first-rotation-id';

    /** @var string A timezone whose clocks go back at 06:00 UTC on 1 November 2026. */
    private const string DAYLIGHT_SAVING_ZONE = 'America/New_York';

    /** @var string A timezone whose clocks go back at 01:00 UTC on 25 October 2026. */
    private const string LONDON = 'Europe/London';

    /** @var string The application timezone before the test changed it. */
    private string $timezone;

    /**
     * Create the identity table.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->timezone = date_default_timezone_get();

        Schema::create('stub_principals', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('email')->unique();
            $blueprint->string('password');
            $blueprint->boolean('is_active')->default(true);
            $blueprint->timestamps();
        });

        Route::middleware('auth:api')->get('/me', static fn (): array => ['session' => Auth::session()?->getSessionIdentifier()]);
    }

    /**
     * Release the frozen clocks, restore the timezone, and drop the identity
     * table.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Schema::dropIfExists('stub_principals');

        Carbon::setTestNow();
        JWT::$timestamp = null;

        date_default_timezone_set($this->timezone);

        parent::tearDown();
    }

    /**
     * Rows of `[timezone, a time (UTC), the wall-clock time stored, seconds
     * early it reads back]` around the repeated hour.
     *
     * @return iterable<string, array{0: string, 1: string, 2: string, 3: int}>
     */
    public static function provideTimesAroundTheRepeatedHour(): iterable
    {
        yield from [
            'New York, before'          => [self::DAYLIGHT_SAVING_ZONE, '2026-11-01 04:30:00', '2026-11-01 00:30:00', 0],
            'New York, the first pass'  => [self::DAYLIGHT_SAVING_ZONE, '2026-11-01 05:30:00', '2026-11-01 01:30:00', 0],
            'New York, the second pass' => [self::DAYLIGHT_SAVING_ZONE, '2026-11-01 06:30:00', '2026-11-01 01:30:00', 3600],
            'New York, after'           => [self::DAYLIGHT_SAVING_ZONE, '2026-11-01 07:30:00', '2026-11-01 02:30:00', 0],
            'London, the first pass'    => [self::LONDON, '2026-10-25 00:30:00', '2026-10-25 01:30:00', 0],
            'London, the second pass'   => [self::LONDON, '2026-10-25 01:30:00', '2026-10-25 01:30:00', 3600],
            'London, after'             => [self::LONDON, '2026-10-25 02:30:00', '2026-10-25 02:30:00', 0],
        ];
    }

    /**
     * With daylight saving, times stored in the repeated hour read back as the
     * first pass.
     *
     * @param  string  $timezone
     * @param  string  $utc
     * @param  string  $wallClock
     * @param  int  $earlyBy
     * @return void
     */
    #[DataProvider('provideTimesAroundTheRepeatedHour')]
    public function testTimesInTheRepeatedHourReadBackAsTheFirstPass(string $timezone, string $utc, string $wallClock, int $earlyBy): void
    {
        $at = $this->atUtc('2026-10-24 12:00:00', $timezone);

        [, $session] = $this->signIn($at, $at->copy()->addDays(2));

        $time = CarbonImmutable::parse($utc, 'UTC')->setTimezone($timezone);

        self::assertTrue($this->store()->rotate($session, self::ROTATION_ID, RefreshTokenHasher::successor(self::ROTATION_ID), $time, $time));

        $row    = $this->storedRow($session);
        $stored = $this->stored($session);

        self::assertSame($wallClock, $row['refresh_rotated_at']);
        self::assertSame($wallClock, $row['idle_expires_at']);
        self::assertSame($time->getTimestamp() - $earlyBy, $stored->getRefreshRotatedAt()?->getTimestamp());
        self::assertSame($time->getTimestamp() - $earlyBy, $stored->getIdleExpiresAt()?->getTimestamp());
    }

    /**
     * With UTC, a rotation at the end of the repeated hour keeps its grace
     * window.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testWithUtcARotationAtTheEndOfTheRepeatedHourKeepsItsGraceWindow(): void
    {
        [$token, $session] = $this->rotateAtTheEndOfTheRepeatedHourAndRetry('UTC');

        self::assertNotNull(GuardSessions::of($this->guard())->refresh(PresentedRefreshToken::fromBody($token), self::requestClient())->session);
        self::assertNull($this->stored($session)->getRevokedAt());
    }

    /**
     * With daylight saving, a rotation in the second pass reads back an hour
     * early and leaves no grace window.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testWithDaylightSavingARotationInTheSecondPassLeavesNoGraceWindow(): void
    {
        [$token, $session] = $this->rotateAtTheEndOfTheRepeatedHourAndRetry(self::DAYLIGHT_SAVING_ZONE);

        self::assertSame(FailureReason::ROTATION_REUSE, $this->refreshFailure($token));
        self::assertSame('rotation_reuse', $this->stored($session)->getRevokedReason());
    }

    /**
     * With daylight saving, a replay fifty minutes after a first-pass rotation
     * is not a grace retry.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testWithDaylightSavingAReplayAfterARotationInTheFirstPassIsNotAGraceRetry(): void
    {
        $replayAt = $this->atUtc('2026-10-25 01:20:00', self::LONDON);

        [$identity, $session] = $this->signIn($replayAt);

        $token     = $this->tokens()->issueRefreshToken($session, self::ROTATION_ID, $identity)->reveal();
        $rotatedAt = $replayAt->toImmutable()->subMinutes(50);

        self::assertTrue($this->store()->rotate($session, self::ROTATION_ID, RefreshTokenHasher::successor(self::ROTATION_ID), $rotatedAt->addHours(3), $rotatedAt));

        self::assertSame(FailureReason::ROTATION_REUSE, $this->refreshFailure($token));
        self::assertSame('rotation_reuse', $this->stored($session)->getRevokedReason());
    }

    /**
     * With daylight saving, a refresh whose idle deadline falls in the second
     * pass fails without writing.
     *
     * @return void
     *
     * @throws \Random\RandomException
     * @throws \Throwable
     */
    public function testWithDaylightSavingARefreshSettingAnIdleDeadlineInTheSecondPassFailsWithoutWriting(): void
    {
        $now = $this->atUtc('2026-11-01 05:30:00', self::DAYLIGHT_SAVING_ZONE);

        [$identity, $session] = $this->signIn($now);

        $token = $this->tokens()->issueRefreshToken($session, self::ROTATION_ID, $identity)->reveal();

        try {
            GuardSessions::of($this->guard())->refresh(PresentedRefreshToken::fromBody($token), self::requestClient());

            self::fail('The refresh should not have been able to issue tokens.');
        } catch (\InvalidArgumentException $exception) {
            self::assertStringStartsWith('Cannot issue a token for a session that has ended', $exception->getMessage());
        }

        self::assertSame(RefreshTokenHasher::hash(self::ROTATION_ID), $this->stored($session)->getRefreshKey());
    }

    /**
     * With daylight saving, an idle deadline in the second pass ends the
     * session an hour early.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testWithDaylightSavingADeadlineInTheSecondPassEndsTheSessionEarly(): void
    {
        $signedInAt = $this->atUtc('2026-11-01 05:00:00', self::DAYLIGHT_SAVING_ZONE);
        $stored     = $signedInAt->copy()->addMinutes(90);

        [$identity, $session] = $this->signIn($signedInAt, $stored);

        $token = $this->tokens()->issueRefreshToken($this->stored($session), self::ROTATION_ID, $identity)->reveal();

        self::assertSame($stored->getTimestamp() - 3600, $this->tokens()->parse($token, TokenType::REFRESH)[Claims::EXPIRES_AT->value] ?? null);

        $this->moveClockTo($signedInAt->copy()->addMinutes(45));

        $this->expectException(\InvalidArgumentException::class);

        $this->tokens()->issueRefreshToken($this->stored($session), self::ROTATION_ID, $identity)->reveal();
    }

    /**
     * With daylight saving, every use in the second pass is recorded.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testWithDaylightSavingEveryUseInTheSecondPassIsRecorded(): void
    {
        $firstUse = $this->atUtc('2026-10-25 01:30:00', self::LONDON);

        [$identity, $session] = $this->signIn($firstUse);

        $this->withToken($this->tokens()->issueAccessToken($identity, $identity, null, $session)->reveal())->getJson('/me')->assertOk();

        self::assertSame('2026-10-25 01:30:00', $this->storedRow($session)['last_used_at']);

        $this->moveClockTo($firstUse->copy()->addSeconds(30));

        $this->withToken($this->tokens()->issueAccessToken($identity, $identity, null, $session)->reveal())->getJson('/me')->assertOk();

        self::assertSame('2026-10-25 01:30:30', $this->storedRow($session)['last_used_at']);
    }

    /**
     * Define the `api` guard.
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
                'refresh_idle_ttl_minutes'     => 60,
                'refresh_absolute_ttl_minutes' => 600,
                'refresh_grace_seconds'        => 30,
            ],
        ]);
        $config->set('authentication.session.last_used_throttle_seconds', 60);
    }

    /**
     * Switch the application to the given timezone and move the clocks to the
     * given UTC time, returned in that timezone.
     *
     * @param  string  $utc
     * @param  string  $timezone
     * @return \Carbon\Carbon
     */
    private function atUtc(string $utc, string $timezone): Carbon
    {
        date_default_timezone_set($timezone);

        $at = Carbon::parse($utc, 'UTC')->setTimezone($timezone);

        $this->moveClockTo($at);

        return $at;
    }

    /**
     * Persist an identity signed in on a new session holding `ROTATION_ID`.
     *
     * @param  \Carbon\Carbon  $now
     * @param  ?\Carbon\Carbon  $idle
     * @return array{0: \Tests\Unit\Stubs\StubPrincipal, 1: \SineMacula\Laravel\Authentication\Models\Session}
     */
    private function signIn(Carbon $now, ?Carbon $idle = null): array
    {
        $identity            = new StubPrincipal;
        $identity->email     = 'repeated-hour@example.test';
        $identity->password  = 'irrelevant';
        $identity->is_active = true;
        $identity->save();

        $session = new Session;
        $session->forceFill([
            'authenticatable_type' => StubPrincipal::class,
            'authenticatable_id'   => (string) $identity->getKey(), // @phpstan-ignore cast.string
            'principal_type'       => $identity->getMorphClass(),
            'principal_id'         => (string) $identity->getKey(), // @phpstan-ignore cast.string
            'guard'                => 'api',
            'status'               => 'active',
            'tenant_id'            => null,
            'switched_at'          => null,
            'sign_in_method'       => 'password',
            'refresh_key'          => RefreshTokenHasher::hash(self::ROTATION_ID),
            'signed_in_at'         => $now,
            'idle_expires_at'      => $idle ?? $now->copy()->addHours(5),
            'absolute_expires_at'  => $now->copy()->addHours(9),
        ])->save();

        return [$identity, $session];
    }

    /**
     * Rotate a new session at 06:59:50 UTC, the end of New York's repeated
     * hour, and return its replaced token and the session.
     *
     * @param  string  $timezone
     * @return array{0: string, 1: \SineMacula\Laravel\Authentication\Models\Session}
     *
     * @throws \Random\RandomException
     */
    private function rotateAtTheEndOfTheRepeatedHourAndRetry(string $timezone): array
    {
        $retryAt = $this->atUtc('2026-11-01 07:00:05', $timezone);

        [$identity, $session] = $this->signIn($retryAt);

        $token     = $this->tokens()->issueRefreshToken($session, self::ROTATION_ID, $identity)->reveal();
        $rotatedAt = $retryAt->toImmutable()->subSeconds(15);

        self::assertTrue($this->store()->rotate($session, self::ROTATION_ID, RefreshTokenHasher::successor(self::ROTATION_ID), $rotatedAt->addHour(), $rotatedAt));

        return [$token, $session];
    }

    /**
     * The refresh rotation store on the application's connections.
     *
     * @return \SineMacula\Laravel\Authentication\Jwt\RefreshRotationStore
     */
    private function store(): RefreshRotationStore
    {
        return new RefreshRotationStore(app(ConnectionResolverInterface::class));
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
     * The `api` guard's token service.
     *
     * @return \SineMacula\Laravel\Authentication\Jwt\JwtTokenService
     */
    private function tokens(): JwtTokenService
    {
        $tokens = Auth::jwt('api');

        self::assertNotNull($tokens);

        return $tokens;
    }

    /**
     * A fresh `api` guard.
     *
     * @return \SineMacula\Laravel\Authentication\Guards\JwtGuard
     */
    private function guard(): JwtGuard
    {
        $manager = app('auth');

        assert($manager instanceof AuthManager);

        $manager->forgetGuards();

        $guard = $manager->guard('api');

        assert($guard instanceof JwtGuard);

        return $guard;
    }
}
