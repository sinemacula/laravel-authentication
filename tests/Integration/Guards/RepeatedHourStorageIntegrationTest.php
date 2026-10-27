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
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversTrait;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\AuthManager;
use SineMacula\Laravel\Authentication\Concerns\ActsAsDevice;
use SineMacula\Laravel\Authentication\Events\Enums\RefreshFailureReason;
use SineMacula\Laravel\Authentication\Events\RefreshFailed;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Jwt\Enums\Claims;
use SineMacula\Laravel\Authentication\Jwt\Enums\TokenType;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenService;
use SineMacula\Laravel\Authentication\Jwt\RefreshRotationStore;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenExchange;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenHasher;
use SineMacula\Laravel\Authentication\Models\Device;
use Tests\TestCase;
use Tests\Unit\Stubs\StubPrincipal;

/**
 * End-to-end tests for device times stored around the hour that repeats when
 * the clocks go back, on the shipped devices table of each engine.
 *
 * The times are stored as wall-clock times in the application timezone, as
 * Laravel stores `datetime` columns. With UTC, the documented setting, they
 * round-trip exactly. With a timezone that observes daylight saving, a time in
 * the second pass of the repeated hour reads back an hour early, so a session
 * can end early or a refresh fail, but a session never ends late. In
 * `America/New_York` the clocks go back at 06:00 UTC on 1 November 2026: 01:00
 * to 01:59 local is 05:00 to 05:59 UTC the first time and 06:00 to 06:59 UTC
 * the second.
 *
 * Carbon's test clock itself resolves a time in the second pass to the first,
 * so the clock is only ever moved to times outside it, and a rotation in it is
 * written through the store with its time given.
 *
 * The `api` guard has a 1-hour idle lifetime, a 10-hour absolute lifetime, and
 * a 30-second grace window.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(JwtTokenService::class)]
#[CoversClass(RefreshRotationStore::class)]
#[CoversClass(RefreshTokenExchange::class)]
#[CoversTrait(ActsAsDevice::class)]
final class RepeatedHourStorageIntegrationTest extends TestCase
{
    /** @var string Plaintext rotation id of the device's first refresh token. */
    private const string ROTATION_ID = 'first-rotation-id';

    /** @var string A timezone whose clocks go back at 06:00 UTC on 1 November 2026. */
    private const string DAYLIGHT_SAVING_ZONE = 'America/New_York';

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
     * Rows of `[a time (UTC), the wall-clock time stored in New York, seconds
     * early it reads back]`: either side of the repeated hour and in each pass
     * through it.
     *
     * @return iterable<string, array{0: string, 1: string, 2: int}>
     */
    public static function provideTimesAroundTheRepeatedHour(): iterable
    {
        yield from [
            'before'          => ['2026-11-01 04:30:00', '2026-11-01 00:30:00', 0],
            'the first pass'  => ['2026-11-01 05:30:00', '2026-11-01 01:30:00', 0],
            'the second pass' => ['2026-11-01 06:30:00', '2026-11-01 01:30:00', 3600],
            'after'           => ['2026-11-01 07:30:00', '2026-11-01 02:30:00', 0],
        ];
    }

    /**
     * With a timezone that observes daylight saving, a rotation stores its time
     * and the new idle deadline as wall-clock times without an offset, so both
     * passes through the repeated hour store the same value, and one in the
     * second pass reads back as the first, an hour early. No time reads back
     * late.
     *
     * @param  string  $utc
     * @param  string  $wallClock
     * @param  int  $earlyBy
     * @return void
     */
    #[DataProvider('provideTimesAroundTheRepeatedHour')]
    public function testTimesInTheSecondPassOfTheRepeatedHourReadBackAnHourEarly(string $utc, string $wallClock, int $earlyBy): void
    {
        $at = $this->atUtc('2026-11-01 00:00:00', self::DAYLIGHT_SAVING_ZONE);

        [, $device] = $this->signIn($at);

        $time = CarbonImmutable::parse($utc, 'UTC')->setTimezone(self::DAYLIGHT_SAVING_ZONE);

        self::assertTrue($this->store()->rotate($device, self::ROTATION_ID, RefreshTokenHasher::successor(self::ROTATION_ID), $time, $time));

        $row    = (array) DB::table('devices')->where('id', $device->getKey())->first();
        $stored = $this->stored($device);

        self::assertSame($wallClock, $row['refresh_rotated_at']);
        self::assertSame($wallClock, $row['idle_expires_at']);
        self::assertSame($time->getTimestamp() - $earlyBy, $stored->getRefreshRotatedAt()?->getTimestamp());
        self::assertSame($time->getTimestamp() - $earlyBy, $stored->getIdleExpiresAt()?->getTimestamp());
    }

    /**
     * With the application timezone at UTC, a rotation at the end of the hour
     * that repeats elsewhere round-trips exactly, and a retry of the rotated
     * token fifteen seconds later is a grace retry that gets the current
     * credential.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testWithUtcARotationAtTheEndOfTheRepeatedHourKeepsItsGraceWindow(): void
    {
        [$token, $device] = $this->rotateAtTheEndOfTheRepeatedHourAndRetry('UTC');

        self::assertNotNull($this->guard()->refresh($token));
        self::assertNull($this->stored($device)->getRevokedAt());
    }

    /**
     * With a timezone that observes daylight saving, a rotation in the second
     * pass of the repeated hour reads back an hour early, so a retry of the
     * rotated token fifteen seconds later is past the grace window: it is a
     * replay and revokes the device. This is why the application timezone must
     * not observe daylight saving.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testWithDaylightSavingARotationInTheSecondPassLeavesNoGraceWindow(): void
    {
        [$token, $device] = $this->rotateAtTheEndOfTheRepeatedHourAndRetry(self::DAYLIGHT_SAVING_ZONE);

        self::assertSame(RefreshFailureReason::ROTATION_REUSE, $this->refreshFailure($token));
        self::assertSame('rotation_reuse', $this->stored($device)->getRevokedReason());
    }

    /**
     * With a timezone that observes daylight saving and an idle lifetime of an
     * hour, a refresh in the first pass of the repeated hour sets an idle
     * deadline in the second pass, which reads back at the refresh's own time:
     * no token can be issued for it, so the refresh fails with an exception
     * before anything is written, and the presented token stays current.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testWithDaylightSavingARefreshSettingAnIdleDeadlineInTheSecondPassFailsWithoutWriting(): void
    {
        $now = $this->atUtc('2026-11-01 05:30:00', self::DAYLIGHT_SAVING_ZONE);

        [$identity, $device] = $this->signIn($now);

        $token = $this->tokens()->issueRefreshToken($device, self::ROTATION_ID, $identity);

        try {
            $this->guard()->refresh($token);

            self::fail('The refresh should not have been able to issue tokens.');
        } catch (\InvalidArgumentException $exception) {
            self::assertStringStartsWith('Cannot issue a token for a device whose session has ended', $exception->getMessage());
        }

        self::assertSame(RefreshTokenHasher::hash(self::ROTATION_ID), $this->stored($device)->getRefreshKey());
    }

    /**
     * With a timezone that observes daylight saving, an idle deadline in the
     * second pass of the repeated hour ends the session an hour early: tokens
     * issued before it expire at the deadline it reads back, and none can be
     * issued after that, although the deadline that was stored is still ahead.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testWithDaylightSavingADeadlineInTheSecondPassEndsTheSessionEarly(): void
    {
        $signedInAt = $this->atUtc('2026-11-01 05:00:00', self::DAYLIGHT_SAVING_ZONE);
        $stored     = $signedInAt->copy()->addMinutes(90);

        [$identity, $device] = $this->signIn($signedInAt, $stored);

        $token = $this->tokens()->issueRefreshToken($this->stored($device), self::ROTATION_ID, $identity);

        self::assertSame($stored->getTimestamp() - 3600, $this->tokens()->parse($token, TokenType::REFRESH)[Claims::EXPIRES_AT->value] ?? null);

        $this->moveClockTo($signedInAt->copy()->addMinutes(45));

        $this->expectException(\InvalidArgumentException::class);

        $this->tokens()->issueRefreshToken($this->stored($device), self::ROTATION_ID, $identity);
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
            'driver'   => 'jwt',
            'provider' => 'identities',
            'jwt'      => [
                'refresh_idle_ttl_minutes'     => 60,
                'refresh_absolute_ttl_minutes' => 600,
                'refresh_grace_seconds'        => 30,
            ],
        ]);
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
     * Persist an identity signed in on a new device holding `ROTATION_ID`, with
     * an idle deadline at the given time (five hours from now by default) and
     * an absolute deadline nine hours from now.
     *
     * @param  \Carbon\Carbon  $now
     * @param  ?\Carbon\Carbon  $idle
     * @return array{0: \Tests\Unit\Stubs\StubPrincipal, 1: \SineMacula\Laravel\Authentication\Models\Device}
     */
    private function signIn(Carbon $now, ?Carbon $idle = null): array
    {
        $identity            = new StubPrincipal;
        $identity->email     = 'repeated-hour@example.test';
        $identity->password  = 'irrelevant';
        $identity->is_active = true;
        $identity->save();

        $device = new Device;
        $device->forceFill([
            'authenticatable_type' => StubPrincipal::class,
            'authenticatable_id'   => (string) $identity->getKey(), // @phpstan-ignore cast.string
            'refresh_key'          => RefreshTokenHasher::hash(self::ROTATION_ID),
            'idle_expires_at'      => $idle ?? $now->copy()->addHours(5),
            'absolute_expires_at'  => $now->copy()->addHours(9),
        ])->save();

        return [$identity, $device];
    }

    /**
     * Sign in at 07:00:05 UTC with the given application timezone, rotate the
     * device at 06:59:50 UTC (01:59:50 in the second pass in New York), and
     * return the rotated token, for a retry fifteen seconds later, and the
     * device.
     *
     * @param  string  $timezone
     * @return array{0: string, 1: \SineMacula\Laravel\Authentication\Models\Device}
     *
     * @throws \Random\RandomException
     */
    private function rotateAtTheEndOfTheRepeatedHourAndRetry(string $timezone): array
    {
        $retryAt = $this->atUtc('2026-11-01 07:00:05', $timezone);

        [$identity, $device] = $this->signIn($retryAt);

        $token     = $this->tokens()->issueRefreshToken($device, self::ROTATION_ID, $identity);
        $rotatedAt = $retryAt->toImmutable()->subSeconds(15);

        self::assertTrue($this->store()->rotate($device, self::ROTATION_ID, RefreshTokenHasher::successor(self::ROTATION_ID), $rotatedAt->addHour(), $rotatedAt));

        return [$token, $device];
    }

    /**
     * The refresh rotation store on the application's connections.
     *
     * @return \SineMacula\Laravel\Authentication\Jwt\RefreshRotationStore
     */
    private function store(): RefreshRotationStore
    {
        return new RefreshRotationStore(app(ConnectionResolverInterface::class), static fn (): mixed => app('db.transactions'));
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
