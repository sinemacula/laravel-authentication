<?php

declare(strict_types = 1);

namespace Tests\Performance;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Codes\CodeRequest;
use SineMacula\Laravel\Authentication\Codes\CodeService;
use SineMacula\Laravel\Authentication\Codes\CodeSignIn;
use SineMacula\Laravel\Authentication\Contracts\OneTimeCodeSender;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Sessions\AccountAttempts;
use SineMacula\Laravel\Authentication\Sessions\SignInResult;
use Tests\Concerns\InteractsWithCodeIdentities;
use Tests\Concerns\InteractsWithRateLimits;
use Tests\Integration\Fixtures\CodeIdentity;
use Tests\Performance\Fixtures\SlowModelProvider;
use Tests\Performance\Fixtures\SlowOneTimeCodeSender;

/**
 * The enumeration criteria for one-time codes, held as contracts: a request for
 * a code runs the same statements, gives the same answer and takes the same
 * time whether or not anyone has the number, with its delivery never inside it,
 * against a slow identity store and a slow gateway; and a failed sign-in by
 * code answers `invalid_credentials` and waits out the real credential timebox
 * whatever failed, while a successful one returns early.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CodeService::class)]
#[CoversClass(CodeSignIn::class)]
final class OneTimeCodeEnumerationTest extends PerformanceContractTestCase
{
    use InteractsWithCodeIdentities, InteractsWithRateLimits;

    /** @var int Timebox for the timing contracts, in microseconds. */
    private const int TIMEBOX_MICROSECONDS = 200000;

    /** @var int Requests or sign-ins timed per case; the fastest is compared, so one scheduler pause cannot fail it. */
    private const int TIMING_SAMPLES = 3;

    /** @var string The code the engine issues for the known number. */
    private const string CODE = '135790';

    /** @var \Tests\Performance\Fixtures\SlowOneTimeCodeSender The slow gateway. */
    private SlowOneTimeCodeSender $sender;

    /** @var ?list<string> The statements run while recording, or `null` when not recording. */
    private ?array $statements = null;

    /**
     * Freeze the immutable clock with the performance clock, create the table,
     * register the slow provider and bind the slow sender.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        CarbonImmutable::setTestNow(CarbonImmutable::instance($this->now));

        self::createCodeIdentitiesTable();

        Auth::provider('slow_model', static fn (Application $app, array $config): SlowModelProvider => new SlowModelProvider(
            $app->make(Hasher::class),
            CodeIdentity::class,
        ));

        SlowModelProvider::$lookups = 0;

        DB::listen(function (QueryExecuted $query): void {
            if ($this->statements === null) {
                return;
            }

            $this->statements[] = $query->sql;
        });

        $this->sender = new SlowOneTimeCodeSender;

        app()->instance(OneTimeCodeSender::class, $this->sender);
    }

    /**
     * Release the clock and drop the table.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        self::dropCodeIdentitiesTable();

        CarbonImmutable::setTestNow();

        parent::tearDown();
    }

    /**
     * A request for a known number and one for a number no one has, each from a
     * client of its own so their limits start alike, run the same statements,
     * in the same order, with the same answer; so do the requests that follow
     * within the cooldown.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACodeRequestRunsTheSameStatementsForAnyNumber(): void
    {
        self::seedCodeIdentity();

        $knownClient   = new ClientContext('198.51.100.1', 'Phone/1.0');
        $unknownClient = new ClientContext('198.51.100.2', 'Phone/1.0');

        [$known, $knownSql]     = $this->recorded(fn (): CodeRequest => $this->codeService('slow')->send('phone_code', ['phone' => self::PHONE], $knownClient));
        [$unknown, $unknownSql] = $this->recorded(fn (): CodeRequest => $this->codeService('slow')->send('phone_code', ['phone' => self::UNKNOWN_PHONE], $unknownClient));

        self::assertEquals($known, $unknown);
        self::assertSame($knownSql, $unknownSql);
        self::assertNotSame([], $knownSql);

        [$knownAgain, $knownAgainSql]     = $this->recorded(fn (): CodeRequest => $this->codeService('slow')->send('phone_code', ['phone' => self::PHONE], $knownClient));
        [$unknownAgain, $unknownAgainSql] = $this->recorded(fn (): CodeRequest => $this->codeService('slow')->send('phone_code', ['phone' => self::UNKNOWN_PHONE], $unknownClient));

        self::assertEquals($knownAgain, $unknownAgain);
        self::assertSame($knownAgainSql, $unknownAgainSql);
        self::assertSame(0, SlowModelProvider::$lookups);
    }

    /**
     * Against a slow identity store and a slow gateway, a request takes as
     * little time for a known number as for one no one has: it never looks the
     * number up, and the delivery runs only after the response, where the known
     * number's code then goes out and the unknown's does not.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACodeRequestTakesNoLongerForAKnownNumber(): void
    {
        config()->set('authentication.codes.resend_cooldown_seconds', 0);

        self::seedCodeIdentity();

        $known   = $this->fastestRequest(self::PHONE);
        $unknown = $this->fastestRequest(self::UNKNOWN_PHONE);

        self::assertSame([0, 0], [SlowModelProvider::$lookups, $this->sender->count()]);
        self::assertLessThan(SlowModelProvider::FOUND_MICROSECONDS * 1000, $known);
        self::assertLessThan(SlowModelProvider::FOUND_MICROSECONDS * 1000, $unknown);

        $this->app?->terminate();

        self::assertSame(1, $this->sender->count());
    }

    /**
     * Rows of how a sign-in by code fails, for a known number or one no one
     * has.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideFailures(): iterable
    {
        yield from [
            'unknown number, wrong code' => ['unknown'],
            'unknown number, its code'   => ['unknown_right'],
            'wrong code'                 => ['wrong'],
            'expired code'               => ['expired'],
            'exhausted code'             => ['exhausted'],
            'used code'                  => ['used'],
            'account without attempts'   => ['account'],
            'malformed code'             => ['malformed'],
        ];
    }

    /**
     * Every failed sign-in by code answers exactly as a wrong code does
     * (`invalid_credentials`, no wait) and waits out the real timebox, a slow
     * lookup of a known number included; only the server-side event may say
     * more.
     *
     * @param  string  $failure
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideFailures')]
    public function testAFailedSignInByCodeLooksTheSameAndWaitsOutTheTimebox(string $failure): void
    {
        config()->set('authentication.codes.max_attempts', 1);

        $identity = self::seedCodeIdentity();
        $phone    = in_array($failure, ['unknown', 'unknown_right'], true) ? self::UNKNOWN_PHONE : self::PHONE;
        $code     = $this->prepare($failure, $identity, $phone);

        $this->recordEvents([AuthenticationFailed::class]);

        app(ConfigRepository::class)->set('authentication.timebox.credentials_microseconds', self::TIMEBOX_MICROSECONDS);

        $sessions = $this->sessions('slow');
        $started  = hrtime(true);
        $result   = $sessions->signIn('phone_code', ['phone' => $phone, 'code' => $code]);
        $elapsed  = hrtime(true) - $started;

        self::assertEquals(SignInResult::failed(FailureReason::INVALID_CREDENTIALS), $result);
        self::assertGreaterThanOrEqual(self::TIMEBOX_MICROSECONDS * 1000, $elapsed);
        self::assertCount(1, $this->recorded);
    }

    /**
     * A successful sign-in by code returns as soon as it is done, the slow
     * lookup included, instead of waiting out the timebox.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASuccessfulSignInByCodeReturnsBeforeTheTimebox(): void
    {
        config()->set('authentication.codes.resend_cooldown_seconds', 0);

        self::seedCodeIdentity();

        app(ConfigRepository::class)->set('authentication.timebox.credentials_microseconds', self::TIMEBOX_MICROSECONDS);

        $fastest = PHP_INT_MAX;

        for ($sample = 0; $sample < self::TIMING_SAMPLES; $sample++) {

            self::issueCodes([self::CODE]);

            $this->codeService('slow')->send('phone_code', ['phone' => self::PHONE]);

            $sessions = $this->sessions('slow');
            $started  = hrtime(true);

            self::assertTrue($sessions->signIn('phone_code', ['phone' => self::PHONE, 'code' => self::CODE])->isSignedIn());

            $fastest = min($fastest, hrtime(true) - $started);
        }

        self::assertGreaterThanOrEqual(SlowModelProvider::FOUND_MICROSECONDS * 1000, $fastest);
        self::assertLessThan(self::TIMEBOX_MICROSECONDS * 1000, $fastest);
    }

    /**
     * Configure the guards, and a `slow` guard over the slow provider that
     * allows phone codes.
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

        self::configureCodeGuards($config);

        $config->set('auth.providers.slow_identities', ['driver' => 'slow_model', 'model' => CodeIdentity::class]);
        $config->set('auth.guards.slow', ['driver' => 'jwt', 'provider' => 'slow_identities', 'audience' => ['methods' => ['phone_code']]]);
    }

    /**
     * Bring the code sent to the number into the state the failure needs, and
     * return the code the sign-in enters.
     *
     * @param  string  $failure
     * @param  \Tests\Integration\Fixtures\CodeIdentity  $identity
     * @param  string  $phone
     * @return string
     *
     * @throws \Throwable
     */
    private function prepare(string $failure, CodeIdentity $identity, string $phone): string
    {
        self::issueCodes([self::CODE]);

        $this->codeService('slow')->send('phone_code', ['phone' => $phone]);

        match ($failure) {
            'expired'   => CarbonImmutable::setTestNow(CarbonImmutable::instance($this->now)->addSeconds(600)),
            'exhausted' => DB::table('one_time_codes')->update(['attempts' => 1]),
            'used'      => DB::table('one_time_codes')->update(['consumed_at' => '2026-04-10 12:00:00']),
            'account'   => DB::table('rate_limits')->insert([
                'key'            => self::counterKey('sign_in', 'per_account', AccountAttempts::account($identity)),
                'hits'           => 5,
                'window_ends_at' => '2026-04-10 12:05:00',
            ]),
            default => null,
        };

        return match ($failure) {
            'unknown', 'wrong' => '000000',
            'malformed'        => '1357',
            default            => self::CODE,
        };
    }

    /**
     * The fastest of a few requests for a code to the number, in nanoseconds.
     *
     * @param  string  $phone
     * @return int
     *
     * @throws \Throwable
     */
    private function fastestRequest(string $phone): int
    {
        $fastest = PHP_INT_MAX;

        for ($sample = 0; $sample < self::TIMING_SAMPLES; $sample++) {

            $codes   = $this->codeService('slow');
            $started = hrtime(true);

            self::assertTrue($codes->send('phone_code', ['phone' => $phone])->isSent());

            $fastest = min($fastest, hrtime(true) - $started);
        }

        return $fastest;
    }

    /**
     * Run the call and return its result and the statements it ran.
     *
     * @template TResult
     *
     * @param  \Closure(): TResult  $call
     * @return array{0: TResult, 1: list<string>}
     */
    private function recorded(\Closure $call): array
    {
        $this->statements = [];

        $result     = $call();
        $statements = $this->statements ?? [];

        $this->statements = null;

        return [$result, $statements];
    }
}
