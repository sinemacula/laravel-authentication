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
use SineMacula\Laravel\Authentication\Codes\CodeBinding;
use SineMacula\Laravel\Authentication\Codes\CodeRequest;
use SineMacula\Laravel\Authentication\Codes\IssuedCode;
use SineMacula\Laravel\Authentication\Codes\OneTimeCodes;
use SineMacula\Laravel\Authentication\Contracts\PasswordResetLinkSender;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Passwords\Enums\ResetStatus;
use SineMacula\Laravel\Authentication\Passwords\PasswordService;
use SineMacula\Laravel\Authentication\Passwords\ResetRequests;
use SineMacula\Laravel\Authentication\Passwords\ResetResult;
use SineMacula\Laravel\Authentication\Passwords\ResetSubmissions;
use Tests\Concerns\InteractsWithPasswords;
use Tests\Integration\Fixtures\PasswordIdentity;
use Tests\Performance\Fixtures\SlowModelProvider;
use Tests\Performance\Fixtures\SlowPasswordResetLinkSender;

/**
 * The enumeration criteria for password resets, held as contracts: a request
 * for a link runs the same statements, gives the same answer and takes the
 * same time whether or not anyone holds the address, with its delivery never
 * inside it, against a slow identity store and a slow mail gateway; a failed
 * reset answers `invalid` and waits out the real credential timebox whatever
 * failed, running the same statements for an address no one holds as for a
 * wrong token; and a successful one returns early.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ResetRequests::class)]
#[CoversClass(ResetSubmissions::class)]
final class PasswordResetEnumerationTest extends PerformanceContractTestCase
{
    use InteractsWithPasswords;

    /** @var int Timebox for the timing contracts, in microseconds. */
    private const int TIMEBOX_MICROSECONDS = 200000;

    /** @var int Requests or resets timed per case; the fastest is compared, so one scheduler pause cannot fail it. */
    private const int TIMING_SAMPLES = 3;

    /** @var string The seeded identity's email address. */
    private const string EMAIL = 'ada@example.test';

    /** @var string An email address no identity has. */
    private const string UNKNOWN_EMAIL = 'nobody@example.test';

    /** @var string The new password every reset sets. */
    private const string NEW_PASSWORD = 'a brand new passphrase';

    /** @var \Tests\Performance\Fixtures\SlowPasswordResetLinkSender The slow gateway. */
    private SlowPasswordResetLinkSender $sender;

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

        self::createPasswordTables();

        Auth::provider('slow_model', static fn (Application $app): SlowModelProvider => new SlowModelProvider($app->make(Hasher::class), PasswordIdentity::class));

        SlowModelProvider::$lookups = 0;

        DB::listen(function (QueryExecuted $query): void {
            if ($this->statements === null) {
                return;
            }

            $this->statements[] = $query->sql;
        });

        $this->sender = new SlowPasswordResetLinkSender;

        app()->instance(PasswordResetLinkSender::class, $this->sender);
    }

    /**
     * Release the clock and drop the table.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        self::dropPasswordTables();

        CarbonImmutable::setTestNow();

        parent::tearDown();
    }

    /**
     * A request for a known address and one for an address no one has, each
     * from a client of its own so their limits start alike, run the same
     * statements, in the same order, with the same answer, and never look the
     * address up; so do the requests that follow within the cooldown.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAResetRequestRunsTheSameStatementsForAnyAddress(): void
    {
        self::seedPasswordIdentity(self::EMAIL);

        $knownClient   = new ClientContext('198.51.100.1', 'Browser/1.0');
        $unknownClient = new ClientContext('198.51.100.2', 'Browser/1.0');

        foreach (range(1, 2) as $round) {

            [$known, $knownSql]     = $this->recorded(fn (): CodeRequest => $this->passwords()->sendResetLink(['email' => self::EMAIL], $knownClient));
            [$unknown, $unknownSql] = $this->recorded(fn (): CodeRequest => $this->passwords()->sendResetLink(['email' => self::UNKNOWN_EMAIL], $unknownClient));

            self::assertEquals($known, $unknown, "Round {$round}.");
            self::assertSame($knownSql, $unknownSql, "Round {$round}.");
            self::assertNotSame([], $knownSql);
        }

        self::assertSame(0, SlowModelProvider::$lookups);
    }

    /**
     * Against a slow identity store and a slow gateway, a request takes as
     * little time for a known address as for one no one has: it never looks the
     * address up, and the delivery runs only after the response, where the
     * known address's link then goes out and the unknown's does not.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAResetRequestTakesNoLongerForAKnownAddress(): void
    {
        config()->set('authentication.codes.resend_cooldown_seconds', 0);

        self::seedPasswordIdentity(self::EMAIL);

        $known   = $this->fastestRequest(self::EMAIL);
        $unknown = $this->fastestRequest(self::UNKNOWN_EMAIL);

        self::assertSame([0, 0], [SlowModelProvider::$lookups, $this->sender->count()]);
        self::assertLessThan(SlowModelProvider::FOUND_MICROSECONDS * 1000, $known);
        self::assertLessThan(SlowModelProvider::FOUND_MICROSECONDS * 1000, $unknown);

        app()->terminate();

        self::assertSame(1, $this->sender->count());
    }

    /**
     * A reset for an address no one holds and one with a wrong token for the
     * seeded identity run the same statements, in the same order, with the same
     * answer.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFailedResetRunsTheSameStatementsForAnyAddress(): void
    {
        self::seedPasswordIdentity(self::EMAIL);

        $wrong = str_repeat('a', 43);

        foreach ([self::EMAIL, self::UNKNOWN_EMAIL] as $email) {
            self::issueToken($email);
        }

        $knownClient   = new ClientContext('198.51.100.1', 'Browser/1.0');
        $unknownClient = new ClientContext('198.51.100.2', 'Browser/1.0');

        $input = static fn (string $email): array => ['email' => $email, 'token' => $wrong, 'password' => self::NEW_PASSWORD];
        $reset = fn (string $email, ClientContext $client): ResetResult => $this->passwords()->reset($input($email), $client);

        [$known, $knownSql]     = $this->recorded(static fn (): ResetResult => $reset(self::EMAIL, $knownClient));
        [$unknown, $unknownSql] = $this->recorded(static fn (): ResetResult => $reset(self::UNKNOWN_EMAIL, $unknownClient));

        self::assertEquals($known, $unknown);
        self::assertSame(ResetStatus::INVALID, $known->status);
        self::assertSame($knownSql, $unknownSql);
    }

    /**
     * Rows of how a reset fails.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideFailures(): iterable
    {
        yield from [
            'an address no one has, a live token for it' => ['unknown'],
            'a wrong token'                              => ['wrong'],
            'an expired token'                           => ['expired'],
            'a used token'                               => ['used'],
            'an inactive identity'                       => ['inactive'],
            'a malformed token'                          => ['malformed'],
        ];
    }

    /**
     * Every failed reset answers `invalid` and waits out the real timebox, a
     * slow lookup of a known address included.
     *
     * @param  string  $failure
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideFailures')]
    public function testAFailedResetLooksTheSameAndWaitsOutTheTimebox(string $failure): void
    {
        self::seedPasswordIdentity(self::EMAIL, ['is_active' => $failure !== 'inactive']);

        [$email, $token] = $this->prepare($failure);

        app(ConfigRepository::class)->set('authentication.timebox.credentials_microseconds', self::TIMEBOX_MICROSECONDS);

        $passwords = $this->passwords();
        $started   = hrtime(true);
        $result    = $passwords->reset(['email' => $email, 'token' => $token, 'password' => self::NEW_PASSWORD]);
        $elapsed   = hrtime(true) - $started;

        self::assertEquals(ResetResult::invalid(), $result);
        self::assertGreaterThanOrEqual(self::TIMEBOX_MICROSECONDS * 1000, $elapsed);
    }

    /**
     * A successful reset returns as soon as it is done, the slow lookup
     * included, instead of waiting out the timebox.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASuccessfulResetReturnsBeforeTheTimebox(): void
    {
        config()->set('authentication.codes.resend_cooldown_seconds', 0);

        self::seedPasswordIdentity(self::EMAIL);

        app(ConfigRepository::class)->set('authentication.timebox.credentials_microseconds', self::TIMEBOX_MICROSECONDS);

        $fastest = PHP_INT_MAX;

        for ($sample = 0; $sample < self::TIMING_SAMPLES; $sample++) {

            $token     = self::issueToken(self::EMAIL);
            $passwords = $this->passwords();
            $started   = hrtime(true);

            self::assertTrue($passwords->reset(['email' => self::EMAIL, 'token' => $token, 'password' => self::NEW_PASSWORD])->isReset());

            $fastest = min($fastest, hrtime(true) - $started);
        }

        self::assertGreaterThanOrEqual(SlowModelProvider::FOUND_MICROSECONDS * 1000, $fastest);
        self::assertLessThan(self::TIMEBOX_MICROSECONDS * 1000, $fastest);
    }

    /**
     * Configure the guards, and a `slow` guard over the slow provider.
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

        self::configurePasswordGuards($config);

        $config->set('auth.providers.slow', ['driver' => 'slow_model']);
        $config->set('auth.guards.slow', ['driver' => 'jwt', 'provider' => 'slow', 'audience' => ['methods' => ['password']]]);
    }

    /**
     * The address and token a reset fails with, set up for the failure.
     *
     * @param  string  $failure
     * @return array{0: string, 1: string}
     *
     * @throws \Throwable
     */
    private function prepare(string $failure): array
    {
        if ($failure === 'unknown') {
            return [self::UNKNOWN_EMAIL, self::issueToken(self::UNKNOWN_EMAIL)];
        }

        $token = self::issueToken(self::EMAIL);

        return match ($failure) {
            'wrong'     => [self::EMAIL, str_repeat('a', 43)],
            'expired'   => [self::EMAIL, self::expire($token)],
            'used'      => [self::EMAIL, self::useUp($token)],
            'malformed' => [self::EMAIL, 'short'],
            default     => [self::EMAIL, $token],
        };
    }

    /**
     * Expire the token.
     *
     * @param  string  $token
     * @return string
     */
    private static function expire(string $token): string
    {
        DB::table('one_time_codes')->update(['expires_at' => '2000-01-01 00:00:00']);

        return $token;
    }

    /**
     * Use the token up.
     *
     * @param  string  $token
     * @return string
     */
    private static function useUp(string $token): string
    {
        DB::table('one_time_codes')->update(['consumed_at' => '2026-04-10 11:00:00']);

        return $token;
    }

    /**
     * Issue a reset link token for the address on the slow guard, directly.
     *
     * @param  string  $email
     * @return string
     *
     * @throws \Throwable
     */
    private static function issueToken(string $email): string
    {
        $issued = app(OneTimeCodes::class)->issueToken(CodeBinding::passwordResetLink('slow', 'email', $email), CarbonImmutable::now(), 3600);

        self::assertInstanceOf(IssuedCode::class, $issued);

        return $issued->code;
    }

    /**
     * The fastest of the timed requests for a link to the address, in
     * nanoseconds.
     *
     * @param  string  $email
     * @return int
     *
     * @throws \Throwable
     */
    private function fastestRequest(string $email): int
    {
        $fastest = PHP_INT_MAX;

        for ($sample = 0; $sample < self::TIMING_SAMPLES; $sample++) {

            $passwords = $this->passwords();
            $started   = hrtime(true);

            self::assertTrue($passwords->sendResetLink(['email' => $email])->isSent());

            $fastest = min($fastest, hrtime(true) - $started);
        }

        return $fastest;
    }

    /**
     * Run the callback and return its result with the statements it ran.
     *
     * @template TResult
     *
     * @param  \Closure(): TResult  $callback
     * @return array{0: TResult, 1: list<string>}
     */
    private function recorded(\Closure $callback): array
    {
        $this->statements = [];

        $result     = $callback();
        $statements = $this->statements ?? [];

        $this->statements = null;

        return [$result, $statements];
    }

    /**
     * The `slow` guard's password service, on a guard resolved for a fresh
     * request.
     *
     * @return \SineMacula\Laravel\Authentication\Passwords\PasswordService
     */
    private function passwords(): PasswordService
    {
        $this->freshGuard('slow');

        return Auth::passwords('slow');
    }
}
