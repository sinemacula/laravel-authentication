<?php

declare(strict_types = 1);

namespace Tests\Integration\Sessions;

use Carbon\CarbonImmutable;
use Firebase\JWT\JWT;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\AdditionalFactorPolicy;
use SineMacula\Laravel\Authentication\Contracts\RequirementCheck;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Factors\Enums\FactorChangeMade;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Http\PresentedRefreshToken;
use SineMacula\Laravel\Authentication\Proofs\Enums\Purpose;
use SineMacula\Laravel\Authentication\Secrets\Secret;
use SineMacula\Laravel\Authentication\Sessions\FactorChangeResult;
use SineMacula\Laravel\Authentication\Sessions\FactorRevocations;
use SineMacula\Laravel\Authentication\Sessions\RefreshResult;
use SineMacula\Laravel\Authentication\Sessions\SignedInSession;
use Tests\Concerns\InteractsWithIsolationLevels;
use Tests\Concerns\InteractsWithProofs;
use Tests\Concerns\InteractsWithSessions;
use Tests\Fixtures\Factors\AlwaysRequireAdditionalFactor;
use Tests\Fixtures\Tenancy\ProofJudgingRequirementCheck;
use Tests\TestCase;

/**
 * Races a refresh against a factor change's judgement of its session, each in
 * its own process.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FactorRevocations::class)]
final class ConcurrentRefreshAndFactorChangeTest extends TestCase
{
    use InteractsWithIsolationLevels, InteractsWithProofs, InteractsWithSessions;

    /** @var int How long the first side holds its transaction once the second waits on the row, in microseconds. */
    private const int SETTLE_MICROSECONDS = 300000;

    /** @var int How many times the second side tries its work before a failure to serialise reaches it. */
    private const int ATTEMPTS = 5;

    /** @var int How long either side waits for the other's signal before giving up, in seconds. */
    private const int SIGNAL_TIMEOUT_SECONDS = 10;

    /** @var \Carbon\CarbonImmutable The second the race runs in, an hour after the sign-in. */
    private CarbonImmutable $racedAt;

    /** @var string Directory the second side reports its outcome in. */
    private string $outcomes;

    /**
     * Skip where processes cannot share the database, freeze the clocks and
     * create the tables.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        if (DB::connection()->getDriverName() === 'sqlite' || !function_exists('pcntl_fork')) {
            self::markTestSkipped('Racing processes need a shared database server and pcntl.');
        }

        $this->racedAt = CarbonImmutable::createStrict(2026, 4, 6, 13, 0, 0);

        $this->freezeAt($this->racedAt->subHour());

        $this->createSessionTables();

        $this->outcomes = sys_get_temp_dir() . '/refresh-factor-change-race-' . bin2hex(random_bytes(8));

        mkdir($this->outcomes);
    }

    /**
     * Remove the outcomes, drop the tables and release the clocks.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        foreach (glob(($this->outcomes ?? sys_get_temp_dir() . '/none') . '/*') ?: [] as $file) {
            unlink($file);
        }

        if (isset($this->outcomes) && is_dir($this->outcomes)) {
            rmdir($this->outcomes);
        }

        $this->dropSessionTables();

        Carbon::setTestNow();
        CarbonImmutable::setTestNow();

        JWT::$timestamp = null;

        parent::tearDown();
    }

    /**
     * A refresh that waits on a change is refused as pending.
     *
     * @param  string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideIsolationLevels')]
    public function testARefreshThatWaitsOnAChangeIsRefusedAsPending(string $level): void
    {
        $signedIn     = $this->signedIn();
        $refreshToken = (string) $signedIn->tokens->refreshToken?->reveal();

        /** @var \ArrayObject<int, ?\SineMacula\Laravel\Authentication\Secrets\Secret> $credential */
        $credential = new \ArrayObject;

        $reported = $this->race(
            static function () use ($signedIn, $credential): void {
                $change = Auth::sessions('api')->factorChanged($signedIn->identity, FactorChangeMade::FACTOR_CONFIRMED, $signedIn->record);

                self::assertTrue($change->isPending());

                $credential->append($change->credential);
            },
            fn (): array => $this->refreshAt($level, $refreshToken),
            'issuance_sequence',
        );

        self::assertSame(self::readsASnapshot($level) ? '40001' : null, $reported['failed']);
        self::assertGreaterThanOrEqual(self::SETTLE_MICROSECONDS / 1000000 / 2, $reported['waited']);
        self::assertFalse($reported['refreshed']);
        self::assertSame(FailureReason::SESSION_PENDING->value, $reported['reason']);
        self::assertSame('pending', DB::table('authentication_sessions')->where('id', $signedIn->record->getKey())->value('status'));

        $pending = $credential[0];
        $proof   = self::adapterProof($signedIn->identity, 'api', $signedIn->record->getKey(), Purpose::SIGN_IN);

        self::assertInstanceOf(Secret::class, $pending);
        self::assertTrue($this->sessions()->satisfy($pending, $proof, self::requestClient())->isSignedIn());
    }

    /**
     * A change that waits on a refresh returns the rotated session to pending.
     *
     * @param  string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideIsolationLevels')]
    public function testAChangeThatWaitsOnARefreshReturnsTheRotatedSessionToPending(string $level): void
    {
        $signedIn = $this->signedIn();

        /** @var \ArrayObject<int, ?\SineMacula\Laravel\Authentication\Jwt\TokenPair> $refreshed */
        $refreshed = new \ArrayObject;

        $reported = $this->race(
            function () use ($signedIn, $refreshed): void {
                $result = $this->sessions()->refresh(PresentedRefreshToken::fromBody((string) $signedIn->tokens->refreshToken?->reveal()), self::requestClient());

                self::assertTrue($result->isRefreshed());

                $refreshed->append($result->session?->tokens);
            },
            fn (): array => $this->changeAt($level, $signedIn),
            'for update',
        );

        self::assertSame(self::readsASnapshot($level) ? '40001' : null, $reported['failed']);
        self::assertGreaterThanOrEqual(self::SETTLE_MICROSECONDS / 1000000 / 2, $reported['waited']);
        self::assertSame('pending', $reported['status']);
        self::assertSame('pending', DB::table('authentication_sessions')->where('id', $signedIn->record->getKey())->value('status'));

        $tokens = $refreshed[0];
        $proof  = self::adapterProof($signedIn->identity, 'api', $signedIn->record->getKey(), Purpose::SIGN_IN);

        self::assertNotNull($tokens);
        self::assertFalse($this->authenticates($tokens->accessToken));
        self::assertSame(
            FailureReason::SESSION_PENDING,
            $this->sessions()->refresh(PresentedRefreshToken::fromBody((string) $tokens->refreshToken?->reveal()), self::requestClient())->reason,
        );
        self::assertIsString($reported['credential']);
        self::assertTrue($this->sessions()->satisfy($reported['credential'], $proof, self::requestClient())->isSignedIn());
    }

    /**
     * Configure the guards.
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
     * An active session of the seeded identity that the factor package then
     * asks for a further factor.
     *
     * @return \SineMacula\Laravel\Authentication\Sessions\SignedInSession
     *
     * @throws \Throwable
     */
    private function signedIn(): SignedInSession
    {
        $this->seedIdentity();

        $signedIn = $this->sessions()->signIn('password', self::credentials(), self::requestContext())->session;

        self::assertNotNull($signedIn);

        app()->instance(AdditionalFactorPolicy::class, new AlwaysRequireAdditionalFactor);
        app()->instance(RequirementCheck::class, new ProofJudgingRequirementCheck);

        return $signedIn;
    }

    /**
     * Run the first side in an open transaction, start the second in another
     * process and commit once it is about to wait.
     *
     * @param  \Closure(): void  $first
     * @param  \Closure(): array<string, mixed>  $second
     * @param  string  $marker
     * @return array<string, mixed>
     *
     * @throws \Throwable
     */
    private function race(\Closure $first, \Closure $second, string $marker): array
    {
        $this->freezeAt($this->racedAt);

        DB::disconnect();

        $pid = pcntl_fork();

        if ($pid < 0) {
            self::fail('The second side could not be forked.');
        }

        if ($pid === 0) {
            $this->runInChild($second, $marker);
        }

        DB::beginTransaction();

        $first();

        touch("{$this->outcomes}/start");

        if (!self::wasSignalled("{$this->outcomes}/waiting")) {
            self::abandon($pid, 'The second side never reached the session\'s row, so the two did not overlap.');
        }

        usleep(self::SETTLE_MICROSECONDS);

        DB::commit();

        pcntl_waitpid($pid, $status);

        $reported = json_decode((string) file_get_contents("{$this->outcomes}/outcome"), true, flags: JSON_THROW_ON_ERROR);

        self::assertIsArray($reported);
        self::assertArrayNotHasKey('error', $reported);

        /** @var array<string, mixed> $reported */
        return $reported;
    }

    /**
     * Refresh at the isolation level in the forked process, retrying after a
     * failure to serialise.
     *
     * @param  string  $level
     * @param  string  $refreshToken
     * @return array{failed: ?string, refreshed: bool, reason: ?string}
     *
     * @throws \Throwable
     */
    private function refreshAt(string $level, #[\SensitiveParameter] string $refreshToken): array
    {
        self::isolateAt($level);

        [$failed, $result] = self::retried(fn (): RefreshResult => $this->sessions()->refresh(PresentedRefreshToken::fromBody($refreshToken), self::requestClient()));

        return ['failed' => $failed, 'refreshed' => $result->isRefreshed(), 'reason' => $result->reason?->value];
    }

    /**
     * Judge the session after a factor change at the isolation level in the
     * forked process, retrying after a failure to serialise.
     *
     * @param  string  $level
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignedInSession  $signedIn
     * @return array{failed: ?string, status: string, credential: ?string}
     *
     * @throws \Throwable
     */
    private function changeAt(string $level, SignedInSession $signedIn): array
    {
        self::isolateAt($level);

        $change = static fn (): FactorChangeResult => Auth::sessions('api')->factorChanged($signedIn->identity, FactorChangeMade::FACTOR_CONFIRMED, $signedIn->record);

        [$failed, $result] = self::retried($change);

        return ['failed' => $failed, 'status' => $result->status->value, 'credential' => $result->credential?->reveal()];
    }

    /**
     * Run the work, retrying each failure to serialise: the first failure's
     * SQLSTATE and the work's answer.
     *
     * @template TResult
     *
     * @param  \Closure(): TResult  $work
     * @return array{0: ?string, 1: TResult}
     *
     * @throws \PDOException
     */
    private static function retried(\Closure $work): array
    {
        $failed = null;

        for ($attempt = 1;; $attempt++) {
            try {
                return [$failed, $work()];
            } catch (\PDOException $exception) {
                if ($attempt === self::ATTEMPTS) {
                    throw $exception;
                }

                $failed ??= (string) $exception->getPrevious()?->getCode();
            }
        }
    }

    /**
     * Set the isolation level of every transaction the default connection
     * begins.
     *
     * @param  string  $level
     * @return void
     */
    private static function isolateAt(string $level): void
    {
        $connection = DB::connection();

        $connection->statement(match ($connection->getDriverName()) {
            'mysql' => 'set session transaction isolation level ' . $level,
            default => 'set session characteristics as transaction isolation level ' . $level,
        });
    }

    /**
     * Whether the access token authenticates a request to the `api` guard.
     *
     * @param  \SineMacula\Laravel\Authentication\Secrets\Secret  $token
     * @return bool
     */
    private function authenticates(Secret $token): bool
    {
        Auth::forgetGuards();

        $guard = app('auth')->guard('api');

        self::assertInstanceOf(JwtGuard::class, $guard);

        return $guard->setRequest(Request::create('/me', 'GET', server: ['HTTP_AUTHORIZATION' => 'Bearer ' . $token->reveal()]))->user() !== null;
    }

    /**
     * Run the second side in the forked process, report its outcome and exit
     * without the parent's shutdown.
     *
     * @param  \Closure(): array<string, mixed>  $second
     * @param  string  $marker
     * @return never
     */
    private function runInChild(\Closure $second, string $marker): never
    {
        $outcome = ['error' => 'The first side never signalled the start.'];

        try {
            if (self::wasSignalled("{$this->outcomes}/start")) {
                $this->signalBefore($marker);

                $started = microtime(true);
                $outcome = [...$second(), 'waited' => microtime(true) - $started];
            }
        } catch (\Throwable $e) {
            $outcome = ['error' => $e::class . ': ' . $e->getMessage()];
        }

        file_put_contents("{$this->outcomes}/outcome", json_encode($outcome));

        posix_kill(posix_getpid(), SIGKILL);

        exit(1);
    }

    /**
     * Signal the first side just before a statement containing the marker is
     * sent.
     *
     * @param  string  $marker
     * @return void
     */
    private function signalBefore(string $marker): void
    {
        DB::connection()->beforeExecuting(function (string $query) use ($marker): void {
            if (!str_contains($query, $marker)) {
                return;
            }

            touch("{$this->outcomes}/waiting");
        });
    }

    /**
     * Wait, up to the timeout, for the other side to create the signal file.
     *
     * @param  string  $signal
     * @return bool
     */
    private static function wasSignalled(string $signal): bool
    {
        $deadline = microtime(true) + self::SIGNAL_TIMEOUT_SECONDS;

        while (!is_file($signal) && microtime(true) < $deadline) {
            usleep(5000);
        }

        return is_file($signal);
    }

    /**
     * Fail the unstarted race, rolling back the first side and reaping the
     * second so neither holds locks.
     *
     * @param  positive-int  $pid
     * @param  string  $message
     * @return never
     */
    private static function abandon(int $pid, string $message): never
    {
        DB::rollBack();

        posix_kill($pid, SIGKILL);
        pcntl_waitpid($pid, $status);

        self::fail($message);
    }

    /**
     * Freeze every clock at the time.
     *
     * @param  \Carbon\CarbonImmutable  $time
     * @return void
     */
    private function freezeAt(CarbonImmutable $time): void
    {
        Carbon::setTestNow($time);
        CarbonImmutable::setTestNow($time);

        JWT::$timestamp = $time->getTimestamp();
    }
}
