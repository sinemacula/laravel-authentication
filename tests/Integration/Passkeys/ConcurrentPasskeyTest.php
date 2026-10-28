<?php

declare(strict_types = 1);

namespace Tests\Integration\Passkeys;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Models\Passkey;
use SineMacula\Laravel\Authentication\Passkeys\Enums\PasskeyRegistrationFailure;
use SineMacula\Laravel\Authentication\Passkeys\PasskeyAssertions;
use SineMacula\Laravel\Authentication\Passkeys\PasskeyChallenges;
use SineMacula\Laravel\Authentication\Passkeys\PasskeyCredentials;
use SineMacula\Laravel\Authentication\Passkeys\PasskeySummary;
use Tests\Concerns\InteractsWithPasskeys;
use Tests\Concerns\InteractsWithSessions;
use Tests\Fixtures\Passkeys\VirtualAuthenticator;
use Tests\Integration\Fixtures\IntegrationIdentity;
use Tests\TestCase;

/**
 * Races two passkey ceremonies on PostgreSQL and MySQL, each in a process with
 * a database connection of its own: one runs inside a transaction it holds
 * open, and the other, started meanwhile, waits on the row the first wrote.
 *
 * - Two answers to one challenge: only the one whose delete commits proceeds;
 *   when that transaction rolls back, the waiting answer uses the challenge.
 * - Two assertions read against the same sign count: only the first to commit
 *   its compare-and-set moves the count; the other is refused as a regression,
 *   however far its own count went.
 * - Two registrations of one credential: only the first to commit stores it;
 *   the other is refused as already registered.
 *
 * Skipped on SQLite, whose in-memory database each process would have to
 * itself, and where `pcntl` is not available.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PasskeyChallenges::class)]
#[CoversClass(PasskeyCredentials::class)]
#[CoversClass(PasskeyAssertions::class)]
final class ConcurrentPasskeyTest extends TestCase
{
    use InteractsWithPasskeys, InteractsWithSessions;

    /** @var int How long the first ceremony holds its transaction open once the second has started, in microseconds. */
    private const int HOLD_MICROSECONDS = 1000000;

    /** @var float The least time, in seconds, the second ceremony must have waited to show it waited on the first. */
    private const float LEAST_WAIT_SECONDS = 0.5;

    /** @var int How long the second ceremony waits to be started before giving up, in seconds. */
    private const int START_TIMEOUT_SECONDS = 10;

    /** @var string Directory the second ceremony reports its outcome in. */
    private string $outcomes;

    /**
     * Skip where processes cannot share the database, freeze the clocks so both
     * processes see one moment, and create the tables.
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

        $now = CarbonImmutable::createStrict(2026, 4, 6, 12, 0, 0);

        Carbon::setTestNow($now);
        CarbonImmutable::setTestNow($now);

        $this->createSessionTables();

        $this->outcomes = sys_get_temp_dir() . '/passkey-race-' . bin2hex(random_bytes(8));

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

        parent::tearDown();
    }

    /**
     * Of two answers to one challenge, the one whose delete commits first
     * proceeds; the other, which waited on it, finds the challenge gone.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testOnlyTheFirstOfTwoAnswersToAChallengeProceeds(): void
    {
        $identity = $this->seedIdentity();

        $this->registerPasskey($identity);

        $options  = Auth::passkeys('api')->factorOptions($identity);
        $response = $this->authenticator()->get($options->options);

        [$first, $second] = $this->race(
            static fn (): ?string => Auth::passkeys('api')->verifyFactor($identity, $options->challengeId, $response)?->value,
            static fn (): ?string => Auth::passkeys('api')->verifyFactor(IntegrationIdentity::query()->findOrFail($identity->id), $options->challengeId, $response)?->value,
            commitFirst: true,
        );

        self::assertNull($first);
        self::assertSame(FailureReason::PASSKEY_CHALLENGE_INVALID->value, $second['outcome']);
        self::assertGreaterThanOrEqual(self::LEAST_WAIT_SECONDS, $second['waited']);
        self::assertSame(1, Passkey::query()->sole()->sign_count);
    }

    /**
     * When the first answer's transaction rolls back, the answer that waited on
     * its delete uses the challenge instead.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnAnswerWaitingOnOneThatRollsBackUsesTheChallenge(): void
    {
        $identity = $this->seedIdentity();

        $this->registerPasskey($identity);

        $options  = Auth::passkeys('api')->factorOptions($identity);
        $response = $this->authenticator()->get($options->options);

        [$first, $second] = $this->race(
            static fn (): ?string => Auth::passkeys('api')->verifyFactor($identity, $options->challengeId, $response)?->value,
            static fn (): ?string => Auth::passkeys('api')->verifyFactor(IntegrationIdentity::query()->findOrFail($identity->id), $options->challengeId, $response)?->value,
            commitFirst: false,
        );

        self::assertNull($first);
        self::assertNull($second['outcome']);
        self::assertGreaterThanOrEqual(self::LEAST_WAIT_SECONDS, $second['waited']);
        self::assertSame(1, Passkey::query()->sole()->sign_count);
    }

    /**
     * Of two assertions read against the same count, the one whose
     * compare-and-set commits first moves the count; the other waited on its
     * row, finds the count moved, and is refused as a regression even though
     * its own count is higher.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testOnlyTheFirstOfTwoAssertionsReadAgainstOneCountMovesIt(): void
    {
        $identity = $this->seedIdentity();

        $this->registerPasskey($identity);

        $firstOptions  = Auth::passkeys('api')->factorOptions($identity);
        $secondOptions = Auth::passkeys('api')->factorOptions($identity);
        $firstAnswer   = $this->authenticator()->get($firstOptions->options);
        $secondAnswer  = $this->authenticator()->get($secondOptions->options);

        [$first, $second] = $this->race(
            static fn (): ?string => Auth::passkeys('api')->verifyFactor($identity, $firstOptions->challengeId, $firstAnswer)?->value,
            static fn (): ?string => Auth::passkeys('api')->verifyFactor(IntegrationIdentity::query()->findOrFail($identity->id), $secondOptions->challengeId, $secondAnswer)
                ?->value,
            commitFirst: true,
        );

        self::assertNull($first);
        self::assertSame(FailureReason::PASSKEY_COUNTER_REGRESSED->value, $second['outcome']);
        self::assertGreaterThanOrEqual(self::LEAST_WAIT_SECONDS, $second['waited']);
        self::assertSame(1, Passkey::query()->sole()->sign_count);
    }

    /**
     * Of two registrations of one credential, the one whose insert commits
     * first stores it; the other waited on the unique index and is refused as
     * already registered.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testOnlyTheFirstOfTwoRegistrationsOfACredentialStoresIt(): void
    {
        $identity = $this->seedIdentity();
        $other    = $this->seedIdentity('grace@example.test');
        $rawId    = random_bytes(32);

        $mine   = Auth::passkeys('api')->registrationOptions($identity, self::USER_NAME);
        $theirs = Auth::passkeys('api')->registrationOptions($other, 'grace@example.test');

        $myAnswer    = $this->authenticator()->create($mine->options, id: $rawId);
        $theirAnswer = (new VirtualAuthenticator(self::ORIGIN))->create($theirs->options, id: $rawId);

        [$first, $second] = $this->race(
            static fn (): ?string => self::registered(Auth::passkeys('api')->register($identity, $mine->challengeId, $myAnswer)),
            static fn (): ?string => self::registered(Auth::passkeys('api')->register(IntegrationIdentity::query()->findOrFail($other->id), $theirs->challengeId, $theirAnswer)),
            commitFirst: true,
        );

        self::assertNull($first);
        self::assertSame(PasskeyRegistrationFailure::ALREADY_REGISTERED->value, $second['outcome']);
        self::assertGreaterThanOrEqual(self::LEAST_WAIT_SECONDS, $second['waited']);
        self::assertSame([(string) $identity->id], Passkey::query()->pluck('authenticatable_id')->all());
    }

    /**
     * Configure the guards and their relying party.
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
        self::configurePasskeys($config);
    }

    /**
     * `null` for a registration that stored its passkey, else the failure's
     * value.
     *
     * @param  \SineMacula\Laravel\Authentication\Passkeys\Enums\PasskeyRegistrationFailure|\SineMacula\Laravel\Authentication\Passkeys\PasskeySummary  $outcome
     * @return ?string
     */
    private static function registered(PasskeyRegistrationFailure|PasskeySummary $outcome): ?string
    {
        return $outcome instanceof PasskeySummary ? null : $outcome->value;
    }

    /**
     * Run the first ceremony here inside a transaction, start the second in
     * another process once the first has written, hold the transaction open
     * while the second waits, then commit or roll back, and return both
     * outcomes.
     *
     * @param  \Closure(): ?string  $first
     * @param  \Closure(): ?string  $second
     * @param  bool  $commitFirst
     * @return array{0: ?string, 1: array<array-key, mixed>}
     *
     * @throws \Throwable
     */
    private function race(\Closure $first, \Closure $second, bool $commitFirst): array
    {
        DB::disconnect();

        $pid = pcntl_fork();

        if ($pid === 0) {
            $this->runInChild($second);
        }

        DB::beginTransaction();

        $outcome = $first();

        touch("{$this->outcomes}/start");
        usleep(self::HOLD_MICROSECONDS);

        $commitFirst ? DB::commit() : DB::rollBack();

        pcntl_waitpid($pid, $status);

        $other = json_decode((string) file_get_contents("{$this->outcomes}/outcome"), true, flags: JSON_THROW_ON_ERROR);

        self::assertIsArray($other);
        self::assertArrayNotHasKey('error', $other);

        return [$outcome, $other];
    }

    /**
     * In the forked process: wait to be started, run the ceremony on a
     * connection of its own, report the outcome, and end without running the
     * parent's shutdown.
     *
     * @param  \Closure(): ?string  $ceremony
     * @return never
     */
    private function runInChild(\Closure $ceremony): never
    {
        try {
            $deadline = microtime(true) + self::START_TIMEOUT_SECONDS;

            while (!is_file("{$this->outcomes}/start") && microtime(true) < $deadline) {
                usleep(5000);
            }

            $started = microtime(true);
            $outcome = ['outcome' => $ceremony(), 'waited' => microtime(true) - $started];
        } catch (\Throwable $e) {
            $outcome = ['error' => $e->getMessage()];
        }

        file_put_contents("{$this->outcomes}/outcome", json_encode($outcome));

        posix_kill(posix_getpid(), SIGKILL);

        exit(1);
    }
}
