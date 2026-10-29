<?php

declare(strict_types = 1);

namespace Tests\Integration\Sessions;

use Carbon\CarbonImmutable;
use Firebase\JWT\JWT;
use Illuminate\Auth\Events\Failed;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Contracts\AdditionalFactorPolicy;
use SineMacula\Laravel\Authentication\Events\DeviceCreated;
use SineMacula\Laravel\Authentication\Events\Enums\SignInFailureReason;
use SineMacula\Laravel\Authentication\Events\SignedIn;
use SineMacula\Laravel\Authentication\Events\SignInFailed;
use SineMacula\Laravel\Authentication\Factors\AdditionalFactorContext;
use SineMacula\Laravel\Authentication\Models\Device;
use SineMacula\Laravel\Authentication\Models\PendingSignIn;
use SineMacula\Laravel\Authentication\Sessions\AccountAttempts;
use SineMacula\Laravel\Authentication\Sessions\PendingSignIns;
use SineMacula\Laravel\Authentication\Sessions\SessionService;
use SineMacula\Laravel\Authentication\Sessions\SignInResult;
use Tests\Concerns\InteractsWithRateLimits;
use Tests\Concerns\InteractsWithSessions;
use Tests\Integration\Fixtures\IntegrationIdentity;
use Tests\TestCase;

/**
 * Races two completions of one pending sign-in on PostgreSQL and MySQL, each in
 * a process with a database connection of its own: one completes inside a
 * transaction it holds open, and the other, started meanwhile, waits on the
 * pending sign-in's row. Whichever transaction commits the delete wins; the
 * other completion fails as `pending_invalid` and starts nothing, so exactly
 * one device is created, one set of slots given back, and one set of events
 * dispatched.
 *
 * Skipped on SQLite, whose in-memory database each process would have to
 * itself, and where `pcntl` is not available.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SessionService::class)]
#[CoversClass(PendingSignIns::class)]
final class ConcurrentPendingCompletionTest extends TestCase
{
    use InteractsWithRateLimits, InteractsWithSessions;

    /** @var int How long the first completion holds its transaction open once the second has started, in microseconds. */
    private const int HOLD_MICROSECONDS = 1000000;

    /** @var float The least time, in seconds, the second completion must have waited to show it waited on the first. */
    private const float LEAST_WAIT_SECONDS = 0.5;

    /** @var int How long the second completion waits to be started before giving up, in seconds. */
    private const int START_TIMEOUT_SECONDS = 10;

    /** @var string Directory the second completion reports its outcome in. */
    private string $outcomes;

    /**
     * Skip where processes cannot share the database, freeze the clocks so both
     * processes see one moment, create the tables, and require a further factor
     * of every sign-in.
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

        JWT::$timestamp = $now->getTimestamp();

        $this->createSessionTables();

        app()->instance(AdditionalFactorPolicy::class, new class implements AdditionalFactorPolicy {
            /**
             * Always require a further factor.
             *
             * @param  \SineMacula\Laravel\Authentication\Factors\AdditionalFactorContext  $context
             * @return bool
             */
            #[\Override]
            public function requiresAdditionalFactor(AdditionalFactorContext $context): bool
            {
                return true;
            }
        });

        $this->outcomes = sys_get_temp_dir() . '/completion-race-' . bin2hex(random_bytes(8));

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
     * The completion that commits first starts the session; the one that waited
     * on its delete then finds the pending sign-in gone and fails as
     * `pending_invalid` for its method, without a device, a slot given back, or
     * a sign-in event.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testOnlyTheFirstOfTwoConcurrentCompletionsToCommitStartsASession(): void
    {
        $identity = $this->seedHeldSignIn();

        [$first, $second] = $this->raceCompletions($this->pendingToken(), commitFirst: true);

        self::assertTrue($first->isSignedIn());
        self::assertSame([DeviceCreated::class, SignedIn::class], $this->recordedClasses());

        self::assertSame(['status' => 'failed', 'reason' => SignInFailureReason::PENDING_INVALID->value], $second['result']);
        self::assertSame([Failed::class, SignInFailed::class], $second['events']);
        self::assertSame('password', $second['failedMethod']);
        self::assertGreaterThanOrEqual(self::LEAST_WAIT_SECONDS, $second['waited']);

        $this->assertOneSessionAndOneRelease($identity);
    }

    /**
     * When the first completion's transaction rolls back, the completion that
     * waited on its delete completes the pending sign-in instead: it starts the
     * one session, gives the slots back and dispatches the events, while the
     * rolled-back completion leaves nothing behind.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACompletionWaitingOnOneThatRollsBackStartsTheSession(): void
    {
        $identity = $this->seedHeldSignIn();

        [$first, $second] = $this->raceCompletions($this->pendingToken(), commitFirst: false);

        self::assertTrue($first->isSignedIn());
        self::assertSame([], $this->recordedClasses());

        self::assertSame(['status' => 'signed_in', 'reason' => null], $second['result']);
        self::assertSame([DeviceCreated::class, SignedIn::class], $second['events']);
        self::assertNull($second['failedMethod']);
        self::assertGreaterThanOrEqual(self::LEAST_WAIT_SECONDS, $second['waited']);

        $this->assertOneSessionAndOneRelease($identity);
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
     * Persist an identity whose identifier and account each have a failed
     * attempt counted, so a slot given back twice would show.
     *
     * @return \Tests\Integration\Fixtures\IntegrationIdentity
     *
     * @throws \Throwable
     */
    private function seedHeldSignIn(): IntegrationIdentity
    {
        $identity = $this->seedIdentity();

        $failed = $this->sessions()->signIn('password', ['email' => 'ada@example.test', 'password' => 'wrong']);

        self::assertSame(SignInFailureReason::INVALID_CREDENTIALS, $failed->reason);

        return $identity;
    }

    /**
     * Sign in and return the token of the pending sign-in the factor policy
     * asked for, which holds a second slot on the identifier and the account.
     *
     * @return string
     *
     * @throws \Throwable
     */
    private function pendingToken(): string
    {
        $pending = $this->sessions()->signIn('password', self::credentials())->pending;

        self::assertNotNull($pending);
        self::assertSame([2, 2], [$this->identifierHits(), $this->accountHits()]);

        return $pending->token;
    }

    /**
     * Complete the pending sign-in here inside a transaction, start a second
     * completion of it in another process once this one has deleted the row,
     * hold the transaction open while the second waits, then commit or roll
     * back, and return both outcomes.
     *
     * @param  string  $token
     * @param  bool  $commitFirst
     * @return array{0: \SineMacula\Laravel\Authentication\Sessions\SignInResult, 1: array<array-key, mixed>}
     *
     * @throws \Throwable
     */
    private function raceCompletions(#[\SensitiveParameter] string $token, bool $commitFirst): array
    {
        $this->recordEvents([Failed::class, SignInFailed::class, DeviceCreated::class, SignedIn::class]);

        DB::disconnect();

        $pid = pcntl_fork();

        if ($pid === 0) {
            $this->completeInChild($token);
        }

        DB::beginTransaction();

        $first = $this->sessions()->complete($token);

        touch("{$this->outcomes}/start");
        usleep(self::HOLD_MICROSECONDS);

        $commitFirst ? DB::commit() : DB::rollBack();

        pcntl_waitpid($pid, $status);

        $second = json_decode((string) file_get_contents("{$this->outcomes}/outcome"), true, flags: JSON_THROW_ON_ERROR);

        self::assertIsArray($second);
        self::assertArrayNotHasKey('error', $second);

        return [$first, $second];
    }

    /**
     * In the forked process: wait to be started, complete the pending sign-in
     * on a connection of its own, report the outcome, and end without running
     * the parent's shutdown.
     *
     * @param  string  $token
     * @return never
     */
    private function completeInChild(#[\SensitiveParameter] string $token): never
    {
        try {
            $deadline = microtime(true) + self::START_TIMEOUT_SECONDS;

            while (!is_file("{$this->outcomes}/start") && microtime(true) < $deadline) {
                usleep(5000);
            }

            $started = microtime(true);
            $result  = $this->sessions()->complete($token);
            $failed  = array_values(array_filter($this->recorded, static fn (object $event): bool => $event instanceof SignInFailed));

            $outcome = [
                'result'       => self::describe($result),
                'events'       => $this->recordedClasses(),
                'failedMethod' => $failed === [] ? null : $failed[0]->method,
                'waited'       => microtime(true) - $started,
            ];
        } catch (\Throwable $e) {
            $outcome = ['error' => $e->getMessage()];
        }

        file_put_contents("{$this->outcomes}/outcome", json_encode($outcome));

        posix_kill(posix_getpid(), SIGKILL);

        exit(1);
    }

    /**
     * Assert the race left one device, no pending sign-in, and the identifier's
     * and the account's held slots given back once each.
     *
     * @param  \Tests\Integration\Fixtures\IntegrationIdentity  $identity
     * @return void
     */
    private function assertOneSessionAndOneRelease(IntegrationIdentity $identity): void
    {
        self::assertSame(1, Device::query()->where('authenticatable_type', $identity->getMorphClass())->count());
        self::assertSame(1, Device::query()->count());
        self::assertSame(0, PendingSignIn::query()->count());
        self::assertSame([1, 1], [$this->identifierHits(), $this->accountHits()]);
    }

    /**
     * The status and reason of a result.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignInResult  $result
     * @return array{status: string, reason: ?string}
     */
    private static function describe(SignInResult $result): array
    {
        return ['status' => $result->status->value, 'reason' => $result->reason?->value];
    }

    /**
     * The hits on the `api` guard's sign-in counter for the seeded address.
     *
     * @return int
     */
    private function identifierHits(): int
    {
        return self::counterHits('api', 'sign_in', 'per_identifier', 'ada@example.test');
    }

    /**
     * The hits on the seeded identity's account counter.
     *
     * @return int
     */
    private function accountHits(): int
    {
        $identity = IntegrationIdentity::query()->where('email', 'ada@example.test')->firstOrFail();

        return self::counterHits('sign_in', 'per_account', AccountAttempts::account($identity));
    }
}
