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
use SineMacula\Laravel\Authentication\Contracts\RequirementCheck;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\SessionCreated;
use SineMacula\Laravel\Authentication\Events\SignedIn;
use SineMacula\Laravel\Authentication\Factors\AdditionalFactorContext;
use SineMacula\Laravel\Authentication\Models\Session;
use SineMacula\Laravel\Authentication\Models\SessionProof;
use SineMacula\Laravel\Authentication\Proofs\Enums\Purpose;
use SineMacula\Laravel\Authentication\Proofs\ProofResult;
use SineMacula\Laravel\Authentication\RateLimiting\AccountAttempts;
use SineMacula\Laravel\Authentication\Requirements\Requirement;
use SineMacula\Laravel\Authentication\Requirements\RequirementPart;
use SineMacula\Laravel\Authentication\Sessions\PendingSessions;
use SineMacula\Laravel\Authentication\Sessions\SessionActivation;
use SineMacula\Laravel\Authentication\Sessions\SessionService;
use SineMacula\Laravel\Authentication\Sessions\SignInResult;
use Tests\Concerns\InteractsWithProofs;
use Tests\Concerns\InteractsWithRateLimits;
use Tests\Concerns\InteractsWithSessions;
use Tests\Fixtures\Tenancy\ProofJudgingRequirementCheck;
use Tests\Integration\Fixtures\IntegrationIdentity;
use Tests\TestCase;

/**
 * Races two satisfactions of one pending credential, each in its own process,
 * so exactly one activates the session.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SessionService::class)]
#[CoversClass(PendingSessions::class)]
#[CoversClass(SessionActivation::class)]
final class ConcurrentPendingSatisfactionTest extends TestCase
{
    use InteractsWithProofs, InteractsWithRateLimits, InteractsWithSessions;

    /** @var int How long the first call holds its transaction open once the second has started, in microseconds. */
    private const int HOLD_MICROSECONDS = 1000000;

    /** @var float The least time, in seconds, the second call must have waited to show it waited on the first. */
    private const float LEAST_WAIT_SECONDS = 0.5;

    /** @var int How long the second call waits to be started before giving up, in seconds. */
    private const int START_TIMEOUT_SECONDS = 10;

    /** @var string Directory the second call reports its outcome in. */
    private string $outcomes;

    /**
     * Skip where processes cannot share the database, freeze the clocks, create
     * the tables and require a further factor.
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
             * @return \SineMacula\Laravel\Authentication\Requirements\Requirement
             */
            #[\Override]
            public function requirementFor(AdditionalFactorContext $context): Requirement
            {
                return new Requirement(new RequirementPart);
            }
        });
        app()->instance(RequirementCheck::class, new ProofJudgingRequirementCheck);

        $this->outcomes = sys_get_temp_dir() . '/satisfaction-race-' . bin2hex(random_bytes(8));

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
     * Only the first of two concurrent satisfactions to commit activates the
     * session.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testOnlyTheFirstOfTwoConcurrentSatisfactionsToCommitActivatesTheSession(): void
    {
        $identity = $this->seedHeldSignIn();

        [$first, $second] = $this->raceSatisfactions($this->pendingSession(), commitFirst: true);

        self::assertTrue($first->isSignedIn());
        self::assertSame([SessionCreated::class, SignedIn::class], $this->recordedClasses());

        self::assertSame(['status' => 'failed', 'reason' => FailureReason::PENDING_INVALID->value], $second['result']);
        self::assertSame([Failed::class, AuthenticationFailed::class], $second['events']);
        self::assertNull($second['failedMethod']);
        self::assertGreaterThanOrEqual(self::LEAST_WAIT_SECONDS, $second['waited']);

        $this->assertOneSessionAndOneRelease($identity);
    }

    /**
     * A satisfaction waiting on one that rolls back activates the session.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASatisfactionWaitingOnOneThatRollsBackActivatesTheSession(): void
    {
        $identity = $this->seedHeldSignIn();

        [$first, $second] = $this->raceSatisfactions($this->pendingSession(), commitFirst: false);

        self::assertTrue($first->isSignedIn());
        self::assertSame([], $this->recordedClasses());

        self::assertSame(['status' => 'signed_in', 'reason' => null], $second['result']);
        self::assertSame([SessionCreated::class, SignedIn::class], $second['events']);
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
     * attempt counted.
     *
     * @return \Tests\Integration\Fixtures\IntegrationIdentity
     *
     * @throws \Throwable
     */
    private function seedHeldSignIn(): IntegrationIdentity
    {
        $identity = $this->seedIdentity();

        $failed = $this->sessions()->signIn('password', ['email' => 'ada@example.test', 'password' => 'wrong'], self::requestContext());

        self::assertSame(FailureReason::INVALID_CREDENTIALS, $failed->reason);

        return $identity;
    }

    /**
     * Sign in and return the pending credential with a further factor's proof
     * bound to it.
     *
     * @return array{0: string, 1: \SineMacula\Laravel\Authentication\Proofs\ProofResult}
     *
     * @throws \Throwable
     */
    private function pendingSession(): array
    {
        $result = $this->sessions()->signIn('password', self::credentials(), self::requestContext());

        self::assertNotNull($result->pending);
        self::assertNotNull($result->credential);
        self::assertSame([2, 2], [$this->identifierHits(), $this->accountHits()]);

        return [$result->credential->reveal(), self::adapterProof($result->pending->identity, 'api', $result->pending->id, Purpose::SIGN_IN)];
    }

    /**
     * Satisfy the session in an open transaction, race a second call in another
     * process, then commit or roll back.
     *
     * @param  array{0: string, 1: \SineMacula\Laravel\Authentication\Proofs\ProofResult}  $pending
     * @param  bool  $commitFirst
     * @return array{0: \SineMacula\Laravel\Authentication\Sessions\SignInResult, 1: array<array-key, mixed>}
     *
     * @throws \Throwable
     */
    private function raceSatisfactions(array $pending, bool $commitFirst): array
    {
        $this->recordEvents([Failed::class, AuthenticationFailed::class, SessionCreated::class, SignedIn::class]);

        DB::disconnect();

        $pid = pcntl_fork();

        if ($pid === 0) {
            $this->satisfyInChild(...$pending);
        }

        DB::beginTransaction();

        $first = $this->sessions()->satisfy(...$pending, client: self::requestClient());

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
     * Satisfy the pending session in the forked process, report the outcome and
     * exit without the parent's shutdown.
     *
     * @param  string  $credential
     * @param  \SineMacula\Laravel\Authentication\Proofs\ProofResult  $proof
     * @return never
     */
    private function satisfyInChild(#[\SensitiveParameter] string $credential, ProofResult $proof): never
    {
        try {
            $deadline = microtime(true) + self::START_TIMEOUT_SECONDS;

            while (!is_file("{$this->outcomes}/start") && microtime(true) < $deadline) {
                usleep(5000);
            }

            $started = microtime(true);
            $result  = $this->sessions()->satisfy($credential, $proof, self::requestClient());
            $failed  = array_values(array_filter($this->recorded, static fn (object $event): bool => $event instanceof AuthenticationFailed));

            $outcome = [
                'result'       => self::describe($result),
                'events'       => $this->recordedClasses(),
                'failedMethod' => $failed === [] ? null : $failed[0]->context->method,
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
     * Assert one active session with one further factor, and each held slot
     * given back once.
     *
     * @param  \Tests\Integration\Fixtures\IntegrationIdentity  $identity
     * @return void
     */
    private function assertOneSessionAndOneRelease(IntegrationIdentity $identity): void
    {
        self::assertSame(1, Session::query()->where('authenticatable_type', $identity->getMorphClass())->count());
        self::assertSame(1, Session::query()->where('status', 'active')->count());
        self::assertSame(2, SessionProof::query()->count());
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
