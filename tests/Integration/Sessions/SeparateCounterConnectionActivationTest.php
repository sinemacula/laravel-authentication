<?php

declare(strict_types = 1);

namespace Tests\Integration\Sessions;

use Carbon\CarbonImmutable;
use Firebase\JWT\JWT;
use Illuminate\Auth\Events\Login;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\QueryException;
use Illuminate\Foundation\Application;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Exceptions;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Contracts\AdditionalFactorPolicy;
use SineMacula\Laravel\Authentication\Contracts\RequirementCheck;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\SessionCreated;
use SineMacula\Laravel\Authentication\Events\SignedIn;
use SineMacula\Laravel\Authentication\Factors\AdditionalFactorContext;
use SineMacula\Laravel\Authentication\Models\Session;
use SineMacula\Laravel\Authentication\Proofs\Enums\Purpose;
use SineMacula\Laravel\Authentication\RateLimiting\AccountAttempts;
use SineMacula\Laravel\Authentication\Requirements\Requirement;
use SineMacula\Laravel\Authentication\Requirements\RequirementPart;
use SineMacula\Laravel\Authentication\Sessions\Enums\SessionStatus;
use SineMacula\Laravel\Authentication\Sessions\PendingSessions;
use SineMacula\Laravel\Authentication\Sessions\SessionActivation;
use SineMacula\Laravel\Authentication\Sessions\SignInResult;
use Tests\Concerns\InteractsWithProofs;
use Tests\Concerns\InteractsWithRateLimits;
use Tests\Concerns\InteractsWithSessions;
use Tests\Fixtures\Tenancy\ProofJudgingRequirementCheck;
use Tests\Integration\Fixtures\IntegrationIdentity;
use Tests\TestCase;

/**
 * Integration tests of pending session activation with the attempt counters on
 * their own connection.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PendingSessions::class)]
#[CoversClass(SessionActivation::class)]
final class SeparateCounterConnectionActivationTest extends TestCase
{
    use InteractsWithProofs, InteractsWithRateLimits, InteractsWithSessions;

    /** @var string Connection the attempt counters live on. */
    private const string COUNTERS = 'counters';

    /**
     * Freeze the clocks, create the tables, and require a further factor of
     * every sign-in.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

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
    }

    /**
     * Drop the tables and release the clocks.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $this->dropSessionTables();

        Carbon::setTestNow();
        CarbonImmutable::setTestNow();

        JWT::$timestamp = null;

        parent::tearDown();
    }

    /**
     * A rolled-back activation gives no slot back, and satisfying it again
     * gives each back once.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARolledBackActivationGivesNoSlotBack(): void
    {
        $identity             = $this->seedHeldSignIn();
        [$credential, $proof] = $this->pendingSession($identity);

        DB::beginTransaction();

        self::assertTrue($this->sessions()->satisfy($credential, $proof, self::requestClient())->isSignedIn());
        self::assertSame([2, 2, 2], $this->hits($identity));

        DB::rollBack();

        self::assertSame([2, 2, 2], $this->hits($identity));
        self::assertSame(SessionStatus::PENDING, Session::query()->sole()->getStatus());

        self::assertTrue($this->sessions()->satisfy($credential, $proof, self::requestClient())->isSignedIn());
        self::assertSame([1, 1, 1], $this->hits($identity));

        self::assertSame(FailureReason::PENDING_INVALID, $this->sessions()->satisfy($credential, $proof, self::requestClient())->reason);
        self::assertSame([1, 1, 1], $this->hits($identity));
        self::assertSame(SessionStatus::ACTIVE, Session::query()->sole()->getStatus());
    }

    /**
     * An activation gives its slots back when its transaction commits.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnActivationGivesItsSlotsBackWhenItsTransactionCommits(): void
    {
        $identity             = $this->seedHeldSignIn();
        [$credential, $proof] = $this->pendingSession($identity);

        DB::transaction(function () use ($identity, $credential, $proof): void {

            self::assertTrue($this->sessions()->satisfy($credential, $proof, self::requestClient())->isSignedIn());
            self::assertSame([2, 2, 2], $this->hits($identity));
        });

        self::assertSame([1, 1, 1], $this->hits($identity));
        self::assertSame(SessionStatus::ACTIVE, Session::query()->sole()->getStatus());
    }

    /**
     * An activation whose slots cannot be given back reports the error and its
     * session.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFailedSlotReleaseReportsTheErrorAndTheSession(): void
    {
        $identity             = $this->seedHeldSignIn();
        [$credential, $proof] = $this->pendingSession($identity);
        $exceptions           = Exceptions::fake([QueryException::class]);

        $this->recordEvents([SessionCreated::class, SignedIn::class]);
        $this->makeCountersUnreachable();

        $result = DB::transaction(fn (): SignInResult => $this->sessions()->satisfy($credential, $proof, self::requestClient()));

        $this->restoreCounters();

        self::assertTrue($result->isSignedIn());
        self::assertSame([SessionCreated::class, SignedIn::class], $this->recordedClasses());
        self::assertSame([2, 2, 2], $this->hits($identity));
        self::assertSame(SessionStatus::ACTIVE, Session::query()->sole()->getStatus());
        self::assertCount(1, $exceptions->reported());

        Exceptions::assertReported(static fn (QueryException $exception): bool => str_contains($exception->getMessage(), 'rate_limits'));
    }

    /**
     * A failed release lets the callbacks queued after it run.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFailedReleaseLetsTheCallbacksQueuedAfterItRun(): void
    {
        $identity   = $this->seedHeldSignIn();
        $first      = $this->pendingSession($identity);
        $second     = $this->pendingSession($identity, 3);
        $exceptions = Exceptions::fake([QueryException::class]);
        $bound      = 0;
        $callerRan  = false;

        $this->recordEvents([SessionCreated::class, SignedIn::class]);

        Event::listen(Login::class, function () use (&$bound): void {
            if (++$bound !== 2) {
                return;
            }

            $this->restoreCounters();
        });

        $this->makeCountersUnreachable();

        $sessions = $this->sessions();

        DB::transaction(static function () use ($sessions, $first, $second, &$callerRan): void {

            self::assertTrue($sessions->satisfy(...$first, client: self::requestClient())->isSignedIn());
            self::assertTrue($sessions->satisfy(...$second, client: self::requestClient())->isSignedIn());

            DB::afterCommit(static function () use (&$callerRan): void {
                $callerRan = true;
            });
        });

        self::assertTrue($callerRan);
        self::assertSame(2, $bound);
        self::assertSame([SessionCreated::class, SignedIn::class, SessionCreated::class, SignedIn::class], $this->recordedClasses());
        self::assertSame([2, 2, 2], $this->hits($identity));
        self::assertSame(2, Session::query()->where('status', SessionStatus::ACTIVE->value)->count());
        self::assertCount(1, $exceptions->reported());
    }

    /**
     * A failed release in a savepoint lets the outer transaction's callbacks
     * run.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFailedReleaseInASavepointLetsTheOuterCallbacksRun(): void
    {
        $identity   = $this->seedHeldSignIn();
        $outer      = $this->pendingSession($identity);
        $inner      = $this->pendingSession($identity, 3);
        $exceptions = Exceptions::fake([QueryException::class]);
        $callerRan  = false;

        $this->recordEvents([SessionCreated::class, SignedIn::class]);
        $this->makeCountersUnreachable();

        DB::transaction(function () use ($outer, $inner, &$callerRan): void {

            self::assertTrue($this->sessions()->satisfy(...$outer, client: self::requestClient())->isSignedIn());

            DB::transaction(function () use ($inner): void {
                self::assertTrue($this->sessions()->satisfy(...$inner, client: self::requestClient())->isSignedIn());
            });

            DB::afterCommit(static function () use (&$callerRan): void {
                $callerRan = true;
            });
        });

        $this->restoreCounters();

        self::assertTrue($callerRan);
        self::assertSame([SessionCreated::class, SignedIn::class, SessionCreated::class, SignedIn::class], $this->recordedClasses());
        self::assertSame([3, 3, 3], $this->hits($identity));
        self::assertSame(2, Session::query()->where('status', SessionStatus::ACTIVE->value)->count());
        self::assertCount(2, $exceptions->reported());
    }

    /**
     * Configure the guards, with the counters on a second connection to the
     * test database (its own database on in-memory SQLite).
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

        $config->set('database.connections.' . self::COUNTERS, $config->array('database.connections.testing'));
        $config->set('authentication.rate_limits.connection', self::COUNTERS);
    }

    /**
     * Persist an identity with one failed sign-in counted on each counter.
     *
     * @return \Tests\Integration\Fixtures\IntegrationIdentity
     *
     * @throws \Throwable
     */
    private function seedHeldSignIn(): IntegrationIdentity
    {
        $identity = $this->seedIdentity();

        self::assertSame(
            FailureReason::INVALID_CREDENTIALS,
            $this->sessions()->signIn('password', ['email' => 'ada@example.test', 'password' => 'wrong'], self::requestContext())->reason,
        );
        self::assertSame([1, 1, 1], $this->hits($identity));

        return $identity;
    }

    /**
     * Sign in and return the pending session's credential and a proof that
     * satisfies it.
     *
     * @param  \Tests\Integration\Fixtures\IntegrationIdentity  $identity
     * @param  int  $held
     * @return array{0: string, 1: \SineMacula\Laravel\Authentication\Proofs\ProofResult}
     *
     * @throws \Throwable
     */
    private function pendingSession(IntegrationIdentity $identity, int $held = 2): array
    {
        $result = $this->sessions()->signIn('password', self::credentials(), self::requestContext());

        self::assertNotNull($result->pending);
        self::assertNotNull($result->credential);
        self::assertSame([$held, $held, $held], $this->hits($identity));

        return [$result->credential->reveal(), self::adapterProof($identity, 'api', $result->pending->id, Purpose::SIGN_IN)];
    }

    /**
     * Move the counters' table out of reach, so giving a slot back fails.
     *
     * @return void
     */
    private function makeCountersUnreachable(): void
    {
        Schema::connection(self::COUNTERS)->rename('rate_limits', 'unreachable_rate_limits');
    }

    /**
     * Bring the counters' table back.
     *
     * @return void
     */
    private function restoreCounters(): void
    {
        Schema::connection(self::COUNTERS)->rename('unreachable_rate_limits', 'rate_limits');
    }

    /**
     * The hits on the identifier, IP address and account sign-in counters.
     *
     * @param  \Tests\Integration\Fixtures\IntegrationIdentity  $identity
     * @return list<int>
     */
    private function hits(IntegrationIdentity $identity): array
    {
        $keys = [
            self::counterKey('api', 'sign_in', 'per_identifier', 'ada@example.test'),
            self::counterKey('api', 'sign_in', 'per_ip', self::CLIENT_IP),
            self::counterKey('sign_in', 'per_account', AccountAttempts::account($identity)),
        ];

        return array_map(static function (string $key): int {
            $hits = DB::connection(self::COUNTERS)->table('rate_limits')->where('key', $key)->value('hits');

            return is_numeric($hits) ? (int) $hits : 0;
        }, $keys);
    }
}
