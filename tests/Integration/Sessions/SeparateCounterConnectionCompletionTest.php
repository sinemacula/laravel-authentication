<?php

declare(strict_types = 1);

namespace Tests\Integration\Sessions;

use Carbon\CarbonImmutable;
use Firebase\JWT\JWT;
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
use SineMacula\Laravel\Authentication\Events\DeviceCreated;
use SineMacula\Laravel\Authentication\Events\Enums\SignInFailureReason;
use SineMacula\Laravel\Authentication\Events\SignedIn;
use SineMacula\Laravel\Authentication\Factors\AdditionalFactorContext;
use SineMacula\Laravel\Authentication\Models\Device;
use SineMacula\Laravel\Authentication\Models\PendingSignIn;
use SineMacula\Laravel\Authentication\Sessions\AccountAttempts;
use SineMacula\Laravel\Authentication\Sessions\SessionService;
use SineMacula\Laravel\Authentication\Sessions\SignInResult;
use Tests\Concerns\InteractsWithRateLimits;
use Tests\Concerns\InteractsWithSessions;
use Tests\Integration\Fixtures\IntegrationIdentity;
use Tests\TestCase;

/**
 * Completes pending sign-ins inside a caller's transaction while the attempt
 * counters live on a connection of their own, as the rate limit documentation
 * advises for callers who may roll back: a completion gives its slots back only
 * once its use of the pending sign-in commits, so rolling it back, which
 * restores the pending sign-in, gives nothing back, and completing it again
 * gives the slots back once. A release that fails after the commit is reported,
 * not thrown, so it keeps no committed session, nor any other callback of the
 * commit, from being reported.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SessionService::class)]
final class SeparateCounterConnectionCompletionTest extends TestCase
{
    use InteractsWithRateLimits, InteractsWithSessions;

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
             * @return bool
             */
            #[\Override]
            public function requiresAdditionalFactor(AdditionalFactorContext $context): bool
            {
                return true;
            }
        });
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
     * A completion rolled back by its caller gives no slot back and leaves the
     * pending sign-in to be completed again; completing it again gives each
     * slot back once, so the failed attempt before it stays counted, and the
     * pending sign-in is then used up.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARolledBackCompletionGivesNoSlotBack(): void
    {
        $identity = $this->seedHeldSignIn();
        $token    = $this->pendingToken($identity);

        DB::beginTransaction();

        self::assertTrue($this->sessions()->complete($token)->isSignedIn());
        self::assertSame([2, 2, 2], $this->hits($identity));

        DB::rollBack();

        self::assertSame([2, 2, 2], $this->hits($identity));
        self::assertSame(1, PendingSignIn::query()->count());
        self::assertSame(0, Device::query()->count());

        self::assertTrue($this->sessions()->complete($token)->isSignedIn());
        self::assertSame([1, 1, 1], $this->hits($identity));

        self::assertSame(SignInFailureReason::PENDING_INVALID, $this->sessions()->complete($token)->reason);
        self::assertSame([1, 1, 1], $this->hits($identity));
        self::assertSame(1, Device::query()->count());
    }

    /**
     * A completion inside a caller's transaction gives its slots back when the
     * transaction commits, not before.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACompletionGivesItsSlotsBackWhenItsTransactionCommits(): void
    {
        $identity = $this->seedHeldSignIn();
        $token    = $this->pendingToken($identity);

        DB::transaction(function () use ($identity, $token): void {

            self::assertTrue($this->sessions()->complete($token)->isSignedIn());
            self::assertSame([2, 2, 2], $this->hits($identity));
        });

        self::assertSame([1, 1, 1], $this->hits($identity));
        self::assertSame(0, PendingSignIn::query()->count());
        self::assertSame(1, Device::query()->count());
    }

    /**
     * A completion whose slots cannot be given back once its transaction
     * commits reports the counters' error instead of throwing it: its session
     * stands and is reported, and the slots stay counted.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACompletionWhoseSlotsCannotBeGivenBackReportsTheErrorAndItsSession(): void
    {
        $identity   = $this->seedHeldSignIn();
        $token      = $this->pendingToken($identity);
        $exceptions = Exceptions::fake([QueryException::class]);

        $this->recordEvents([DeviceCreated::class, SignedIn::class]);
        $this->makeCountersUnreachable();

        $result = DB::transaction(fn (): SignInResult => $this->sessions()->complete($token));

        $this->restoreCounters();

        self::assertTrue($result->isSignedIn());
        self::assertSame([DeviceCreated::class, SignedIn::class], $this->recordedClasses());
        self::assertSame([2, 2, 2], $this->hits($identity));
        self::assertSame(1, Device::query()->count());
        self::assertSame(0, PendingSignIn::query()->count());
        self::assertCount(1, $exceptions->reported());

        Exceptions::assertReported(static fn (QueryException $exception): bool => str_contains($exception->getMessage(), 'rate_limits'));
    }

    /**
     * Two completions in one transaction, the first of which cannot give its
     * slots back: the second session is still reported and gives its own slots
     * back, and a callback the caller queued after both still runs.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFailedReleaseLetsTheCallbacksQueuedAfterItRun(): void
    {
        $identity   = $this->seedHeldSignIn();
        $first      = $this->pendingToken($identity);
        $second     = $this->pendingToken($identity, 3);
        $exceptions = Exceptions::fake([QueryException::class]);
        $signedIn   = 0;
        $callerRan  = false;

        $this->recordEvents([DeviceCreated::class, SignedIn::class]);

        Event::listen(SignedIn::class, function () use (&$signedIn): void {
            if (++$signedIn !== 2) {
                return;
            }

            $this->restoreCounters();
        });

        $this->makeCountersUnreachable();

        DB::transaction(function () use ($first, $second, &$callerRan): void {

            self::assertTrue($this->sessions()->complete($first)->isSignedIn());
            self::assertTrue($this->sessions()->complete($second)->isSignedIn());

            DB::afterCommit(static function () use (&$callerRan): void {
                $callerRan = true;
            });
        });

        self::assertTrue($callerRan);
        self::assertSame([DeviceCreated::class, SignedIn::class, DeviceCreated::class, SignedIn::class], $this->recordedClasses());
        self::assertSame([2, 2, 2], $this->hits($identity));
        self::assertSame(2, Device::query()->count());
        self::assertSame(0, PendingSignIn::query()->count());
        self::assertCount(1, $exceptions->reported());
    }

    /**
     * A completion inside a savepoint whose slots cannot be given back, whose
     * callbacks Laravel runs before those of the transaction around it, keeps
     * neither the earlier completion's session nor the caller's own callback
     * from being reported; each failed release is reported and its slots stay
     * counted.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFailedReleaseInASavepointLetsTheOuterCallbacksRun(): void
    {
        $identity   = $this->seedHeldSignIn();
        $outer      = $this->pendingToken($identity);
        $inner      = $this->pendingToken($identity, 3);
        $exceptions = Exceptions::fake([QueryException::class]);
        $callerRan  = false;

        $this->recordEvents([DeviceCreated::class, SignedIn::class]);
        $this->makeCountersUnreachable();

        DB::transaction(function () use ($outer, $inner, &$callerRan): void {

            self::assertTrue($this->sessions()->complete($outer)->isSignedIn());

            DB::transaction(function () use ($inner): void {
                self::assertTrue($this->sessions()->complete($inner)->isSignedIn());
            });

            DB::afterCommit(static function () use (&$callerRan): void {
                $callerRan = true;
            });
        });

        $this->restoreCounters();

        self::assertTrue($callerRan);
        self::assertSame([DeviceCreated::class, SignedIn::class, DeviceCreated::class, SignedIn::class], $this->recordedClasses());
        self::assertSame([3, 3, 3], $this->hits($identity));
        self::assertSame(2, Device::query()->count());
        self::assertSame(0, PendingSignIn::query()->count());
        self::assertCount(2, $exceptions->reported());
    }

    /**
     * Configure the guards, and the counters on a second connection to the test
     * database (a database of its own on SQLite, where each in-memory
     * connection has one).
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
     * Persist an identity with a failed sign-in counted on its identifier, the
     * client's IP address and its account, so a slot given back twice would
     * show.
     *
     * @return \Tests\Integration\Fixtures\IntegrationIdentity
     *
     * @throws \Throwable
     */
    private function seedHeldSignIn(): IntegrationIdentity
    {
        $identity = $this->seedIdentity();

        self::assertSame(SignInFailureReason::INVALID_CREDENTIALS, $this->sessions()->signIn('password', ['email' => 'ada@example.test', 'password' => 'wrong'])->reason);
        self::assertSame([1, 1, 1], $this->hits($identity));

        return $identity;
    }

    /**
     * Sign in and return the token of the pending sign-in the factor policy
     * asked for, which holds one more slot on each counter, so each then holds
     * the given number.
     *
     * @param  \Tests\Integration\Fixtures\IntegrationIdentity  $identity
     * @param  int  $held
     * @return string
     *
     * @throws \Throwable
     */
    private function pendingToken(IntegrationIdentity $identity, int $held = 2): string
    {
        $pending = $this->sessions()->signIn('password', self::credentials())->pending;

        self::assertNotNull($pending);
        self::assertSame([$held, $held, $held], $this->hits($identity));

        return $pending->token;
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
     * The hits on the identifier's, the client IP address's and the account's
     * sign-in counters, read on the counters' connection.
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
