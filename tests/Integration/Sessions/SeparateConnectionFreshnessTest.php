<?php

declare(strict_types = 1);

namespace Tests\Integration\Sessions;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Contracts\FreshnessPolicy;
use SineMacula\Laravel\Authentication\Database\StorageConnection;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Factors\Enums\FactorChange;
use SineMacula\Laravel\Authentication\Freshness\ConfiguredFreshness;
use SineMacula\Laravel\Authentication\Freshness\Operations;
use SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind;
use SineMacula\Laravel\Authentication\Proofs\Evaluation;
use SineMacula\Laravel\Authentication\Proofs\RecordedProof;
use SineMacula\Laravel\Authentication\Sessions\FactorChangeGate;
use Tests\Concerns\InteractsWithProofs;
use Tests\Concerns\InteractsWithSessionRecords;
use Tests\Integration\Fixtures\SeparateConnectionSession;
use Tests\Integration\Fixtures\SeparateConnectionSessionIdentity;
use Tests\TestCase;

/**
 * Integration tests of a current freshness judgement for sessions on their own
 * connection.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ConfiguredFreshness::class)]
#[CoversClass(FactorChangeGate::class)]
final class SeparateConnectionFreshnessTest extends TestCase
{
    use InteractsWithProofs, InteractsWithSessionRecords;

    /** @var string What a current judgement outside a transaction is refused with. */
    private const string OUTSIDE_A_TRANSACTION = 'A current freshness judgement is asked inside a transaction on the session model\'s connection.';

    /** @var \Carbon\CarbonImmutable Frozen clock reference. */
    private CarbonImmutable $now;

    /**
     * Freeze the clocks and create the identity table on the default
     * connection.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->now = CarbonImmutable::createStrict(2026, 4, 6, 12, 0, 0);

        Carbon::setTestNow($this->now);
        CarbonImmutable::setTestNow($this->now);

        Schema::create('stub_principals', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('email')->unique();
            $blueprint->string('password');
            $blueprint->boolean('is_active')->default(true);
            $blueprint->timestamps();
        });
    }

    /**
     * Release the clocks and drop the identity table.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Schema::dropIfExists('stub_principals');

        Carbon::setTestNow();
        CarbonImmutable::setTestNow();

        parent::tearDown();
    }

    /**
     * A current judgement inside a transaction on the default connection only
     * is refused.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACurrentJudgementOnTheDefaultConnectionOnlyIsRefused(): void
    {
        $session = $this->steppedUpSession();
        $policy  = app(FreshnessPolicy::class);

        $asks = [
            'freshProof' => static fn (): mixed => $policy->freshProof($session, Operations::FACTOR_CHANGE, current: true),
            'freshUntil' => static fn (): mixed => $policy->freshUntil($session, Operations::FACTOR_CHANGE, current: true),
        ];

        foreach ($asks as $asked => $ask) {

            DB::beginTransaction();

            try {
                self::assertFalse(StorageConnection::isInTransaction());

                $statements = self::statementsDuring(static fn (): \LogicException => self::thrownBy($ask));
            } finally {
                DB::rollBack();
            }

            self::assertSame([], $statements, $asked);
        }
    }

    /**
     * A current judgement inside a transaction on the session's connection is
     * answered.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACurrentJudgementOnTheSessionsConnectionIsAnswered(): void
    {
        $session    = $this->steppedUpSession();
        $policy     = app(FreshnessPolicy::class);
        $connection = DB::connection(SeparateConnectionSession::CONNECTION);

        $proof = null;
        $until = null;

        $statements = self::statementsDuring(static function () use ($connection, $policy, $session, &$proof, &$until): void {
            $connection->transaction(static function () use ($policy, $session, &$proof, &$until): void {
                self::assertTrue(StorageConnection::isInTransaction());

                $proof = $policy->freshProof($session, Operations::FACTOR_CHANGE, current: true);
                $until = $policy->freshUntil($session, Operations::FACTOR_CHANGE, current: true);
            });
        });

        self::assertInstanceOf(RecordedProof::class, $proof);
        self::assertSame(ProofKind::ADDITIONAL_FACTOR, $proof->kind);
        self::assertSame($this->now->subMinute()->getTimestamp(), $proof->authenticatedAt->getTimestamp());
        self::assertSame($this->now->subMinute()->addSeconds(900)->getTimestamp(), $until?->getTimestamp());
        self::assertCount(4, $statements);
        self::assertSame([SeparateConnectionSession::CONNECTION], array_values(array_unique(array_column($statements, 0))));
    }

    /**
     * A factor change is judged in its own transaction on the session's
     * connection.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFactorChangeIsJudgedInATransactionOnTheSessionsConnection(): void
    {
        $session = $this->steppedUpSession();

        $outside = Auth::sessions('api')->factorChange($session, FactorChange::ADD);

        DB::beginTransaction();

        try {
            $inside = Auth::sessions('api')->factorChange($session, FactorChange::ADD);
        } finally {
            DB::rollBack();
        }

        foreach ([$outside, $inside] as $verdict) {
            self::assertTrue($verdict->isAllowed());
            self::assertSame(ProofKind::ADDITIONAL_FACTOR, $verdict->proof?->kind);
            self::assertSame($this->now->subMinute()->addSeconds(900)->getTimestamp(), $verdict->freshUntil?->getTimestamp());
        }
    }

    /**
     * Keep the sessions on a separate database as the storage connection and
     * configure the `api` guard.
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

        $config->set('database.connections.' . SeparateConnectionSession::CONNECTION, ['driver' => 'sqlite', 'database' => ':memory:', 'prefix' => '']);
        $config->set('authentication.storage.connection', SeparateConnectionSession::CONNECTION);
        $config->set('authentication.rate_limits.connection', 'testing');
        $config->set('authentication.session.model', SeparateConnectionSession::class);
        $config->set('auth.defaults.guard', 'api');
        $config->set('auth.providers.identities', ['driver' => 'model', 'model' => SeparateConnectionSessionIdentity::class]);
        $config->set('auth.guards.api', ['driver' => 'jwt', 'provider' => 'identities', 'application' => ['methods' => ['password']]]);
    }

    /**
     * A live session on its own connection, stepped up a minute ago.
     *
     * @return \Tests\Integration\Fixtures\SeparateConnectionSession
     */
    private function steppedUpSession(): SeparateConnectionSession
    {
        $identity            = new SeparateConnectionSessionIdentity;
        $identity->email     = 'separate@example.test';
        $identity->password  = 'irrelevant';
        $identity->is_active = true;
        $identity->save();

        $session = new SeparateConnectionSession;
        $session->forceFill([
            ...self::liveSession(),
            'authenticatable_type' => $identity->getMorphClass(),
            'authenticatable_id'   => (string) $identity->getKey(), // @phpstan-ignore cast.string
            'principal_type'       => $identity->getMorphClass(),
            'principal_id'         => (string) $identity->getKey(), // @phpstan-ignore cast.string
        ])->save();

        self::recordProof($session, ProofKind::ADDITIONAL_FACTOR, $this->now->subMinute(), ['otp'], new Evaluation(true, true));

        return $session;
    }

    /**
     * The `LogicException` the current judgement is refused with.
     *
     * @param  \Closure(): mixed  $ask
     * @return \LogicException
     */
    private static function thrownBy(\Closure $ask): \LogicException
    {
        try {
            $ask();
        } catch (\LogicException $exception) {
            self::assertSame(self::OUTSIDE_A_TRANSACTION, $exception->getMessage());

            return $exception;
        }

        self::fail('A current judgement outside a transaction on the session\'s connection was answered.');
    }

    /**
     * Each statement run during the callback: its connection and its SQL.
     *
     * @param  \Closure(): mixed  $callback
     * @return list<array{0: string, 1: string}>
     */
    private static function statementsDuring(\Closure $callback): array
    {
        /** @var \ArrayObject<int, array{0: string, 1: string}> $statements */
        $statements = new \ArrayObject;

        Event::listen(QueryExecuted::class, static function (QueryExecuted $query) use ($statements): void {
            $statements->append([$query->connectionName, $query->sql]);
        });

        $callback();

        return array_values($statements->getArrayCopy());
    }
}
