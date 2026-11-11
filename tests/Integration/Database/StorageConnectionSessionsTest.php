<?php

declare(strict_types = 1);

namespace Tests\Integration\Database;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Database\Query\Builder;
use Illuminate\Database\QueryException;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Codes\CodeBinding;
use SineMacula\Laravel\Authentication\Codes\Enums\CodeCheck;
use SineMacula\Laravel\Authentication\Codes\IssuedCode;
use SineMacula\Laravel\Authentication\Codes\OneTimeCodes;
use SineMacula\Laravel\Authentication\Contracts\AdditionalFactorPolicy;
use SineMacula\Laravel\Authentication\Contracts\RequirementCheck;
use SineMacula\Laravel\Authentication\Database\StorageConnection;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Factors\AdditionalFactorContext;
use SineMacula\Laravel\Authentication\Factors\Enums\FactorChangeMade;
use SineMacula\Laravel\Authentication\Models\Session;
use SineMacula\Laravel\Authentication\Models\SessionProof;
use SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\Purpose;
use SineMacula\Laravel\Authentication\RateLimiting\AccountAttempts;
use SineMacula\Laravel\Authentication\Requirements\Requirement;
use SineMacula\Laravel\Authentication\Requirements\RequirementPart;
use Tests\Concerns\InteractsWithPasskeys;
use Tests\Concerns\InteractsWithProofs;
use Tests\Concerns\InteractsWithRateLimits;
use Tests\Concerns\InteractsWithSessionRecords;
use Tests\Concerns\InteractsWithSessions;
use Tests\Fixtures\Tenancy\ProofJudgingRequirementCheck;
use Tests\Integration\Fixtures\IntegrationIdentity;
use Tests\Integration\Fixtures\NamedConnectionIdentity;
use Tests\TestCase;

/**
 * Integration tests of the package on a storage connection other than the
 * default.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(StorageConnection::class)]
final class StorageConnectionSessionsTest extends TestCase
{
    use InteractsWithPasskeys, InteractsWithProofs, InteractsWithRateLimits, InteractsWithSessionRecords, InteractsWithSessions;

    /** @var string The connection the package's tables live on. */
    private const string STORAGE = 'package_store';

    /** @var string The connection the counters live on. */
    private const string COUNTERS = 'counters';

    /**
     * Create the identity tables on the default connection.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->createSessionTables();
    }

    /**
     * Drop the identity tables and forget the session listeners a test added.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Session::flushEventListeners();

        $this->dropSessionTables();

        parent::tearDown();
    }

    /**
     * A sign-in counts on the counters' connection and writes and refreshes its
     * session on the storage connection.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASessionIsWrittenAndRefreshedOnTheStorageConnection(): void
    {
        $identity = $this->seedIdentity();

        self::assertSame(
            FailureReason::INVALID_CREDENTIALS,
            $this->sessions()->signIn('password', ['email' => 'ada@example.test', 'password' => 'wrong'], self::requestContext())->reason,
        );
        self::assertSame(1, $this->accountHits($identity));

        $session = $this->sessions()->signIn('password', self::credentials(), self::requestContext())->session;

        self::assertNotNull($session);
        self::assertSame(self::STORAGE, $session->record->getConnectionName());
        self::assertSame(1, $this->records()->count());

        $digest = $this->records()->value('refresh_key');

        self::assertNotNull(
            self::sessionsOf($this->freshGuard())->refresh(self::bodyToken($session->tokens), self::requestClient())->session,
        );
        self::assertNotSame($digest, $this->records()->value('refresh_key'));
    }

    /**
     * A passkey is registered and used to sign in on the storage connection.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPasskeyRegistersAndSignsInOnTheStorageConnection(): void
    {
        $this->registerPasskey($this->seedIdentity());

        self::assertSame(1, DB::connection(self::STORAGE)->table('passkeys')->count());

        $this->signInOptions();

        self::assertSame(1, DB::connection(self::STORAGE)->table('passkey_challenges')->whereNull('consumed_at')->count());
        self::assertTrue($this->signInWithPasskey()->isSignedIn());
        self::assertSame(1, $this->records()->count());
    }

    /**
     * A one-time code is issued, and used, on the storage connection.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAOneTimeCodeIsIssuedAndUsedOnTheStorageConnection(): void
    {
        $codes   = app(OneTimeCodes::class);
        $binding = CodeBinding::signIn('api', 'email', 'ada@example.test');
        $now     = CarbonImmutable::now();
        $issued  = $codes->issue($binding, $now);

        self::assertInstanceOf(IssuedCode::class, $issued);
        self::assertSame(1, DB::connection(self::STORAGE)->table('one_time_codes')->count());
        self::assertSame(CodeCheck::ACCEPTED, $codes->check($binding, $issued->challengeId, $issued->code(), $now));
        self::assertNotNull(DB::connection(self::STORAGE)->table('one_time_codes')->value('consumed_at'));
    }

    /**
     * A failed write while satisfying a pending session leaves it pending.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFailedWriteKeepsTheSessionPending(): void
    {
        $identity = $this->seedIdentity();

        $this->requireAFurtherFactor();

        $result = $this->sessions()->signIn('password', self::credentials(), self::requestContext());

        self::assertNotNull($result->pending);
        self::assertNotNull($result->credential);
        self::assertSame(1, $this->records()->where('status', 'pending')->count());

        $proof = self::adapterProof($identity, 'api', $result->pending->id, Purpose::SIGN_IN);

        SessionProof::creating(static function (): never {
            throw new \RuntimeException('The proof could not be written.');
        });

        try {
            $this->sessions()->satisfy($result->credential->reveal(), $proof, self::requestClient());

            self::fail('Expected the proof write to fail.');
        } catch (\RuntimeException $exception) {
            self::assertSame('The proof could not be written.', $exception->getMessage());
        }

        self::assertSame(1, $this->records()->where('status', 'pending')->count());
        self::assertSame(1, DB::connection(self::STORAGE)->table('authentication_proofs')->count());

        SessionProof::flushEventListeners();

        self::assertTrue($this->sessions()->satisfy($result->credential->reveal(), $proof, self::requestClient())->isSignedIn());
        self::assertSame(1, $this->records()->where('status', 'active')->count());
        self::assertSame(FailureReason::PENDING_INVALID, $this->sessions()->satisfy($result->credential->reveal(), $proof, self::requestClient())->reason);
    }

    /**
     * A rolled back storage transaction leaves the counters counted.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARolledBackStorageTransactionLeavesTheCountersCounted(): void
    {
        $identity = $this->seedIdentity();
        $storage  = DB::connection(self::STORAGE);

        $storage->beginTransaction();

        self::assertSame(
            FailureReason::INVALID_CREDENTIALS,
            $this->sessions()->signIn('password', ['email' => 'ada@example.test', 'password' => 'wrong'], self::requestContext())->reason,
        );

        $storage->rollBack();

        self::assertSame(1, $this->accountHits($identity));
    }

    /**
     * A factor change follows the caller's transaction on the storage
     * connection only.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFactorChangeFollowsTheCallersTransactionOnTheStorageConnection(): void
    {
        $identity = $this->seedIdentity();
        $session  = $this->sessions()->signIn('password', self::credentials(), self::requestContext())->session;

        self::assertNotNull($session);

        $this->requireAFurtherFactor();

        $storage = DB::connection(self::STORAGE);

        $storage->beginTransaction();

        self::assertTrue($this->sessions()->factorChanged($identity, FactorChangeMade::FACTOR_CONFIRMED, $session->record)->isPending());

        $storage->rollBack();

        self::assertSame('active', $this->records()->value('status'));

        DB::beginTransaction();

        self::assertTrue($this->sessions()->factorChanged($identity, FactorChangeMade::FACTOR_CONFIRMED, $session->record)->isPending());

        DB::rollBack();

        self::assertSame('pending', $this->records()->value('status'));
    }

    /**
     * An active session's proofs are read, and its row locked, on the storage
     * connection.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnActiveSessionsProofsAreReadAndLockedOnTheStorageConnection(): void
    {
        $this->seedIdentity();

        $session = $this->sessions()->signIn('password', self::credentials(), self::requestContext())->session;

        self::assertNotNull($session);

        $key        = $session->record->getKey();
        $statements = [];

        DB::listen(static function (QueryExecuted $query) use (&$statements): void {
            $statements[] = [$query->connectionName, stripos($query->sql, 'for update') !== false];
        });

        $storage = DB::connection(self::STORAGE);
        $read    = fn (): ?ProofKind => $this->sessions()->proofs($key)[0]->kind ?? null;
        $locks   = $storage->getDriverName() !== 'sqlite';

        DB::beginTransaction();

        self::assertSame(ProofKind::FIRST_FACTOR, $read());

        DB::rollBack();

        $storage->beginTransaction();

        self::assertSame(ProofKind::FIRST_FACTOR, $read());

        $storage->rollBack();

        self::assertSame([[self::STORAGE, false], [self::STORAGE, false], [self::STORAGE, $locks], [self::STORAGE, false]], $statements);
    }

    /**
     * A session loads an owner from the connection its model names, or else
     * from the session's own.
     *
     * @return void
     */
    public function testASessionLoadsAnOwnerThatNamesItsConnection(): void
    {
        $identity = $this->seedIdentity();

        $this->seedOwnedSession(NamedConnectionIdentity::class, $identity->getKey());

        $owner = Session::query()->sole()->authenticatable;

        self::assertInstanceOf(NamedConnectionIdentity::class, $owner);
        self::assertSame($identity->getKey(), $owner->getKey());
        self::assertInstanceOf(NamedConnectionIdentity::class, Session::query()->with('authenticatable')->sole()->authenticatable);

        $this->records()->delete();
        $this->seedOwnedSession(IntegrationIdentity::class, $identity->getKey());

        $this->expectException(QueryException::class);

        Session::query()->sole()->authenticatable()->getResults();
    }

    /**
     * Configure the guards and passkeys, and put the package's tables and the
     * counters on prefixed connections.
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

        $config  = $app->make(ConfigRepository::class);
        $testing = $config->array('database.connections.testing');

        self::configureSessionGuards($config);
        self::configurePasskeys($config);

        $config->set('database.connections.' . self::STORAGE, [...$testing, 'prefix' => 'store_']);
        $config->set('database.connections.' . self::COUNTERS, [...$testing, 'prefix' => 'counters_']);
        $config->set('authentication.storage.connection', self::STORAGE);
        $config->set('authentication.rate_limits.connection', self::COUNTERS);
    }

    /**
     * Require a further factor of every sign-in.
     *
     * @return void
     */
    private function requireAFurtherFactor(): void
    {
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
     * Persist a live session owned by the identity of the type and key.
     *
     * @param  class-string  $type
     * @param  mixed  $key
     * @return void
     */
    private function seedOwnedSession(string $type, mixed $key): void
    {
        (new Session)->forceFill([...self::liveSession(), 'authenticatable_type' => $type, 'authenticatable_id' => (string) $key])->save(); // @phpstan-ignore cast.string
    }

    /**
     * The identity's account sign-in counter, read on the counters' connection.
     *
     * @param  \Tests\Integration\Fixtures\IntegrationIdentity  $identity
     * @return int
     */
    private function accountHits(IntegrationIdentity $identity): int
    {
        $hits = DB::connection(self::COUNTERS)->table('rate_limits')->where('key', self::counterKey('sign_in', 'per_account', AccountAttempts::account($identity)))->value('hits');

        return is_numeric($hits) ? (int) $hits : 0;
    }

    /**
     * A query on the sessions table, on the storage connection.
     *
     * @return \Illuminate\Database\Query\Builder
     */
    private function records(): Builder
    {
        return DB::connection(self::STORAGE)->table('authentication_sessions');
    }
}
