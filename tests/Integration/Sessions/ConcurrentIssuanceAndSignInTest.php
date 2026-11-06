<?php

declare(strict_types = 1);

namespace Tests\Integration\Sessions;

use Carbon\CarbonImmutable;
use Firebase\JWT\JWT;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\AdditionalFactorPolicy;
use SineMacula\Laravel\Authentication\Contracts\RequirementCheck;
use SineMacula\Laravel\Authentication\Factors\AdditionalFactorContext;
use SineMacula\Laravel\Authentication\Factors\Enums\FactorChange;
use SineMacula\Laravel\Authentication\Factors\Enums\FactorChangeMade;
use SineMacula\Laravel\Authentication\Factors\FactorChangeVerdict;
use SineMacula\Laravel\Authentication\Http\PresentedRefreshToken;
use SineMacula\Laravel\Authentication\Models\SessionProof;
use SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\Purpose;
use SineMacula\Laravel\Authentication\Proofs\Evaluation;
use SineMacula\Laravel\Authentication\Proofs\SessionProofs;
use SineMacula\Laravel\Authentication\Requirements\Requirement;
use SineMacula\Laravel\Authentication\Requirements\RequirementPart;
use SineMacula\Laravel\Authentication\Secrets\Secret;
use SineMacula\Laravel\Authentication\Sessions\FactorChangeGate;
use SineMacula\Laravel\Authentication\Sessions\FactorChangeResult;
use SineMacula\Laravel\Authentication\Sessions\FactorRevocations;
use SineMacula\Laravel\Authentication\Sessions\SignedInSession;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use Tests\Concerns\InteractsWithExternalSignIns;
use Tests\Concerns\InteractsWithIsolationLevels;
use Tests\Concerns\InteractsWithProofs;
use Tests\Concerns\InteractsWithSessions;
use Tests\Fixtures\Tenancy\ProofJudgingRequirementCheck;
use Tests\Integration\Fixtures\IntegrationIdentity;
use Tests\TestCase;

/**
 * Races an issuance for a session, or a judgement of it made under its lock,
 * against a proof another identity's session records, on PostgreSQL and MySQL,
 * each side in a process with a database connection of its own: the first side
 * issues an access token for the session, judges it again after a change of its
 * identity's factors, or asks the factor-change gate about it, inside a
 * caller's transaction that it holds open, at READ COMMITTED or REPEATABLE
 * READ; the second, started meanwhile, records a proof of another identity, so
 * the sides share no attempt-limit row. Either the first side holds the newest
 * session (a refresh, a step-up, the activation that completes a pending
 * sign-in, a factor change or a gate verdict) and the second side signs a new
 * session in through an external provider, or the first side refreshes the
 * session, judges it after a factor change or holds a gate verdict on it and
 * the second side steps up the session next to it, on either side, in the
 * proofs' session index.
 *
 * On MySQL the issuance, every requirement judgement and every freshness
 * judgement made under the session's lock (the gate's, for a factor change's
 * operation, whose kinds the index holds on either side of the session's first
 * factor) reads the session's proofs with a shared lock, which at REPEATABLE
 * READ also locks the gaps on either side of that session's proofs in the index
 * (`session_id`, `kind`, `authenticated_at`), keys being time-ordered: after
 * the newest session's proofs, where a new session's proof is inserted; before
 * the next session's `first_factor` entry, where its further factor falls; and
 * after the previous session's last entry, where its recovery code falls. So
 * the second side waits until the caller's transaction commits, and then
 * commits itself: it waits, and never deadlocks. At READ COMMITTED MySQL locks
 * no gap, and PostgreSQL reads the proofs without a lock at either level, so
 * the second side never waits there.
 *
 * Skipped on SQLite, whose in-memory database each process would have to
 * itself, and where `pcntl` is not available.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SessionProofs::class)]
#[CoversClass(FactorRevocations::class)]
#[CoversClass(FactorChangeGate::class)]
final class ConcurrentIssuanceAndSignInTest extends TestCase
{
    use InteractsWithExternalSignIns, InteractsWithIsolationLevels, InteractsWithProofs, InteractsWithSessions;

    /** @var int How long the first side holds its transaction open for the second to finish once it is about to insert its proof, in seconds. */
    private const int HOLD_SECONDS = 1;

    /** @var int How long either side waits for the other's signal before giving up, in seconds. */
    private const int SIGNAL_TIMEOUT_SECONDS = 10;

    /** @var string Directory the second side reports its outcome in. */
    private string $outcomes;

    /**
     * Skip where processes cannot share the database, freeze the clocks so both
     * processes see one moment, create the tables, and ask the first side's
     * identity alone for a further factor at sign-in.
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

        $this->freezeAt(CarbonImmutable::createStrict(2026, 4, 6, 12, 0, 0));

        $this->createSessionTables();

        $this->outcomes = sys_get_temp_dir() . '/issuance-sign-in-race-' . bin2hex(random_bytes(8));

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
     * Rows of `[holder, isolation level]`: the issuances, the judgement after a
     * factor change and the gate's verdict, that read the newest session's
     * proofs with a shared lock on MySQL, at READ COMMITTED and at REPEATABLE
     * READ.
     *
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function provideHoldersAndIsolationLevels(): iterable
    {
        foreach (['refresh', 'step-up', 'activation', 'factor change', 'gate'] as $holder) {
            foreach (self::provideIsolationLevels() as $name => [$level]) {
                yield "{$holder} at {$name}" => [$holder, $level];
            }
        }
    }

    /**
     * A sign-in of another identity, started while a caller's transaction holds
     * an issuance for the newest session, a judgement of it after a factor
     * change or a gate verdict on it, waits for that transaction on MySQL at
     * REPEATABLE READ and nowhere else, and then commits with its own session,
     * proof and provenance; the first side commits too, so neither side
     * deadlocks.
     *
     * @param  string  $holder
     * @param  string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideHoldersAndIsolationLevels')]
    public function testASignInWaitsAtMostForACurrentReadOfTheNewestSession(string $holder, string $level): void
    {
        $ada   = $this->seedIdentity();
        $grace = $this->seedIdentity('grace@example.test');

        $reported = $this->race($this->holderFor($holder, $ada), $level, function () use ($grace): string {
            $session = $this->sessions()->signInExternally($this->linkedResult($grace, linkId: 'link-grace'), self::requestContext())->session;

            self::assertNotNull($session);

            return (string) IdentifierCoercion::stringify($session->record->getKey());
        });

        self::assertSame(self::waitsAt($level), $reported['blocked']);
        self::assertSame(['first_factor'], DB::table('authentication_proofs')->where('session_id', $reported['result'])->pluck('kind')->all());
        self::assertTrue(DB::table('authentication_provenance')->where('session_id', $reported['result'])->exists());
        self::assertSame(2, DB::table('authentication_sessions')->where('status', 'active')->whereNull('revoked_at')->count());
    }

    /**
     * Rows of `[holder, neighbour, isolation level]`: a refresh of a session, a
     * judgement of it after a factor change or a gate verdict on it, and the
     * session signed in just after it, stepped up with a further factor, whose
     * proof sorts before its own `first_factor` entry, or the one signed in
     * just before it, stepped up with a recovery code, whose proof sorts after
     * its own `first_factor` entry, each at READ COMMITTED and at REPEATABLE
     * READ.
     *
     * @return iterable<string, array{0: string, 1: string, 2: string}>
     */
    public static function provideNeighboursAndIsolationLevels(): iterable
    {
        foreach (['refresh', 'factor change', 'gate'] as $holder) {
            foreach (['next', 'previous'] as $neighbour) {
                foreach (self::provideIsolationLevels() as $name => [$level]) {
                    yield "the {$neighbour} session of a {$holder} at {$name}" => [$holder, $neighbour, $level];
                }
            }
        }
    }

    /**
     * A step-up of another identity's session whose proofs border those of the
     * session a caller's transaction holds a refresh of, a judgement of after a
     * factor change or a gate verdict on, on either side, waits for that
     * transaction on MySQL at REPEATABLE READ and nowhere else, and then
     * commits with its proof recorded; the first side commits too, so neither
     * side deadlocks.
     *
     * @param  string  $holder
     * @param  string  $neighbour
     * @param  string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideNeighboursAndIsolationLevels')]
    public function testAStepUpOfANeighbouringSessionWaitsAtMostForACurrentRead(string $holder, string $neighbour, string $level): void
    {
        $ada   = $this->seedIdentity();
        $grace = $this->seedIdentity('grace@example.test');

        $previous = $neighbour === 'previous' ? $this->signedIn($grace) : null;
        $session  = $this->signedIn($ada);
        $next     = $neighbour === 'next' ? $this->signedIn($grace) : null;
        $other    = $previous ?? $next;

        self::assertNotNull($other);

        $key   = (string) IdentifierCoercion::stringify($session->record->getKey());
        $their = (string) IdentifierCoercion::stringify($other->record->getKey());
        $kind  = $next === null ? ProofKind::RECOVERY_CODE : ProofKind::ADDITIONAL_FACTOR;

        self::assertSame($next === null ? 1 : -1, strcmp($key, $their) <=> 0);

        $proof = self::adapterProof($grace, 'api', $other->record->getKey(), kind: $kind);
        $first = $this->neighbourHolderFor($holder, $ada, $session);

        $reported = $this->race($first, $level, function () use ($proof, $their): string {
            self::assertNotNull($this->sessions()->stepUp($proof, self::requestClient())->accessToken);

            return $their;
        });

        self::assertSame(self::waitsAt($level), $reported['blocked']);
        self::assertContains($kind->value, DB::table('authentication_proofs')->where('session_id', $their)->pluck('kind')->all());
    }

    /**
     * Register the guards.
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
     * Sign the identity in with its password, so its session is the newest, and
     * return what the first side does to that session, which hands back the
     * access token it issued, or the judgement's result: a refresh of it, a
     * step-up of it with a hardware key, the activation that satisfies the
     * further factor its sign-in was asked for, a judgement after a factor
     * change, or the gate's verdict on adding a factor.
     *
     * @param  string  $holder
     * @param  \Tests\Integration\Fixtures\IntegrationIdentity  $identity
     * @return \Closure(): mixed
     *
     * @throws \Throwable
     */
    private function holderFor(string $holder, IntegrationIdentity $identity): \Closure
    {
        $sessions = $this->sessions();

        if ($holder === 'activation') {
            $this->askForAFurtherFactorOf($identity);

            $result = $sessions->signIn('password', self::credentials(), self::requestContext());

            self::assertNotNull($result->pending);
            self::assertNotNull($result->credential);

            $credential = $result->credential->reveal();
            $proof      = self::adapterProof($identity, 'api', $result->pending->id, Purpose::SIGN_IN);

            return static fn (): ?Secret => $sessions->satisfy($credential, $proof, self::requestClient())->session?->tokens->accessToken;
        }

        $session = $sessions->signIn('password', self::credentials(), self::requestContext())->session;

        self::assertNotNull($session);

        if ($holder === 'refresh') {
            $refresh = $session->tokens->refreshToken?->reveal() ?? '';

            return static fn (): ?Secret => $sessions->refresh(PresentedRefreshToken::fromBody($refresh), self::requestClient())->session?->tokens->accessToken;
        }

        if ($holder === 'factor change') {
            return $this->factorChangeOf($identity, $session);
        }

        if ($holder === 'gate') {
            return $this->gateOf($identity, $session);
        }

        $proof = self::adapterProof($identity, 'api', $session->record->getKey(), methods: ['hwk'], evaluation: new Evaluation(true, true));

        return static fn (): ?Secret => $sessions->stepUp($proof, self::requestClient())->accessToken;
    }

    /**
     * Step the identity's session up with a further factor, then ask the
     * identity, and no other, for one, and return the judgement of the session
     * after a factor change, which reads its first factor and its further
     * factors and keeps it active.
     *
     * @param  \Tests\Integration\Fixtures\IntegrationIdentity  $identity
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignedInSession  $session
     * @return \Closure(): \SineMacula\Laravel\Authentication\Sessions\FactorChangeResult
     *
     * @throws \Throwable
     */
    private function factorChangeOf(IntegrationIdentity $identity, SignedInSession $session): \Closure
    {
        $sessions = $this->sessions();

        self::assertTrue($sessions->stepUp(self::adapterProof($identity, 'api', $session->record->getKey()), self::requestClient())->isIssued());

        $this->askForAFurtherFactorOf($identity);

        return static function () use ($sessions, $identity, $session): FactorChangeResult {
            $result = $sessions->factorChanged($identity, FactorChangeMade::FACTOR_CONFIRMED, $session->record);

            self::assertTrue($result->isActive());

            return $result;
        };
    }

    /**
     * What the first side does to the identity's session whose neighbour steps
     * up: a refresh of it, a judgement of it after a factor change, or the
     * gate's verdict on adding a factor from it.
     *
     * @param  string  $holder
     * @param  \Tests\Integration\Fixtures\IntegrationIdentity  $identity
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignedInSession  $session
     * @return \Closure(): mixed
     *
     * @throws \Throwable
     */
    private function neighbourHolderFor(string $holder, IntegrationIdentity $identity, SignedInSession $session): \Closure
    {
        $sessions = $this->sessions();
        $refresh  = $session->tokens->refreshToken?->reveal() ?? '';

        return match ($holder) {
            'refresh' => static fn (): ?Secret => $sessions->refresh(PresentedRefreshToken::fromBody($refresh), self::requestClient())->session?->tokens->accessToken,
            'gate'    => $this->gateOf($identity, $session),
            default   => $this->factorChangeOf($identity, $session),
        };
    }

    /**
     * Step the identity's session up with a further factor, and return the
     * factor-change gate's verdict on adding a factor from it, which reads its
     * proofs current under its lock and allows the change.
     *
     * @param  \Tests\Integration\Fixtures\IntegrationIdentity  $identity
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignedInSession  $session
     * @return \Closure(): \SineMacula\Laravel\Authentication\Factors\FactorChangeVerdict
     *
     * @throws \Throwable
     */
    private function gateOf(IntegrationIdentity $identity, SignedInSession $session): \Closure
    {
        $sessions = $this->sessions();

        self::assertTrue($sessions->stepUp(self::adapterProof($identity, 'api', $session->record->getKey()), self::requestClient())->isIssued());

        return static function () use ($sessions, $session): FactorChangeVerdict {
            $verdict = $sessions->factorChange($session->record, FactorChange::ADD);

            self::assertTrue($verdict->isAllowed());

            return $verdict;
        };
    }

    /**
     * Ask a further factor of the identity, and of no other, when it signs in,
     * judged on the session's proofs.
     *
     * @param  \Tests\Integration\Fixtures\IntegrationIdentity  $identity
     * @return void
     */
    private function askForAFurtherFactorOf(IntegrationIdentity $identity): void
    {
        app()->instance(AdditionalFactorPolicy::class, new readonly class ($identity->getKey()) implements AdditionalFactorPolicy {
            /**
             * Constructor.
             *
             * @param  mixed  $identityId
             */
            public function __construct(

                /** The key of the identity asked for a further factor. */
                private mixed $identityId,
            ) {}

            /**
             * A further factor of the identity, nothing of any other.
             *
             * @param  \SineMacula\Laravel\Authentication\Factors\AdditionalFactorContext  $context
             * @return \SineMacula\Laravel\Authentication\Requirements\Requirement
             */
            #[\Override]
            public function requirementFor(AdditionalFactorContext $context): Requirement
            {
                return $context->identity->getAuthIdentifier() === $this->identityId ? new Requirement(new RequirementPart) : new Requirement;
            }
        });
        app()->instance(RequirementCheck::class, new ProofJudgingRequirementCheck);
    }

    /**
     * Sign the identity in with its password, as a new session.
     *
     * @param  \Tests\Integration\Fixtures\IntegrationIdentity  $identity
     * @return \SineMacula\Laravel\Authentication\Sessions\SignedInSession
     *
     * @throws \Throwable
     */
    private function signedIn(IntegrationIdentity $identity): SignedInSession
    {
        $session = $this->sessions()->signIn('password', self::credentials($identity->email), self::requestContext())->session;

        self::assertNotNull($session);

        return $session;
    }

    /**
     * Issue, or judge, here inside a caller's transaction at the isolation
     * level, start the second side in another process once it has, hold the
     * transaction open until the second side is about to insert its proof and
     * then until it finishes, for no longer than the hold, then commit, and
     * return what the second side returned and whether it was blocked: still
     * unfinished when the transaction committed.
     *
     * @param  \Closure(): mixed  $issue
     * @param  string  $level
     * @param  \Closure(): string  $second
     * @return array{result: string, blocked: bool}
     *
     * @throws \Throwable
     */
    private function race(\Closure $issue, string $level, \Closure $second): array
    {
        DB::disconnect();

        $pid = pcntl_fork();

        if ($pid < 0) {
            self::fail('The second side could not be forked.');
        }

        if ($pid === 0) {
            $this->runInChild(function () use ($second): string {
                $inserting = "{$this->outcomes}/inserting";

                SessionProof::creating(static function () use ($inserting): void {
                    touch($inserting);
                });

                $result = $second();

                touch("{$this->outcomes}/finished");

                return $result;
            });
        }

        self::beginTransactionAt($level);

        self::assertNotNull($issue());

        touch("{$this->outcomes}/start");

        if (!self::wasSignalled("{$this->outcomes}/inserting")) {
            self::abandon($pid, 'The second side never reached the insert of its proof, so the two did not overlap.');
        }

        $finished = self::wasSignalled("{$this->outcomes}/finished", self::HOLD_SECONDS);

        DB::commit();

        pcntl_waitpid($pid, $status);

        $reported = json_decode((string) file_get_contents("{$this->outcomes}/outcome"), true, flags: JSON_THROW_ON_ERROR);

        self::assertIsArray($reported);
        self::assertArrayNotHasKey('error', $reported);
        self::assertIsString($reported['result']);

        return ['result' => $reported['result'], 'blocked' => !$finished];
    }

    /**
     * Whether the second side waits for the first at the isolation level: on
     * MySQL at REPEATABLE READ alone, where the shared lock of the first side's
     * current read locks the gaps around its session's proofs.
     *
     * @param  string  $level
     * @return bool
     */
    private static function waitsAt(string $level): bool
    {
        return DB::connection()->getDriverName() === 'mysql' && $level === 'repeatable read';
    }

    /**
     * In the forked process: wait to be started, run the second side on a
     * connection of its own, report its outcome, and end without running the
     * parent's shutdown.
     *
     * @param  \Closure(): string  $second
     * @return never
     */
    private function runInChild(\Closure $second): never
    {
        $outcome = ['error' => 'The first side never signalled the start.'];

        try {
            if (self::wasSignalled("{$this->outcomes}/start")) {
                $outcome = ['result' => $second()];
            }
        } catch (\Throwable $e) {
            $outcome = ['error' => $e::class . ': ' . $e->getMessage()];
        }

        file_put_contents("{$this->outcomes}/outcome", json_encode($outcome));

        posix_kill(posix_getpid(), SIGKILL);

        exit(1);
    }

    /**
     * Wait for the other side to create the signal file, for no longer than the
     * timeout in seconds: whether it did.
     *
     * @param  string  $signal
     * @param  int  $timeout
     * @return bool
     */
    private static function wasSignalled(string $signal, int $timeout = self::SIGNAL_TIMEOUT_SECONDS): bool
    {
        $deadline = microtime(true) + $timeout;

        while (!is_file($signal) && microtime(true) < $deadline) {
            usleep(5000);
        }

        return is_file($signal);
    }

    /**
     * Fail the race that was never set up: roll the first side's transaction
     * back and stop and reap the second side, so neither is left holding locks
     * on the tables the teardown drops.
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
