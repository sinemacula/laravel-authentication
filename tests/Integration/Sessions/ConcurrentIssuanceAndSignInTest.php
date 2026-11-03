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
use SineMacula\Laravel\Authentication\Models\SessionProof;
use SineMacula\Laravel\Authentication\Proofs\Enums\Purpose;
use SineMacula\Laravel\Authentication\Proofs\Evaluation;
use SineMacula\Laravel\Authentication\Proofs\SessionProofs;
use SineMacula\Laravel\Authentication\Requirements\Requirement;
use SineMacula\Laravel\Authentication\Requirements\RequirementPart;
use SineMacula\Laravel\Authentication\Secrets\Secret;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use Tests\Concerns\InteractsWithExternalSignIns;
use Tests\Concerns\InteractsWithIsolationLevels;
use Tests\Concerns\InteractsWithProofs;
use Tests\Concerns\InteractsWithSessions;
use Tests\Fixtures\Tenancy\ProofJudgingRequirementCheck;
use Tests\Integration\Fixtures\IntegrationIdentity;
use Tests\TestCase;

/**
 * Races an issuance for the newest session against a sign-in of another
 * identity, on PostgreSQL and MySQL, each side in a process with a database
 * connection of its own: the first side issues an access token for the newest
 * session (a refresh, a step-up, or the activation that completes a pending
 * sign-in) inside a caller's transaction that it holds open, at READ COMMITTED
 * or REPEATABLE READ; the second, started meanwhile, signs another identity in
 * through an external provider, so the sides share no attempt-limit row.
 *
 * On MySQL the issuance reads the session's proofs with a shared lock, which at
 * REPEATABLE READ also locks the gap after that session's last proof. The
 * newest session's gap runs to the end of the proofs' session index, where a
 * new session's proof is inserted, so the sign-in waits until the caller's
 * transaction commits, and then commits itself: it waits, and never deadlocks.
 * At READ COMMITTED MySQL locks no gap, and PostgreSQL reads the proofs without
 * a lock at either level, so the sign-in never waits there.
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
final class ConcurrentIssuanceAndSignInTest extends TestCase
{
    use InteractsWithExternalSignIns, InteractsWithIsolationLevels, InteractsWithProofs, InteractsWithSessions;

    /** @var int How long the first side holds its transaction once the second is about to insert its proof, in microseconds. */
    private const int HOLD_MICROSECONDS = 1000000;

    /** @var float The time, in seconds, that separates a sign-in that waited for the first side from one that did not. */
    private const float WAIT_THRESHOLD_SECONDS = 0.5;

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
     * Rows of `[issuer, isolation level]`: the issuances that read the newest
     * session's proofs with a shared lock on MySQL, at READ COMMITTED and at
     * REPEATABLE READ.
     *
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function provideIssuersAndIsolationLevels(): iterable
    {
        foreach (['refresh', 'step-up', 'activation'] as $issuer) {
            foreach (self::provideIsolationLevels() as $name => [$level]) {
                yield "{$issuer} at {$name}" => [$issuer, $level];
            }
        }
    }

    /**
     * A sign-in of another identity, started while a caller's transaction holds
     * an issuance for the newest session, waits for that transaction on MySQL
     * at REPEATABLE READ and nowhere else, and then commits with its own
     * session, proof and provenance; the issuance commits too, so neither side
     * deadlocks.
     *
     * @param  string  $issuer
     * @param  string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideIssuersAndIsolationLevels')]
    public function testASignInWaitsAtMostForAnIssuanceOfTheNewestSession(string $issuer, string $level): void
    {
        $ada   = $this->seedIdentity();
        $grace = $this->seedIdentity('grace@example.test');
        $issue = $this->issuerFor($issuer, $ada);

        DB::disconnect();

        $pid = pcntl_fork();

        if ($pid < 0) {
            self::fail('The second side could not be forked.');
        }

        if ($pid === 0) {
            $this->runInChild(function () use ($grace): string {
                $inserting = "{$this->outcomes}/inserting";

                SessionProof::creating(static function () use ($inserting): void {
                    touch($inserting);
                });

                $session = $this->sessions()->signInExternally($this->linkedResult($grace, linkId: 'link-grace'))->session;

                self::assertNotNull($session);

                return (string) IdentifierCoercion::stringify($session->record->getKey());
            });
        }

        self::beginTransactionAt($level);

        self::assertNotNull($issue());

        touch("{$this->outcomes}/start");

        if (!self::wasSignalled("{$this->outcomes}/inserting")) {
            self::abandon($pid, 'The second side never reached the insert of its proof, so the two did not overlap.');
        }

        usleep(self::HOLD_MICROSECONDS);

        DB::commit();

        pcntl_waitpid($pid, $status);

        $reported = json_decode((string) file_get_contents("{$this->outcomes}/outcome"), true, flags: JSON_THROW_ON_ERROR);

        self::assertIsArray($reported);
        self::assertArrayNotHasKey('error', $reported);
        self::assertIsString($reported['result']);
        self::assertSame(DB::connection()->getDriverName() === 'mysql' && $level === 'repeatable read', $reported['waited'] >= self::WAIT_THRESHOLD_SECONDS);
        self::assertSame(['first_factor'], DB::table('authentication_proofs')->where('session_id', $reported['result'])->pluck('kind')->all());
        self::assertTrue(DB::table('authentication_provenance')->where('session_id', $reported['result'])->exists());
        self::assertSame(2, DB::table('authentication_sessions')->where('status', 'active')->whereNull('revoked_at')->count());
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
     * return the issuance named for that session, which hands back the access
     * token it issued: a refresh of it, a step-up of it with a hardware key, or
     * the activation that satisfies the further factor its sign-in was asked
     * for.
     *
     * @param  string  $issuer
     * @param  \Tests\Integration\Fixtures\IntegrationIdentity  $identity
     * @return \Closure(): ?\SineMacula\Laravel\Authentication\Secrets\Secret
     *
     * @throws \Throwable
     */
    private function issuerFor(string $issuer, IntegrationIdentity $identity): \Closure
    {
        $sessions = $this->sessions();

        if ($issuer === 'activation') {
            $this->askForAFurtherFactorOf($identity);

            $result = $sessions->signIn('password', self::credentials());

            self::assertNotNull($result->pending);
            self::assertNotNull($result->credential);

            $credential = $result->credential->reveal();
            $proof      = self::adapterProof($identity, 'api', $result->pending->id, Purpose::SIGN_IN);

            return static fn (): ?Secret => $sessions->satisfy($credential, $proof)->session?->tokens->accessToken;
        }

        $session = $sessions->signIn('password', self::credentials())->session;

        self::assertNotNull($session);

        if ($issuer === 'refresh') {
            $refresh = $session->tokens->refreshToken?->reveal() ?? '';

            return static fn (): ?Secret => $sessions->refresh($refresh)->session?->tokens->accessToken;
        }

        $proof = self::adapterProof($identity, 'api', $session->record->getKey(), methods: ['hwk'], evaluation: new Evaluation(true, true));

        return static fn (): ?Secret => $sessions->stepUp($proof)->accessToken;
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
     * In the forked process: wait to be started, run the second side on a
     * connection of its own, report its outcome and how long it took, and end
     * without running the parent's shutdown.
     *
     * @param  \Closure(): string  $second
     * @return never
     */
    private function runInChild(\Closure $second): never
    {
        $outcome = ['error' => 'The first side never signalled the start.'];

        try {
            if (self::wasSignalled("{$this->outcomes}/start")) {
                $started = microtime(true);
                $result  = $second();
                $outcome = ['result' => $result, 'waited' => microtime(true) - $started];
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
     * timeout: whether it did.
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
