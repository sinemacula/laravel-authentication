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
 * Races an issuance or locked judgement of a session against another identity's
 * proof, each in its own process.
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
     * Skip where processes cannot share the database, freeze the clocks, create
     * the tables and ask the first identity for a further factor.
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
     * Rows of `[holder, isolation level]`.
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
     * A sign-in waits at most for a current read of the newest session.
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
     * Rows of `[holder, neighbour, isolation level]`.
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
     * A step-up of a neighbouring session waits at most for a current read.
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
     * Sign the identity in and return what the first side does to its session.
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
     * Step the session up, ask the identity for a further factor and return the
     * judgement after a factor change.
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
     * What the first side does to the session whose neighbour steps up.
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
     * Step the session up and return the factor-change gate's verdict on adding
     * a factor.
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
     * Ask a further factor of the identity alone when it signs in.
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
     * Issue or judge inside a caller's transaction, race the second side and
     * return its result and whether it was blocked.
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
     * Whether the second side waits for the first at the isolation level.
     *
     * @param  string  $level
     * @return bool
     */
    private static function waitsAt(string $level): bool
    {
        return DB::connection()->getDriverName() === 'mysql' && $level === 'repeatable read';
    }

    /**
     * Run the second side in the forked process, report its outcome and exit
     * without the parent's shutdown.
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
     * Wait, up to the timeout in seconds, for the other side to create the
     * signal file.
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
