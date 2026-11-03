<?php

declare(strict_types = 1);

namespace Tests\Feature\Sessions;

use Carbon\CarbonImmutable;
use Firebase\JWT\JWT;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Foundation\Application;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Jwt\Enums\TokenType;
use SineMacula\Laravel\Authentication\Proofs\Enums\Purpose;
use SineMacula\Laravel\Authentication\Sessions\ProofIssuance;
use SineMacula\Laravel\Authentication\Sessions\SignedInSession;
use Tests\Concerns\InspectsIssuanceGuards;
use Tests\Concerns\InteractsWithProofs;
use Tests\Concerns\InteractsWithSessions;
use Tests\TestCase;

/**
 * Feature tests of the shared step of a step-up and a reauthentication: the
 * session's row is locked, then, once the proof is taken, the session's
 * issuance guard is written before the proof, in the same transaction, so an
 * issuance of the session that overlaps it waits for it and reads its proof;
 * a proof that is refused writes nothing, and a caller's rollback takes the
 * guard back with the proof.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ProofIssuance::class)]
final class ProofIssuanceTest extends TestCase
{
    use InspectsIssuanceGuards, InteractsWithProofs, InteractsWithSessions;

    /** @var \Carbon\CarbonImmutable Frozen clock reference. */
    private CarbonImmutable $now;

    /**
     * Freeze the clocks and create the tables.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->now = CarbonImmutable::createStrict(2026, 4, 6, 12, 0, 0);

        $this->clockAt($this->now);
        $this->createSessionTables();
    }

    /**
     * Release the clocks and drop the tables.
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
     * A step-up writes the issuance guard once the proof is taken and before it
     * is recorded, in the transaction that locked the row, and the token it
     * issues reads the proofs after both: its `auth_time` and `amr` are the new
     * proof's.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheGuardIsWrittenBeforeTheProofInTheLockingTransaction(): void
    {
        $session    = $this->signedIn();
        $statements = [];

        $this->clockAt($this->now->addMinute());

        DB::listen(static function (QueryExecuted $query) use (&$statements): void {
            $statements[] = [strtolower(strtok($query->sql, ' ') ?: ''), $query->sql, $query->connection->transactionLevel()];
        });

        $result = $this->sessions()->stepUp(self::adapterProof($session->identity, 'api', $session->record->getKey()));

        self::assertTrue($result->isIssued());

        $writes = array_values(array_filter($statements, static fn (array $statement): bool => $statement[0] !== 'select'));

        self::assertCount(2, $writes);
        self::assertStringContainsString('issuance_sequence', $writes[0][1]);
        self::assertStringStartsWith('insert', $writes[1][1]);
        self::assertStringContainsString('authentication_proofs', $writes[1][1]);
        self::assertStringContainsString('group by', end($statements)[1]);
        self::assertSame([1], array_values(array_unique(array_column($statements, 2))));
        self::assertSame(1, self::issuanceGuardWrites($session->record->getKey()));

        $claims = Auth::manager()->jwt('api')->parse($result->accessToken?->reveal() ?? '', TokenType::ACCESS);

        self::assertIsArray($claims);
        self::assertSame($this->now->addMinute()->getTimestamp(), $claims['auth_time']);
        self::assertSame(['pwd', 'otp', 'mfa'], $claims['amr']);
    }

    /**
     * A proof the session does not take (another purpose than a step-up's) is
     * refused before the guard: nothing at all is written.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARefusedProofWritesNoGuard(): void
    {
        $session = $this->signedIn();
        $writes  = 0;

        DB::listen(static function (QueryExecuted $query) use (&$writes): void {
            $writes += (int) preg_match('/^\s*(insert|update|delete)\b/i', $query->sql);
        });

        $result = $this->sessions()->stepUp(self::adapterProof($session->identity, 'api', $session->record->getKey(), Purpose::REAUTHENTICATE));

        self::assertFalse($result->isIssued());
        self::assertSame(FailureReason::PROOF_INVALID, $result->reason);
        self::assertSame(0, $writes);
        self::assertSame(0, self::issuanceGuardWrites($session->record->getKey()));
    }

    /**
     * Inside a caller's transaction the guard and the proof are written into
     * it, and a rollback of the caller's transaction takes both back.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACallersRollbackTakesTheGuardBackWithTheProof(): void
    {
        $session = $this->signedIn();

        DB::beginTransaction();

        self::assertTrue($this->sessions()->stepUp(self::adapterProof($session->identity, 'api', $session->record->getKey()))->isIssued());
        self::assertSame(1, self::issuanceGuardWrites($session->record->getKey()));

        DB::rollBack();

        self::assertSame(0, self::issuanceGuardWrites($session->record->getKey()));
        self::assertSame(1, DB::table('authentication_proofs')->count());
    }

    /**
     * Register the guards.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        assert($app instanceof Application);

        self::configureSessionGuards($app->make(ConfigRepository::class));
    }

    /**
     * A session the identity signed in to with its password now.
     *
     * @return \SineMacula\Laravel\Authentication\Sessions\SignedInSession
     *
     * @throws \Throwable
     */
    private function signedIn(): SignedInSession
    {
        $this->seedIdentity();

        $session = $this->sessions()->signIn('password', self::credentials())->session;

        self::assertNotNull($session);

        return $session;
    }

    /**
     * Freeze every clock at the time.
     *
     * @param  \Carbon\CarbonImmutable  $time
     * @return void
     */
    private function clockAt(CarbonImmutable $time): void
    {
        Carbon::setTestNow($time);
        CarbonImmutable::setTestNow($time);

        JWT::$timestamp = $time->getTimestamp();
    }
}
