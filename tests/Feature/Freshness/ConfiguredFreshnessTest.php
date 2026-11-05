<?php

declare(strict_types = 1);

namespace Tests\Feature\Freshness;

use Carbon\CarbonImmutable;
use Firebase\JWT\JWT;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Foundation\Application;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Contracts\ExternalEvidencePolicy;
use SineMacula\Laravel\Authentication\Contracts\FreshnessPolicy;
use SineMacula\Laravel\Authentication\Contracts\Session as Contract;
use SineMacula\Laravel\Authentication\External\ExternalEvidence;
use SineMacula\Laravel\Authentication\External\ExternalResult;
use SineMacula\Laravel\Authentication\Freshness\ConfiguredFreshness;
use SineMacula\Laravel\Authentication\Freshness\FreshnessRequirement;
use SineMacula\Laravel\Authentication\Freshness\FreshnessSettings;
use SineMacula\Laravel\Authentication\Freshness\Operations;
use SineMacula\Laravel\Authentication\Models\Session;
use SineMacula\Laravel\Authentication\Proofs\Channel;
use SineMacula\Laravel\Authentication\Proofs\Enums\ChannelKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\Purpose;
use SineMacula\Laravel\Authentication\Proofs\Evaluation;
use SineMacula\Laravel\Authentication\Proofs\NewProof;
use SineMacula\Laravel\Authentication\Proofs\ObservedProperties;
use SineMacula\Laravel\Authentication\Proofs\ProofWriter;
use SineMacula\Laravel\Authentication\Proofs\RecordedProof;
use SineMacula\Laravel\Authentication\Proofs\SessionProofs;
use SineMacula\Laravel\Authentication\Requirements\Enums\RequirementKind;
use Tests\Concerns\InteractsWithExternalSignIns;
use Tests\Concerns\InteractsWithProofs;
use Tests\Concerns\InteractsWithSessions;
use Tests\Concerns\MarksSharedLocks;
use Tests\Fixtures\External\ScriptedEvidencePolicy;
use Tests\Integration\Fixtures\MachineClient;
use Tests\TestCase;

/**
 * Feature tests of the package's freshness policy through the container: the
 * requirement each operation has on an application (configured, the caller's,
 * the stricter of both, or none), and whether a session holds a proof fresh
 * enough, judged on the newest that meets the requirement, on the session as
 * stored; asked plainly and, inside a transaction, current, on the session as
 * committed, which answer alike.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ConfiguredFreshness::class)]
#[CoversClass(FreshnessSettings::class)]
#[CoversClass(FreshnessRequirement::class)]
#[CoversClass(SessionProofs::class)]
final class ConfiguredFreshnessTest extends TestCase
{
    use InteractsWithExternalSignIns, InteractsWithProofs, InteractsWithSessions, MarksSharedLocks;

    /** @var string What a current judgement outside a transaction is refused with. */
    private const string OUTSIDE_A_TRANSACTION = 'A current freshness judgement is asked inside a transaction on the session model\'s connection.';

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
     * By default the container binds the configured policy, one instance shared
     * by every caller; an application's own binding replaces it (see
     * `ProviderBindingOrderTest` and `ReboundFreshnessPolicyTest`).
     *
     * @return void
     */
    public function testTheContainerBindsTheConfiguredPolicy(): void
    {
        self::assertInstanceOf(ConfiguredFreshness::class, app(FreshnessPolicy::class));
        self::assertSame(app(FreshnessPolicy::class), app(FreshnessPolicy::class));
    }

    /**
     * The requirement is the configured one, the caller's, or the stricter of
     * both; none for an operation with neither, for two with no kind in common,
     * or for a name that is not an operation's.
     *
     * @return void
     */
    public function testTheRequirementIsTheStricterOfTheConfiguredAndTheCallers(): void
    {
        $policy = self::policy();
        $caller = new FreshnessRequirement(300, [ProofKind::ADDITIONAL_FACTOR], true);

        $configured = $policy->requirement('api', Operations::IDENTIFIER_CHANGE);

        self::assertNotNull($configured);
        self::assertSame(900, $configured->maxAgeSeconds);
        self::assertSame(
            [ProofKind::FIRST_FACTOR, ProofKind::FIRST_FACTOR_REAUTHENTICATION, ProofKind::EXTERNAL_REAUTHENTICATION, ProofKind::ADDITIONAL_FACTOR, ProofKind::RECOVERY_CODE],
            $configured->proofs,
        );
        self::assertEquals(new FreshnessRequirement(300, [ProofKind::ADDITIONAL_FACTOR], true), $policy->requirement('api', Operations::FACTOR_CHANGE, $caller));
        self::assertSame($caller, $policy->requirement('api', 'mfa.add_factor', $caller));
        self::assertNull($policy->requirement('api', 'mfa.add_factor'));
        self::assertNull($policy->requirement('api', 'Mfa.Add', $caller));

        config()->set('authentication.freshness.factor_change.proofs', ['first_factor']);

        self::assertNull($policy->requirement('api', Operations::FACTOR_CHANGE, $caller));
    }

    /**
     * A session is fresh for a configured operation within its age and stale
     * after it; the fresh proof is the newest the requirement takes.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASessionIsFreshWithinTheAgeAndStaleAfter(): void
    {
        $record = $this->signedIn();

        $this->clockAt($this->now->addSeconds(899));

        self::assertSame(ProofKind::FIRST_FACTOR, self::freshProof($record, Operations::IDENTIFIER_CHANGE)?->kind);

        $this->clockAt($this->now->addSeconds(900));

        self::assertNull(self::freshProof($record, Operations::IDENTIFIER_CHANGE));
        self::assertNull(self::freshProof($record, Operations::PASSWORD_ESTABLISHMENT));
    }

    /**
     * A reauthentication, or a step-up, makes a long-lived session fresh again,
     * and is the fresh proof.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAReauthenticationMakesALongLivedSessionFresh(): void
    {
        $record = $this->signedIn();

        $this->clockAt($this->now->addDays(20));

        self::assertNull(self::freshProof($record, Operations::IDENTIFIER_CHANGE));

        self::recordProof($record, ProofKind::FIRST_FACTOR_REAUTHENTICATION, $this->now->addDays(20)->subMinute(), ['pwd']);

        self::assertSame(ProofKind::FIRST_FACTOR_REAUTHENTICATION, self::freshProof($record, Operations::IDENTIFIER_CHANGE)?->kind);
    }

    /**
     * The shipped `factor_change` requirement takes only further factors and
     * recovery codes, as changing a factor needs a fresh step-up: it ignores a
     * fresh first factor and a fresh reauthentication, and takes a step-up.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAStepUpOnlyRequirementIgnoresTheFirstFactor(): void
    {
        $record = $this->signedIn();

        self::assertNull(self::freshProof($record, Operations::FACTOR_CHANGE));

        self::recordProof($record, ProofKind::FIRST_FACTOR_REAUTHENTICATION, $this->now, ['pwd']);

        self::assertNull(self::freshProof($record, Operations::FACTOR_CHANGE));

        self::recordProof($record, ProofKind::RECOVERY_CODE, $this->now, ['otp'], new Evaluation(true, false));

        self::assertSame(ProofKind::RECOVERY_CODE, self::freshProof($record, Operations::FACTOR_CHANGE)?->kind);
    }

    /**
     * A caller's requirement makes the configured one stricter in its age, its
     * kinds and its flags, and stands alone for an operation of its own, such
     * as another package's.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACallersRequirementIsAppliedWithTheConfiguredOne(): void
    {
        $record = $this->signedIn();

        self::recordProof($record, ProofKind::ADDITIONAL_FACTOR, $this->now->subMinutes(5), ['otp'], new Evaluation(true, false));

        $policy = self::policy();

        self::assertNull($policy->freshProof($record, Operations::IDENTIFIER_CHANGE, new FreshnessRequirement(60, [ProofKind::ADDITIONAL_FACTOR])));
        self::assertNotNull($policy->freshProof($record, Operations::IDENTIFIER_CHANGE, new FreshnessRequirement(600, [ProofKind::ADDITIONAL_FACTOR])));
        self::assertNull($policy->freshProof($record, Operations::IDENTIFIER_CHANGE, new FreshnessRequirement(600, [ProofKind::ADDITIONAL_FACTOR], true)));
        self::assertNull($policy->freshProof($record, 'mfa.add_factor', new FreshnessRequirement(600, [ProofKind::ADDITIONAL_FACTOR], phishingResistant: true)));
        self::assertSame(['otp'], $policy->freshProof($record, 'mfa.add_factor', new FreshnessRequirement(600, [ProofKind::ADDITIONAL_FACTOR]))?->methods);
        self::assertNull($policy->freshProof($record, 'sso.reauthenticate', new FreshnessRequirement(600, [ProofKind::EXTERNAL_REAUTHENTICATION])));

        self::recordProof($record, ProofKind::EXTERNAL_REAUTHENTICATION, $this->now->subMinute(), [], null, new ObservedProperties);

        self::assertSame(
            ProofKind::EXTERNAL_REAUTHENTICATION,
            $policy->freshProof($record, 'sso.reauthenticate', new FreshnessRequirement(600, [ProofKind::EXTERNAL_REAUTHENTICATION]))?->kind,
        );
    }

    /**
     * Freshness takes no external provider's evidence: a provider's proof whose
     * evidence was accepted as multifactor, three days old, never meets a
     * requirement that asks for multifactor authentication, whether it is the
     * sign-in's or a reauthentication's, though it still meets one that does
     * not ask for it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAProvidersEvidenceNeverMakesTheSessionFreshForMultifactor(): void
    {
        app()->instance(ExternalEvidencePolicy::class, new ScriptedEvidencePolicy([RequirementKind::MULTIFACTOR]));

        $identity  = $this->seedIdentity();
        $evidence  = new ExternalEvidence(['mfa'], null, $this->now->subDays(3));
        $record    = $this->sessions()->signInExternally($this->linkedResult($identity, subject: 'subject-1', evidence: $evidence))->session?->record;
        $policy    = self::policy();
        $proofs    = [ProofKind::FIRST_FACTOR, ProofKind::EXTERNAL_REAUTHENTICATION];
        $mfa       = new FreshnessRequirement(300, $proofs, true);
        $plain     = new FreshnessRequirement(300, $proofs);
        $operation = 'sso.reauthenticate';

        self::assertInstanceOf(Session::class, $record);
        self::assertSame(1, DB::table('authentication_proofs')->where('multifactor', true)->whereNotNull('evidence')->count());
        self::assertNull($policy->freshProof($record, $operation, $mfa));
        self::assertSame(ProofKind::FIRST_FACTOR, $policy->freshProof($record, $operation, $plain)?->kind);

        $this->clockAt($this->now->addMinute());

        $result = new ExternalResult('connection-7', self::ISSUER, 'subject-1', authenticatedAt: $this->now->addMinute(), evidence: $evidence);

        self::assertTrue($this->sessions()->reauthenticateExternally($record->getKey(), $result)->isIssued());
        self::assertSame(2, DB::table('authentication_proofs')->where('multifactor', true)->whereNotNull('evidence')->count());
        self::assertNull($policy->freshProof($record, $operation, $mfa));
        self::assertSame(ProofKind::EXTERNAL_REAUTHENTICATION, $policy->freshProof($record, $operation, new FreshnessRequirement(300, $proofs))?->kind);
    }

    /**
     * An operation neither configured nor given a requirement is never fresh,
     * and nothing is read for it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnOperationWithNeitherIsNeverFreshAndReadsNothing(): void
    {
        $record  = $this->signedIn();
        $queries = 0;

        DB::listen(static function (QueryExecuted $query) use (&$queries): void {
            $queries++;
        });

        self::assertNull(self::freshProof($record, 'mfa.add_factor'));
        self::assertNull(self::freshProof($record, 'Not An Operation'));
        self::assertSame(0, $queries);
    }

    /**
     * A guard's own entry replaces the package's, and `null` there removes the
     * operation, so only a caller's requirement makes it fresh.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAGuardsOwnFreshnessApplies(): void
    {
        $record = $this->signedIn();

        $this->clockAt($this->now->addMinutes(20));

        config()->set('auth.guards.api.freshness', ['identifier_change' => ['max_age_seconds' => 1800, 'proofs' => ['first_factor']], 'factor_change' => null]);

        self::assertNotNull(self::freshProof($record, Operations::IDENTIFIER_CHANGE));
        self::assertNull(self::freshProof($record, Operations::FACTOR_CHANGE));
        self::assertNotNull(self::freshProof($record, Operations::FACTOR_CHANGE, new FreshnessRequirement(1800, [ProofKind::FIRST_FACTOR])));
    }

    /**
     * The session is judged as stored, never as the caller holds it: one
     * revoked or ended since the caller loaded it, moved to another guard, or
     * gone, is never fresh.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheSessionIsJudgedAsStored(): void
    {
        $record = $this->signedIn();

        self::assertNotNull(self::freshProof($record, Operations::IDENTIFIER_CHANGE));

        DB::table('authentication_sessions')->update(['revoked_at' => $this->now]);

        self::assertNull(self::freshProof($record, Operations::IDENTIFIER_CHANGE));

        DB::table('authentication_sessions')->update(['revoked_at' => null, 'idle_expires_at' => $this->now]);

        self::assertNull(self::freshProof($record, Operations::IDENTIFIER_CHANGE));

        DB::table('authentication_sessions')->update(['idle_expires_at' => $this->now->addDay(), 'guard' => 'admin']);

        self::assertNull(self::freshProof($record, Operations::IDENTIFIER_CHANGE));

        Session::query()->delete();

        self::assertNull(self::freshProof($record, Operations::IDENTIFIER_CHANGE));
        self::assertNull(self::freshProof(new Session, Operations::IDENTIFIER_CHANGE));
    }

    /**
     * The ways a session a model that reissues keys put under the caller's key
     * can record another owner: another identity's key, or another morph type
     * with the same key.
     *
     * @return iterable<string, array{array<string, string>}>
     */
    public static function otherOwners(): iterable
    {
        yield 'another identity' => [['authenticatable_id' => 'another-identity']];

        yield 'another type' => [['authenticatable_type' => MachineClient::class]];
    }

    /**
     * A session the caller still holds after its key was given to a live
     * session of another owner, on the same guard and with a fresh proof of its
     * own, is not fresh: the replacement's proof is found only for the
     * replacement.
     *
     * @param  array<string, string>  $owner
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('otherOwners')]
    public function testASessionWhoseKeyNowHoldsAnotherOwnersIsNotFresh(array $owner): void
    {
        $record = $this->signedIn();

        DB::table('authentication_sessions')->where('id', $record->getKey())->update($owner);

        $replacement = Session::query()->findOrFail($record->getKey());

        self::recordProof($replacement, ProofKind::FIRST_FACTOR, $this->now);

        self::assertNotNull(self::freshProof($replacement, Operations::IDENTIFIER_CHANGE));
        self::assertNull(self::freshProof($record, Operations::IDENTIFIER_CHANGE));
    }

    /**
     * Rows of `[how long after the retained session the replacement started]`:
     * later, or in the same second, which only the generation tells apart.
     *
     * @return iterable<string, array{int}>
     */
    public static function replacementStarts(): iterable
    {
        yield 'a minute later' => [60];

        yield 'in the same second' => [0];
    }

    /**
     * A session the caller still holds after it was deleted and its key given
     * to a later session of the same identity, on the same guard, is not fresh
     * for the replacement's further factor: the retained session never stepped
     * up, and only the replacement's own instance is answered with the proof.
     *
     * @param  int  $after
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('replacementStarts')]
    public function testARetainedSessionIsNotFreshForItsReplacementsProof(int $after): void
    {
        $retained = $this->signedIn();
        $row      = (array) DB::table('authentication_sessions')->where('id', $retained->getKey())->first();
        $started  = $this->now->addSeconds($after);

        $retained->delete();

        $this->clockAt($started);

        $replacement = new Session;
        $replacement->forceFill([...array_diff_key($row, array_flip(['generation', 'created_at', 'updated_at'])), 'signed_in_at' => $started])->save();

        self::recordProof($replacement, ProofKind::ADDITIONAL_FACTOR, $started, ['otp'], new Evaluation(true, true));

        self::assertSame(ProofKind::ADDITIONAL_FACTOR, self::freshProof($replacement, Operations::FACTOR_CHANGE)?->kind);
        self::assertNull(self::freshProof($retained, Operations::FACTOR_CHANGE));
    }

    /**
     * A session that is not an Eloquent session records no owner, so it is
     * never fresh, even under the key and guard of a live session that is.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASessionThatRecordsNoOwnerIsNeverFresh(): void
    {
        $record = $this->signedIn();

        self::assertNotNull(self::freshProof($record, Operations::IDENTIFIER_CHANGE));

        foreach ([Contract::class, EloquentSession::class] as $contract) {
            $session = \Mockery::mock($contract);
            $session->shouldReceive('getGuard')->andReturn('api');
            $session->shouldReceive('getSessionIdentifier')->andReturn($record->getKey());

            self::assertNull(self::freshProof($session, Operations::IDENTIFIER_CHANGE), $contract);
        }
    }

    /**
     * Asking reads the session and its freshest proof: two queries, however
     * many proofs the session holds.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAskingReadsTwice(): void
    {
        $record = $this->signedIn();

        foreach (range(1, 30) as $minutes) {
            self::recordProof($record, ProofKind::ADDITIONAL_FACTOR, $this->now->subMinutes($minutes), ['otp'], new Evaluation(true, true));
        }

        $queries = 0;

        DB::listen(static function (QueryExecuted $query) use (&$queries): void {
            $queries++;
        });

        self::assertNotNull(self::policy()->freshProof($record, Operations::IDENTIFIER_CHANGE));
        self::assertSame(2, $queries);
    }

    /**
     * Asked current inside a transaction, for a proof or until when, the policy
     * reads the session's row with a lock held until the transaction ends and
     * its proofs with a shared lock (on MySQL and MariaDB, the marked SQLite
     * included): still two queries. Asked plainly, it takes neither.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAskingCurrentLocksTheSessionAndReadsItsProofsCurrent(): void
    {
        $record = $this->signedIn();

        self::markSharedLocks();

        $policy = self::policy();

        $judge   = static fn (): ?RecordedProof => $policy->freshProof($record, Operations::IDENTIFIER_CHANGE, current: true);
        $current = self::statementsDuring(static fn (): mixed => DB::transaction($judge));
        $plain   = self::statementsDuring(static fn (): ?RecordedProof => $policy->freshProof($record, Operations::IDENTIFIER_CHANGE));
        $until   = self::statementsDuring(static fn (): ?CarbonImmutable => $policy->freshUntil($record, Operations::IDENTIFIER_CHANGE));
        $lasts   = static fn (): ?CarbonImmutable => $policy->freshUntil($record, Operations::IDENTIFIER_CHANGE, current: true);
        $lasting = self::statementsDuring(static fn (): mixed => DB::transaction($lasts));

        self::assertSame($current, $lasting);
        self::assertCount(2, $current);
        self::assertTrue(str_contains($current[0], 'authentication_sessions') && self::locksForUpdate($current[0]));
        self::assertSame([self::takesSharedLocks()], array_map(self::sharesLock(...), array_values(array_filter($current, self::readsProofs(...)))));
        self::assertCount(2, $plain);
        self::assertSame($plain, $until);
        self::assertSame([], array_filter($plain, static fn (string $sql): bool => self::locksForUpdate($sql) || self::sharesLock($sql)));
        self::assertSame(str_replace([' /* for update */', ' /* lock in share mode */', ' for update', ' lock in share mode'], '', $current), $plain);
    }

    /**
     * Asked current outside any transaction, for a proof or until when, the
     * policy refuses with a `LogicException` before it reads anything, the
     * requirement included, for an operation with a requirement or with none.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAskingCurrentOutsideATransactionThrowsAndReadsNothing(): void
    {
        $record = $this->signedIn();

        $asks = [];

        foreach ([Operations::IDENTIFIER_CHANGE, 'mfa.add_factor'] as $operation) {
            $asks["freshProof: {$operation}"] = static fn (): ?RecordedProof => self::policy()->freshProof($record, $operation, current: true);
            $asks["freshUntil: {$operation}"] = static fn (): ?CarbonImmutable => self::policy()->freshUntil($record, $operation, current: true);
        }

        foreach ($asks as $asked => $ask) {

            $statements = self::statementsDuring(static function () use ($ask): void {
                try {
                    $ask();

                    self::fail('A current judgement outside a transaction was answered.');
                } catch (\LogicException $exception) {
                    self::assertSame(self::OUTSIDE_A_TRANSACTION, $exception->getMessage());
                }
            });

            self::assertSame([], $statements, $asked);
        }
    }

    /**
     * A session that is not an Eloquent session (a plain one, one that only
     * names the boundary, or a model that does not implement it) is answered
     * with no proof without a query, asked plainly or current.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASessionThatIsNotAnEloquentSessionIsAnsweredWithoutAQuery(): void
    {
        $record = $this->signedIn();

        foreach ([Contract::class, EloquentSession::class, Model::class . ', ' . Contract::class] as $contract) {
            $session = \Mockery::mock($contract);
            $session->shouldReceive('getGuard')->andReturn('api');
            $session->shouldReceive('getSessionIdentifier')->andReturn($record->getKey());
            $session->shouldReceive('getConnection')->andReturn(DB::connection());

            $statements = self::statementsDuring(static function () use ($session): void {
                self::assertNull(self::policy()->freshProof($session, Operations::IDENTIFIER_CHANGE));
                self::assertNull(self::policy()->freshUntil($session, Operations::IDENTIFIER_CHANGE));
                self::assertNull(DB::transaction(static fn (): ?RecordedProof => self::policy()->freshProof($session, Operations::IDENTIFIER_CHANGE, current: true)));
                self::assertNull(DB::transaction(static fn (): ?CarbonImmutable => self::policy()->freshUntil($session, Operations::IDENTIFIER_CHANGE, current: true)));
            });

            self::assertSame([], $statements, $contract);
        }
    }

    /**
     * A session stays fresh until its newest qualifying proof is as old as the
     * effective requirement's maximum age: that second is the first that is no
     * longer fresh, and a stricter caller's age brings it forward. A session
     * with no fresh proof is fresh until no time at all.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASessionIsFreshUntilItsNewestProofIsTooOld(): void
    {
        $record = $this->signedIn();

        self::recordProof($record, ProofKind::FIRST_FACTOR_REAUTHENTICATION, $this->now->addMinutes(2), ['pwd']);

        $this->clockAt($this->now->addMinutes(3));

        $until = self::freshUntil($record, Operations::IDENTIFIER_CHANGE);

        self::assertSame($this->now->addMinutes(2)->addSeconds(900)->getTimestamp(), $until?->getTimestamp());
        $stricter = self::freshUntil($record, Operations::IDENTIFIER_CHANGE, FreshnessRequirement::within(120));

        self::assertSame($this->now->addMinutes(2)->addSeconds(120)->getTimestamp(), $stricter?->getTimestamp());
        self::assertNull(self::freshUntil($record, Operations::FACTOR_CHANGE));
        self::assertNull(self::freshUntil($record, 'mfa.add_factor'));

        $this->clockAt($until->subSecond());

        self::assertNotNull(self::freshProof($record, Operations::IDENTIFIER_CHANGE));

        $this->clockAt($until);

        self::assertNull(self::freshProof($record, Operations::IDENTIFIER_CHANGE));
        self::assertNull(self::freshUntil($record, Operations::IDENTIFIER_CHANGE));
    }

    /**
     * A factor excluded from the judgement never makes the session fresh:
     * another factor's step-up still does, and the deadline follows the proof
     * that counts.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnExcludedFactorNeverMakesTheSessionFresh(): void
    {
        $record = $this->signedIn();

        ProofWriter::record($record, 'api', self::stepUp('factor-a', $this->now->subMinutes(2)));
        ProofWriter::record($record, 'api', self::stepUp('factor-b', $this->now->subMinute()));

        $policy = self::policy();

        self::assertSame('factor-b', $policy->freshProof($record, Operations::FACTOR_CHANGE)?->factor);
        self::assertSame('factor-a', $policy->freshProof($record, Operations::FACTOR_CHANGE, null, 'factor-b')?->factor);
        self::assertSame($this->now->subMinutes(2)->addSeconds(900)->getTimestamp(), self::freshUntil($record, Operations::FACTOR_CHANGE, null, 'factor-b')?->getTimestamp());

        DB::table('authentication_proofs')->where('factor_reference', 'factor-a')->delete();

        self::assertNull($policy->freshProof($record, Operations::FACTOR_CHANGE, null, 'factor-b'));
        self::assertNull(self::freshUntil($record, Operations::FACTOR_CHANGE, null, 'factor-b'));
        self::assertNotNull($policy->freshProof($record, Operations::FACTOR_CHANGE, null, 'factor-c'));
    }

    /**
     * Asking until when a session stays fresh reads what asking for its fresh
     * proof reads: the session and its freshest proof.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAskingUntilWhenReadsTwice(): void
    {
        $record  = $this->signedIn();
        $queries = 0;

        DB::listen(static function (QueryExecuted $query) use (&$queries): void {
            $queries++;
        });

        self::assertNotNull(self::policy()->freshUntil($record, Operations::IDENTIFIER_CHANGE));
        self::assertSame(2, $queries);
    }

    /**
     * Configure the session guards.
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
     * The freshness policy the container binds.
     *
     * @return \SineMacula\Laravel\Authentication\Contracts\FreshnessPolicy
     */
    private static function policy(): FreshnessPolicy
    {
        return app(FreshnessPolicy::class);
    }

    /**
     * What the policy answers for the session, asked plainly and, inside a
     * transaction, current, which must answer alike.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @param  string  $operation
     * @param  ?\SineMacula\Laravel\Authentication\Freshness\FreshnessRequirement  $requirement
     * @param  ?string  $excludingFactor
     * @return ?\SineMacula\Laravel\Authentication\Proofs\RecordedProof
     *
     * @throws \Throwable
     */
    private static function freshProof(Contract $session, string $operation, ?FreshnessRequirement $requirement = null, ?string $excludingFactor = null): ?RecordedProof
    {
        $policy  = self::policy();
        $plain   = $policy->freshProof($session, $operation, $requirement, $excludingFactor);
        $current = DB::transaction(static fn (): ?RecordedProof => $policy->freshProof($session, $operation, $requirement, $excludingFactor, true));

        self::assertEquals($plain, $current);

        return $plain;
    }

    /**
     * Until when the policy answers the session stays fresh, asked plainly and,
     * inside a transaction, current, which must answer alike.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @param  string  $operation
     * @param  ?\SineMacula\Laravel\Authentication\Freshness\FreshnessRequirement  $requirement
     * @param  ?string  $excludingFactor
     * @return ?\Carbon\CarbonImmutable
     *
     * @throws \Throwable
     */
    private static function freshUntil(Contract $session, string $operation, ?FreshnessRequirement $requirement = null, ?string $excludingFactor = null): ?CarbonImmutable
    {
        $policy  = self::policy();
        $plain   = $policy->freshUntil($session, $operation, $requirement, $excludingFactor);
        $current = DB::transaction(static fn (): ?CarbonImmutable => $policy->freshUntil($session, $operation, $requirement, $excludingFactor, true));

        self::assertEquals($plain, $current);

        return $plain;
    }

    /**
     * The record of a session the identity signed in to with its password now.
     *
     * @return \SineMacula\Laravel\Authentication\Models\Session
     *
     * @throws \Throwable
     */
    private function signedIn(): Session
    {
        $this->seedIdentity();

        $record = $this->sessions()->signIn('password', self::credentials())->session?->record;

        self::assertInstanceOf(Session::class, $record);

        return $record;
    }

    /**
     * Move the clocks to the time given.
     *
     * @param  \Carbon\CarbonImmutable  $at
     * @return void
     */
    private function clockAt(CarbonImmutable $at): void
    {
        Carbon::setTestNow($at);
        CarbonImmutable::setTestNow($at);

        JWT::$timestamp = $at->getTimestamp();
    }

    /**
     * A step-up made with the factor at the time given, accepted.
     *
     * @param  string  $factor
     * @param  \Carbon\CarbonImmutable  $at
     * @return \SineMacula\Laravel\Authentication\Proofs\NewProof
     */
    private static function stepUp(string $factor, CarbonImmutable $at): NewProof
    {
        $channel = new Channel(ChannelKind::AUTHENTICATOR_APP);

        return new NewProof(ProofKind::ADDITIONAL_FACTOR, Purpose::STEP_UP, 'totp', $channel, $factor, new ObservedProperties, new Evaluation(true, true), ['otp'], $at);
    }
}
