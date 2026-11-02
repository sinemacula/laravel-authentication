<?php

declare(strict_types = 1);

namespace Tests\Feature\Proofs;

use Carbon\CarbonImmutable;
use Firebase\JWT\JWT;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Foundation\Application;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Freshness\FreshnessRequirement;
use SineMacula\Laravel\Authentication\Models\Session;
use SineMacula\Laravel\Authentication\Models\SessionProof;
use SineMacula\Laravel\Authentication\Proofs\AuthenticationClaims;
use SineMacula\Laravel\Authentication\Proofs\AuthenticationMethods;
use SineMacula\Laravel\Authentication\Proofs\AuthenticationSummary;
use SineMacula\Laravel\Authentication\Proofs\Channel;
use SineMacula\Laravel\Authentication\Proofs\Enums\ChannelKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\KeyProtection;
use SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\Purpose;
use SineMacula\Laravel\Authentication\Proofs\Evaluation;
use SineMacula\Laravel\Authentication\Proofs\NewProof;
use SineMacula\Laravel\Authentication\Proofs\ObservedProperties;
use SineMacula\Laravel\Authentication\Proofs\ProofHistory;
use SineMacula\Laravel\Authentication\Proofs\ProofWriter;
use SineMacula\Laravel\Authentication\Proofs\Provenance;
use SineMacula\Laravel\Authentication\Proofs\RecordedProof;
use SineMacula\Laravel\Authentication\Proofs\SessionProofs;
use SineMacula\Laravel\Authentication\Sessions\SignedInSession;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use Tests\Concerns\InteractsWithProofs;
use Tests\Concerns\InteractsWithSessions;
use Tests\TestCase;
use Tests\Unit\Stubs\PlainSessionFixture;

/**
 * Feature tests of the reads of a session's proofs against the database: the
 * `auth_time` and `amr` derived from them, never stored, and the newest proof a
 * freshness requirement takes; only counting proofs are read (not voided, and a
 * further factor or recovery code only when accepted), on the write connection,
 * in a bounded number of rows whatever the session's history.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SessionProofs::class)]
#[CoversClass(ProofHistory::class)]
#[CoversClass(AuthenticationClaims::class)]
#[CoversClass(AuthenticationSummary::class)]
#[CoversClass(AuthenticationMethods::class)]
#[CoversClass(RecordedProof::class)]
final class SessionProofsTest extends TestCase
{
    use InteractsWithProofs, InteractsWithSessions;

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

        Carbon::setTestNow($this->now);
        CarbonImmutable::setTestNow($this->now);

        JWT::$timestamp = $this->now->getTimestamp();

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
     * A signed-in session's claims are its first factor's time and values.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASessionsClaimsAreItsFirstFactors(): void
    {
        $summary = AuthenticationClaims::forSession($this->signedIn()->record);

        self::assertSame([$this->now->getTimestamp(), ['pwd']], [$summary->authenticatedAt->getTimestamp(), $summary->methods]);
    }

    /**
     * A step-up moves the authentication time and adds its values, and `mfa`
     * when its evaluation reported multifactor authentication; a
     * reauthentication moves the time and adds nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testLaterProofsMoveTheTimeAndAddWhatTheyMay(): void
    {
        $record = $this->signedIn()->record;

        self::recordProof($record, ProofKind::ADDITIONAL_FACTOR, $this->now->addMinutes(5), ['otp'], new Evaluation(true, false));

        $stepped = AuthenticationClaims::forSession($record);

        self::assertSame([$this->now->addMinutes(5)->getTimestamp(), ['pwd', 'otp']], [$stepped->authenticatedAt->getTimestamp(), $stepped->methods]);

        self::recordProof($record, ProofKind::RECOVERY_CODE, $this->now->addMinutes(6), ['kba'], new Evaluation(true, true));
        self::recordProof($record, ProofKind::FIRST_FACTOR_REAUTHENTICATION, $this->now->addMinutes(9), ['pop']);
        self::recordProof($record, ProofKind::EXTERNAL_REAUTHENTICATION, $this->now->addMinutes(8), ['urn:provider:hwk']);

        $summary = AuthenticationClaims::forSession($record);

        self::assertSame([$this->now->addMinutes(9)->getTimestamp(), ['pwd', 'otp', 'kba', 'mfa']], [$summary->authenticatedAt->getTimestamp(), $summary->methods]);
    }

    /**
     * A reauthentication with the same values as the first factor moves the
     * time and adds nothing, and the first factor's values still count: proofs
     * of different kinds are told apart, whatever values they share.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAReauthenticationWithTheFirstFactorsValuesMovesOnlyTheTime(): void
    {
        $record = $this->signedIn()->record;

        self::recordProof($record, ProofKind::FIRST_FACTOR_REAUTHENTICATION, $this->now->addMinutes(9), ['pwd']);

        $summary = AuthenticationClaims::forSession($record);

        self::assertSame([$this->now->addMinutes(9)->getTimestamp(), ['pwd']], [$summary->authenticatedAt->getTimestamp(), $summary->methods]);
    }

    /**
     * Only counting proofs count: a voided one never, and a further factor or a
     * recovery code only when its adapter accepted it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testOnlyCountingProofsCount(): void
    {
        $record = $this->signedIn()->record;

        self::recordProof($record, ProofKind::ADDITIONAL_FACTOR, $this->now->addMinutes(5), ['otp'], new Evaluation(false, true));
        self::recordProof($record, ProofKind::RECOVERY_CODE, $this->now->addMinutes(6), ['kba'], new Evaluation(true, true));

        DB::table('authentication_proofs')->where('kind', 'recovery_code')->update(['voided_at' => $this->now]);

        $summary = AuthenticationClaims::forSession($record);

        self::assertSame([$this->now->getTimestamp(), ['pwd']], [$summary->authenticatedAt->getTimestamp(), $summary->methods]);
    }

    /**
     * A session's further factors count only once a counting further factor or
     * recovery code is recorded on it: not with its first factor or a
     * reauthentication alone, not with one its adapter refused, a voided one,
     * or one bound to another guard; a recovery code or a further factor its
     * adapter accepted is one.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testOnlyAcceptedUnvoidedFurtherFactorsOfTheSessionCount(): void
    {
        $record = $this->signedIn()->record;
        $held   = static fn (): bool => SessionProofs::query($record, null, [ProofKind::ADDITIONAL_FACTOR, ProofKind::RECOVERY_CODE], 1) !== [];

        self::recordProof($record, ProofKind::FIRST_FACTOR_REAUTHENTICATION, $this->now->addMinute(), ['pwd']);
        self::recordProof($record, ProofKind::ADDITIONAL_FACTOR, $this->now->addMinutes(2), ['otp'], new Evaluation(false, true));

        self::assertFalse($held());

        self::recordProof($record, ProofKind::ADDITIONAL_FACTOR, $this->now->addMinutes(3), ['otp'], new Evaluation(true, true));

        DB::table('authentication_proofs')->where('kind', 'additional_factor')->where('accepted', true)->update(['voided_at' => $this->now]);

        self::assertFalse($held());

        self::recordProof($record, ProofKind::RECOVERY_CODE, $this->now->addMinutes(4), ['kba'], new Evaluation(true, false));

        DB::table('authentication_proofs')->where('kind', 'recovery_code')->update(['guard' => 'admin']);

        self::assertFalse($held());

        DB::table('authentication_proofs')->where('kind', 'recovery_code')->update(['guard' => 'api']);

        self::assertTrue($held());

        DB::table('authentication_proofs')->where('kind', 'recovery_code')->update(['voided_at' => $this->now]);

        self::assertFalse($held());

        self::recordProof($record, ProofKind::ADDITIONAL_FACTOR, $this->now->addMinutes(5), ['otp'], new Evaluation(true, true));

        self::assertTrue($held());
    }

    /**
     * With a factor excluded, the newest proof that meets a requirement is
     * never one made with that factor, while proofs made with another factor,
     * or with none, still meet it; the reference is compared exactly, so a
     * factor that differs from it only in case is another factor.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnExcludedFactorsProofsNeverMeetARequirement(): void
    {
        $record      = $this->signedIn()->record;
        $requirement = new FreshnessRequirement(900, [ProofKind::ADDITIONAL_FACTOR, ProofKind::FIRST_FACTOR]);
        $factor      = fn (string $reference, int $minutes): NewProof => new NewProof(
            ProofKind::ADDITIONAL_FACTOR,
            Purpose::STEP_UP,
            'totp',
            new Channel(ChannelKind::AUTHENTICATOR_APP),
            $reference,
            new ObservedProperties,
            new Evaluation(true, true),
            ['otp'],
            $this->now->addMinutes($minutes),
        );

        ProofWriter::record($record, 'api', $factor('factor-a', 1));
        ProofWriter::record($record, 'api', $factor('factor-b', 2));

        $later = $this->now->addMinutes(3);

        self::assertSame('factor-b', SessionProofs::newestMeeting($record, $requirement, $later)?->factor);
        self::assertSame('factor-a', SessionProofs::newestMeeting($record, $requirement, $later, 'factor-b')?->factor);
        self::assertSame('factor-b', SessionProofs::newestMeeting($record, $requirement, $later, 'FACTOR-A')?->factor);
        self::assertSame('factor-b', SessionProofs::newestMeeting($record, $requirement, $later, 'factor-a')?->factor);

        DB::table('authentication_proofs')->where('factor_reference', 'factor-a')->delete();

        $first = SessionProofs::newestMeeting($record, $requirement, $later, 'factor-b');

        self::assertNotNull($first);
        self::assertSame(ProofKind::FIRST_FACTOR, $first->kind);
        self::assertNull($first->factor);
        self::assertNull(SessionProofs::newestMeeting($record, new FreshnessRequirement(900, [ProofKind::ADDITIONAL_FACTOR]), $later, 'factor-b'));
    }

    /**
     * A session with no counting first factor gets no claims: issuing for it
     * fails closed, whatever else it holds.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASessionWithoutAFirstFactorHasNoClaims(): void
    {
        $record = $this->signedIn()->record;

        self::recordProof($record, ProofKind::ADDITIONAL_FACTOR, $this->now->addMinutes(5), ['otp'], new Evaluation(true, true));

        DB::table('authentication_proofs')->where('kind', 'first_factor')->update(['voided_at' => $this->now]);

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('The session records no counting first factor, so no access token can say when or how it authenticated.');

        AuthenticationClaims::forSession($record);
    }

    /**
     * A proof recorded under the session's key but bound to another guard or
     * another owner, as one left behind by an earlier session whose key a later
     * one reuses would be, counts for neither the claims nor freshness; bound
     * to the session as it is, the same proof counts for both.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAProofBoundToAnotherGuardOrOwnerNeverCounts(): void
    {
        $record = $this->signedIn()->record;
        $bound  = ['guard' => 'api', 'authenticatable_type' => $record->getAttribute('authenticatable_type'), 'authenticatable_id' => $record->getAttribute('authenticatable_id')];
        $stepUp = new FreshnessRequirement(900, [ProofKind::ADDITIONAL_FACTOR]);
        $later  = $this->now->addMinute();
        $others = [
            'another guard'      => ['guard' => 'admin'],
            'another owner type' => ['authenticatable_type' => 'another-model'],
            'another owner key'  => ['authenticatable_id' => '999999'],
        ];

        self::recordProof($record, ProofKind::ADDITIONAL_FACTOR, $later, ['otp'], new Evaluation(true, true));

        foreach ($others as $case => $binding) {

            DB::table('authentication_proofs')->where('kind', 'additional_factor')->update([...$bound, ...$binding]);

            $summary = AuthenticationClaims::forSession($record);

            self::assertSame(['pwd'], $summary->methods, $case);
            self::assertNull(SessionProofs::newestMeeting($record, $stepUp, $later), $case);
        }

        DB::table('authentication_proofs')->where('kind', 'additional_factor')->update($bound);

        self::assertSame(['pwd', 'otp', 'mfa'], AuthenticationClaims::forSession($record)->methods);
        self::assertSame(ProofKind::ADDITIONAL_FACTOR, SessionProofs::newestMeeting($record, $stepUp, $later)?->kind);
    }

    /**
     * A session whose only first factor is bound to another owner has no
     * claims: issuing for it fails closed.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASessionWhoseFirstFactorIsAnothersHasNoClaims(): void
    {
        $record = $this->signedIn()->record;

        DB::table('authentication_proofs')->update(['authenticatable_id' => '999999']);

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('The session records no counting first factor, so no access token can say when or how it authenticated.');

        AuthenticationClaims::forSession($record);
    }

    /**
     * A session that is not an Eloquent session records no owner a proof could
     * be bound to, so even proofs under its key count for nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASessionThatIsNotAModelHasNoProofs(): void
    {
        $record = $this->signedIn()->record;
        $plain  = new PlainSessionFixture((string) IdentifierCoercion::stringify($record->getKey()));

        self::assertNull(SessionProofs::history($plain)->authenticatedAt());
        self::assertNull(SessionProofs::newestMeeting($plain, new FreshnessRequirement(900, [ProofKind::FIRST_FACTOR]), $this->now));
        self::assertNotNull(SessionProofs::history($record)->authenticatedAt());

        $contract = \Mockery::mock(EloquentSession::class);
        $contract->shouldReceive('getSessionIdentifier')->andReturn($record->getKey());
        $contract->shouldReceive('getGuard')->andReturn('api');

        self::assertNull(SessionProofs::history($contract)->authenticatedAt());
    }

    /**
     * A session with no proofs at all, or one that has no key, has no claims.
     *
     * @return void
     */
    public function testASessionWithoutProofsHasNoClaims(): void
    {
        self::assertNull(SessionProofs::history(new Session)->authenticatedAt());

        $this->expectException(\LogicException::class);

        AuthenticationClaims::forSession(new Session);
    }

    /**
     * A stored list that is not one, or holds what is not a value, yields only
     * its string values.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testStoredValuesAreReadAsStrings(): void
    {
        $record = $this->signedIn()->record;

        DB::table('authentication_proofs')->update(['methods' => '["pwd", 7, null]']);

        self::assertSame(['pwd'], AuthenticationClaims::forSession($record)->methods);

        DB::table('authentication_proofs')->update(['methods' => '"pwd"']);

        self::assertSame([], AuthenticationClaims::forSession($record)->methods);
        self::assertSame(['a'], AuthenticationMethods::kept(['a', ['b']]));
    }

    /**
     * The claims read is one aggregate query, whose rows are the distinct
     * kinds, values and multifactor reports, however many step-ups the session
     * made.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheClaimsReadIsBoundedByTheDistinctProofs(): void
    {
        $record = $this->signedIn()->record;

        foreach (range(1, 40) as $minutes) {
            self::recordProof($record, ProofKind::ADDITIONAL_FACTOR, $this->now->addMinutes($minutes), ['otp'], new Evaluation(true, $minutes % 2 === 0));
        }

        $queries = [];

        DB::listen(static function (QueryExecuted $query) use (&$queries): void {
            $queries[] = $query->sql;
        });

        $summary = AuthenticationClaims::forSession($record);

        self::assertCount(1, $queries);
        self::assertStringContainsString('group by', strtolower($queries[0]));
        self::assertSame([$this->now->addMinutes(40)->getTimestamp(), ['pwd', 'otp', 'mfa']], [$summary->authenticatedAt->getTimestamp(), $summary->methods]);
        self::assertSame(41, SessionProof::query()->count());
    }

    /**
     * The newest proof a requirement takes is found and read back whole: its
     * kind, purpose, method, channel, factor, observations, evaluation, values
     * and time.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheNewestMeetingProofIsReadBackWhole(): void
    {
        $record   = $this->signedIn()->record;
        $observed = new ObservedProperties(true, true, false, null, true, KeyProtection::HARDWARE);

        self::recordProof($record, ProofKind::ADDITIONAL_FACTOR, $this->now->subMinutes(3), ['otp'], new Evaluation(true, true));
        self::recordProof($record, ProofKind::ADDITIONAL_FACTOR, $this->now->subMinutes(1), ['hwk'], new Evaluation(true, false), $observed);

        $proof = SessionProofs::newestMeeting($record, new FreshnessRequirement(900, [ProofKind::ADDITIONAL_FACTOR]), $this->now);

        self::assertNotNull($proof);
        self::assertSame([ProofKind::ADDITIONAL_FACTOR, Purpose::STEP_UP, 'test', ChannelKind::UNKNOWN, null, null, ['hwk']], [
            $proof->kind,
            $proof->purpose,
            $proof->method,
            $proof->channel->kind,
            $proof->channel->reference,
            $proof->factor,
            $proof->methods,
        ]);
        self::assertEquals($observed, $proof->observed);
        self::assertEquals(new Evaluation(true, false), $proof->evaluation);
        self::assertSame($this->now->subMinute()->getTimestamp(), $proof->authenticatedAt->getTimestamp());
        self::assertSame(SessionProof::query()->where('kind', 'additional_factor')->orderByDesc('authenticated_at')->value('id'), $proof->id);

        $first = SessionProofs::newestMeeting($record, new FreshnessRequirement(900, [ProofKind::FIRST_FACTOR]), $this->now);

        self::assertNotNull($first);
        self::assertSame(
            [ProofKind::FIRST_FACTOR, Purpose::SIGN_IN, 'password', ChannelKind::PASSWORD, null],
            [$first->kind, $first->purpose, $first->method, $first->channel->kind, $first->evaluation],
        );
    }

    /**
     * A further factor whose stored evaluation lacks its multifactor report is
     * read back with no evaluation rather than a guessed one.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAHalfRecordedEvaluationIsReadAsNone(): void
    {
        $record = $this->signedIn()->record;

        self::recordProof($record, ProofKind::ADDITIONAL_FACTOR, $this->now, ['otp'], new Evaluation(true, true));

        DB::table('authentication_proofs')->where('kind', 'additional_factor')->update(['multifactor' => null]);

        $proof = SessionProofs::newestMeeting($record, new FreshnessRequirement(900, [ProofKind::ADDITIONAL_FACTOR]), $this->now);

        self::assertSame([ProofKind::ADDITIONAL_FACTOR, null], [$proof?->kind, $proof?->evaluation]);
    }

    /**
     * A proof meets a maximum age from its own second until, and not including,
     * the second the age after it, and one made after now never does.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheAgeRunsFromTheProofsOwnSecond(): void
    {
        $record      = $this->signedIn()->record;
        $requirement = new FreshnessRequirement(60, [ProofKind::FIRST_FACTOR]);

        self::assertNotNull(SessionProofs::newestMeeting($record, $requirement, $this->now));
        self::assertNotNull(SessionProofs::newestMeeting($record, $requirement, $this->now->addSeconds(59)));
        self::assertNull(SessionProofs::newestMeeting($record, $requirement, $this->now->addSeconds(60)));
        self::assertNull(SessionProofs::newestMeeting($record, $requirement, $this->now->subSecond()));
    }

    /**
     * A requirement that asks for multifactor or phishing resistance takes only
     * a proof that reported or observed it, never one that left it unobserved,
     * and never a voided or unaccepted one.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheFlagsTakeOnlyAProofThatShowedThem(): void
    {
        $record = $this->signedIn()->record;
        $kinds  = [ProofKind::FIRST_FACTOR, ProofKind::ADDITIONAL_FACTOR];

        self::assertNull(SessionProofs::newestMeeting($record, new FreshnessRequirement(900, $kinds, true), $this->now));
        self::assertNull(SessionProofs::newestMeeting($record, new FreshnessRequirement(900, $kinds, phishingResistant: true), $this->now));

        self::recordProof($record, ProofKind::ADDITIONAL_FACTOR, $this->now, ['otp'], new Evaluation(false, true), new ObservedProperties(phishingResistant: true));

        self::assertNull(SessionProofs::newestMeeting($record, new FreshnessRequirement(900, $kinds, true), $this->now));

        self::recordProof($record, ProofKind::ADDITIONAL_FACTOR, $this->now, ['otp'], new Evaluation(true, true), new ObservedProperties(phishingResistant: false));

        self::assertNotNull(SessionProofs::newestMeeting($record, new FreshnessRequirement(900, $kinds, true), $this->now));
        self::assertNull(SessionProofs::newestMeeting($record, new FreshnessRequirement(900, $kinds, phishingResistant: true), $this->now));

        self::recordProof($record, ProofKind::ADDITIONAL_FACTOR, $this->now, ['hwk'], new Evaluation(true, true), new ObservedProperties(phishingResistant: true));

        self::assertSame(['hwk'], SessionProofs::newestMeeting($record, new FreshnessRequirement(900, $kinds, true, true), $this->now)?->methods);

        DB::table('authentication_proofs')->update(['voided_at' => $this->now]);

        self::assertNull(SessionProofs::newestMeeting($record, new FreshnessRequirement(900, $kinds), $this->now));
    }

    /**
     * A page of the counting proofs reads newest first, ties by id, only those
     * made since the time given and of the kinds given when they are, and no
     * more than the limit; the first factor is the oldest first-factor proof.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPageOfProofsIsBoundedByTimeKindAndLimit(): void
    {
        $session = $this->signedIn()->record;

        self::recordProof($session, ProofKind::ADDITIONAL_FACTOR, $this->now->addMinutes(2), ['otp'], new Evaluation(true, true));
        self::recordProof($session, ProofKind::RECOVERY_CODE, $this->now->addMinutes(2), [], new Evaluation(true, false));
        self::recordProof($session, ProofKind::ADDITIONAL_FACTOR, $this->now->addMinute(), ['otp'], new Evaluation(false, false));
        self::recordProof($session, ProofKind::FIRST_FACTOR_REAUTHENTICATION, $this->now->addMinutes(3), ['pwd']);

        $all = SessionProofs::query($session, null, null, 10);

        self::assertSame(
            [ProofKind::FIRST_FACTOR_REAUTHENTICATION, ProofKind::ADDITIONAL_FACTOR, ProofKind::RECOVERY_CODE, ProofKind::FIRST_FACTOR],
            array_map(static fn (RecordedProof $proof): ProofKind => $proof->kind, self::sortTies($all)),
        );
        self::assertCount(2, SessionProofs::query($session, null, null, 2));
        self::assertSame(
            [ProofKind::ADDITIONAL_FACTOR, ProofKind::RECOVERY_CODE],
            array_map(
                static fn (RecordedProof $proof): ProofKind => $proof->kind,
                self::sortTies(SessionProofs::query($session, $this->now->addMinutes(2), [ProofKind::ADDITIONAL_FACTOR, ProofKind::RECOVERY_CODE], 10)),
            ),
        );
        self::assertSame([], SessionProofs::query($session, $this->now->addMinutes(4), null, 10));

        $first = SessionProofs::firstFactor($session);

        self::assertNotNull($first);
        self::assertSame(ProofKind::FIRST_FACTOR, $first->kind);
        self::assertSame('password', $first->method);
    }

    /**
     * Two proofs of one second come newest id first.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testProofsOfOneSecondComeNewestIdFirst(): void
    {
        $session = $this->signedIn()->record;

        self::recordProof($session, ProofKind::ADDITIONAL_FACTOR, $this->now->addMinute(), ['otp'], new Evaluation(true, true));
        self::recordProof($session, ProofKind::ADDITIONAL_FACTOR, $this->now->addMinute(), ['otp'], new Evaluation(true, true));

        $page = SessionProofs::query($session, $this->now->addMinute(), null, 10);
        $ids  = array_map(static fn (RecordedProof $proof): string => $proof->id, $page);

        $sorted = $ids;

        rsort($sorted);

        self::assertCount(2, $ids);
        self::assertSame($sorted, $ids);
    }

    /**
     * The connection is the one the session's provenance records, and none for
     * a session no external provider established.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheConnectionIsTheProvenances(): void
    {
        $password = $this->signedIn()->record;
        $identity = $password->authenticatable()->first();

        self::assertNull(SessionProofs::connectionId($password));
        self::assertInstanceOf(Identity::class, $identity);

        $external = $this->sessions()->start($identity, null, 'sso', null, new Provenance('conn-a'))->session?->record;

        self::assertNotNull($external);
        self::assertSame('conn-a', SessionProofs::connectionId($external));
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
     * The proofs ordered by kind within one second, for comparing pages whose
     * ties the ids order.
     *
     * @param  list<\SineMacula\Laravel\Authentication\Proofs\RecordedProof>  $proofs
     * @return list<\SineMacula\Laravel\Authentication\Proofs\RecordedProof>
     */
    private static function sortTies(array $proofs): array
    {
        usort($proofs, static fn (RecordedProof $a, RecordedProof $b): int => [$b->authenticatedAt->getTimestamp(), $a->kind->value] <=> [
            $a->authenticatedAt->getTimestamp(),
            $b->kind->value,
        ]);

        return $proofs;
    }
}
