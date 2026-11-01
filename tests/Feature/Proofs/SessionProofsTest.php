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
use SineMacula\Laravel\Authentication\Freshness\FreshnessRequirement;
use SineMacula\Laravel\Authentication\Models\Session;
use SineMacula\Laravel\Authentication\Models\SessionProof;
use SineMacula\Laravel\Authentication\Proofs\AuthenticationClaims;
use SineMacula\Laravel\Authentication\Proofs\AuthenticationMethods;
use SineMacula\Laravel\Authentication\Proofs\AuthenticationSummary;
use SineMacula\Laravel\Authentication\Proofs\Enums\ChannelKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\KeyProtection;
use SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\Purpose;
use SineMacula\Laravel\Authentication\Proofs\Evaluation;
use SineMacula\Laravel\Authentication\Proofs\ObservedProperties;
use SineMacula\Laravel\Authentication\Proofs\ProofHistory;
use SineMacula\Laravel\Authentication\Proofs\RecordedProof;
use SineMacula\Laravel\Authentication\Proofs\SessionProofs;
use SineMacula\Laravel\Authentication\Sessions\SignedInSession;
use Tests\Concerns\InteractsWithProofs;
use Tests\Concerns\InteractsWithSessions;
use Tests\TestCase;

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
}
