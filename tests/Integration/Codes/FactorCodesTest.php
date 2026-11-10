<?php

declare(strict_types = 1);

namespace Tests\Integration\Codes;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Queue;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Codes\CodeBinding;
use SineMacula\Laravel\Authentication\Codes\CodeRequest;
use SineMacula\Laravel\Authentication\Codes\CodeService;
use SineMacula\Laravel\Authentication\Codes\Enums\CodePurpose;
use SineMacula\Laravel\Authentication\Codes\Enums\CodeRequestStatus;
use SineMacula\Laravel\Authentication\Codes\Enums\FactorCodeOutcome;
use SineMacula\Laravel\Authentication\Codes\Enums\FactorCodeRefusal;
use SineMacula\Laravel\Authentication\Codes\FactorCodeAdmission;
use SineMacula\Laravel\Authentication\Codes\FactorCodeBinding;
use SineMacula\Laravel\Authentication\Codes\FactorCodeCheck;
use SineMacula\Laravel\Authentication\Codes\FactorCodes;
use SineMacula\Laravel\Authentication\Codes\OneTimeCodeMessage;
use SineMacula\Laravel\Authentication\Codes\RefuseFactorCodes;
use SineMacula\Laravel\Authentication\Codes\SendOneTimeCode;
use SineMacula\Laravel\Authentication\Contracts\FactorCodeCounters;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\Enums\AuthenticationFlow;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Proofs\Channel;
use SineMacula\Laravel\Authentication\Proofs\Enums\ChannelKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\Purpose;
use SineMacula\Laravel\Authentication\Proofs\ProofBinding;
use SineMacula\Laravel\Authentication\RateLimiting\AccountAttempts;
use SineMacula\Laravel\Authentication\Testing\FakeOneTimeCodeSender;
use Tests\Concerns\InteractsWithCodeIdentities;
use Tests\Concerns\InteractsWithRateLimits;
use Tests\Fixtures\Codes\RecordingFactorCodeCounters;
use Tests\Fixtures\Database\LockMarkingSQLiteGrammar;
use Tests\Integration\Fixtures\CodeIdentity;
use Tests\TestCase;

/**
 * Integration tests for a factor package's codes through `Auth::codes($guard)`
 * against the shipped tables: `sendFactorCode()` and `verifyFactorCode()` for
 * the `mfa` challenges of a sign-in or a step-up and the `enrollment`
 * challenges that confirm a factor being enrolled, what each is bound to, the
 * counters asked before every delivery and check and told every counted attempt
 * inside the consuming transaction, the per-IP and per-destination limits kept
 * here, and the delivery cap that a new transaction never resets.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CodeService::class)]
#[CoversClass(FactorCodes::class)]
#[CoversClass(SendOneTimeCode::class)]
final class FactorCodesTest extends TestCase
{
    use InteractsWithCodeIdentities, InteractsWithRateLimits;

    /** @var string The code the engine issues first. */
    private const string CODE = '135790';

    /** @var string The destination the factor's codes go to. */
    private const string FACTOR_PHONE = '+447700900555';

    /** @var string The client the requests come from. */
    private const string IP = '203.0.113.7';

    /** @var \Carbon\CarbonImmutable Frozen clock reference. */
    private CarbonImmutable $now;

    /** @var \Tests\Integration\Fixtures\CodeIdentity The identity the factor is the identity's. */
    private CodeIdentity $identity;

    /** @var \Tests\Fixtures\Codes\RecordingFactorCodeCounters The factor package's counters, as bound. */
    private RecordingFactorCodeCounters $counters;

    /**
     * Freeze the clock, create the table and an identity, issue known codes,
     * fake the queue and bind recording counters that admit every code.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->now = CarbonImmutable::createStrict(2026, 4, 6, 12, 0, 0);

        CarbonImmutable::setTestNow($this->now);

        self::createCodeIdentitiesTable();
        self::issueCodes([self::CODE, '246802', '975310', '864200', '531975']);

        $this->identity = self::seedCodeIdentity();
        $this->counters = new RecordingFactorCodeCounters;

        $this->app?->instance(FactorCodeCounters::class, $this->counters);

        config()->set('queue.default', 'database');
        config()->set('queue.connections.database', ['driver' => 'database']);

        Queue::fake();
    }

    /**
     * Release the clock and drop the table.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        self::dropCodeIdentitiesTable();

        CarbonImmutable::setTestNow();

        parent::tearDown();
    }

    /**
     * An admitted send issues an `mfa` challenge under the destination and the
     * identity, bound to its transaction, queues its delivery to the identity,
     * and answers the challenge id and when another may be sent; the counters
     * are asked once and told nothing, since nothing was attempted.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnAdmittedSendIssuesAChallengeBoundToItsTransaction(): void
    {
        $binding = $this->binding();
        $request = $this->send($binding);
        $row     = (array) DB::table('one_time_codes')->sole();

        self::assertSame(CodeRequestStatus::SENT, $request->status);
        self::assertSame($row['challenge_id'], $request->challengeId);
        self::assertEquals($this->now->addSeconds(600), $request->expiresAt);
        self::assertEquals($this->now->addSeconds(60), $request->resendAvailableAt);
        self::assertSame(
            [self::bindingDigest(CodeBinding::factor('mobile', $binding)), 'mfa', 'mobile', 1],
            [$row['id'], $row['purpose'], $row['guard'], (int) $row['deliveries']],
        );
        self::assertIsString($row['context']);
        self::assertSame([$binding], $this->counters->admitted);
        self::assertSame([], $this->counters->reports);

        Queue::assertPushed(SendOneTimeCode::class, fn (SendOneTimeCode $job): bool => $job->binding->purpose === CodePurpose::MFA
            && [$job->binding->type, $job->binding->identifier]                                               === ['sms', self::FACTOR_PHONE]
            && $job->identity                                                                                 === $this->identity
            && $job->issued->challengeId                                                                      === $request->challengeId);
    }

    /**
     * The job delivers a factor's code to the identity it was issued for, read
     * again, with the purpose, the channel's kind as the type and the
     * destination; an enrolment's with the purpose `enrollment`.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheJobDeliversToTheIdentity(): void
    {
        $sender = FakeOneTimeCodeSender::fake($this->app);

        $this->send($this->binding());
        $this->send($this->binding(Purpose::ENROLLMENT, grant: 'grant-1', destination: 'ada.factor@example.test', kind: ChannelKind::EMAIL));

        Queue::assertPushed(SendOneTimeCode::class, static function (SendOneTimeCode $job): bool {
            $job->handle(app());

            return true;
        });

        $messages = array_map(self::delivered(...), $sender->sent());

        self::assertSame([
            [CodePurpose::MFA, 'sms', self::FACTOR_PHONE, self::CODE, $this->identity->getKey()],
            [CodePurpose::ENROLLMENT, 'email', 'ada.factor@example.test', '246802', $this->identity->getKey()],
        ], $messages);
    }

    /**
     * A job whose identity was deleted, or became a machine identity, before it
     * ran delivers nothing; nor does one whose code a resend replaced.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheJobDeliversNothingForAGoneIdentityOrAReplacedCode(): void
    {
        $sender = FakeOneTimeCodeSender::fake($this->app);

        $this->send($this->binding());

        $job = Queue::pushed(SendOneTimeCode::class)->sole();

        self::assertInstanceOf(SendOneTimeCode::class, $job);

        CarbonImmutable::setTestNow($this->now->addSeconds(60));

        $this->send($this->binding());
        $job->handle(app());

        self::assertSame(0, $sender->count());

        $current = Queue::pushed(SendOneTimeCode::class)->last();

        self::assertInstanceOf(SendOneTimeCode::class, $current);

        $this->identity->delete();
        $current->handle(app());

        self::assertSame(0, $sender->count());
    }

    /**
     * The package's default counters refuse every factor code: a send writes
     * nothing and queues nothing, and a check of a live challenge leaves it
     * untouched; each is answered `refused` (`type_not_enabled`) and reported
     * as `factor_code_refused` on the `factor_code` flow.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheDefaultCountersRefuseEveryCode(): void
    {
        $this->app?->forgetInstance(FactorCodeCounters::class);
        $this->app?->singleton(FactorCodeCounters::class, RefuseFactorCodes::class);

        $this->recordEvents([AuthenticationFailed::class]);

        $request = $this->send($this->binding());
        $failed  = $this->recordedEvent(AuthenticationFailed::class);

        self::assertSame([CodeRequestStatus::REFUSED, FactorCodeRefusal::TYPE_NOT_ENABLED, null], [$request->status, $request->refusal, $request->challengeId]);
        self::assertSame([AuthenticationFlow::FACTOR_CODE, FailureReason::FACTOR_CODE_REFUSED], [$failed->flow, $failed->reason]);
        self::assertSame([null, null], [$failed->identifier, $failed->challengeId]);
        self::assertSame(0, DB::table('one_time_codes')->count());

        Queue::assertNothingPushed();

        $this->app?->instance(FactorCodeCounters::class, $this->counters);

        $challenge = (string) $this->send($this->binding())->challengeId;

        $this->app?->instance(FactorCodeCounters::class, new RefuseFactorCodes);

        $check = $this->verify($this->binding(), $challenge, self::CODE);

        self::assertSame([FactorCodeOutcome::REFUSED, FactorCodeRefusal::TYPE_NOT_ENABLED], [$check->outcome, $check->refusal]);
        self::assertSame([0, null], [self::column('attempts'), DB::table('one_time_codes')->value('consumed_at')]);
    }

    /**
     * Counters that have the factor locked answer a send `locked`, with until
     * when, and write nothing; a check is `locked` too, with the challenge
     * untouched and nothing reported.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testLockedCountersHoldBackTheSendAndTheCheck(): void
    {
        $challenge = (string) $this->send($this->binding())->challengeId;
        $until     = $this->now->addMinutes(15);

        $this->counters->admission = FactorCodeAdmission::locked($until);

        CarbonImmutable::setTestNow($this->now->addSeconds(60));

        $this->recordEvents([AuthenticationFailed::class]);

        $request = $this->send($this->binding());

        self::assertSame([CodeRequestStatus::LOCKED, $until], [$request->status, $request->lockedUntil]);
        self::assertSame(FailureReason::FACTOR_CODE_LOCKED, $this->recordedEvent(AuthenticationFailed::class)->reason);
        self::assertSame(1, self::column('deliveries'));

        $check = $this->verify($this->binding(), $challenge, self::CODE);

        self::assertSame([FactorCodeOutcome::LOCKED, $until, $challenge], [$check->outcome, $check->lockedUntil, $check->challengeId]);
        self::assertSame([0, null], [self::column('attempts'), DB::table('one_time_codes')->value('consumed_at')]);
        self::assertSame([], $this->counters->reports);
    }

    /**
     * The right code is verified, at the time it was checked, once the counters
     * admit it and are told of the attempt, exactly once, as passed, inside the
     * storage transaction that uses the challenge up; the IP slot it took is
     * given back. A replay is used and reports nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheRightCodeIsVerifiedAndReportedOnce(): void
    {
        $binding   = $this->binding();
        $challenge = (string) $this->send($binding)->challengeId;
        $check     = $this->verify($binding, $challenge, self::CODE);

        self::assertSame([FactorCodeOutcome::VERIFIED, $challenge, null, null], [$check->outcome, $check->challengeId, $check->lockedUntil, $check->refusal]);
        self::assertTrue($check->isVerified());
        self::assertEquals($this->now, $check->verifiedAt);
        self::assertCount(1, $this->counters->reports);
        self::assertSame([$binding, $challenge, true], array_slice($this->counters->reports[0], 0, 3));
        self::assertGreaterThan(0, $this->counters->reports[0][3]);
        self::assertNotNull(DB::table('one_time_codes')->value('consumed_at'));
        self::assertSame(0, self::counterHits('mobile', 'factor_code', 'per_ip', self::IP));

        self::assertSame(FactorCodeOutcome::USED, $this->verify($binding, $challenge, self::CODE)->outcome);
        self::assertCount(1, $this->counters->reports);
    }

    /**
     * A wrong code is invalid and reported once as failed; a lock the counters
     * answer for it is carried, and its IP slot is kept.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAWrongCodeIsReportedAsFailed(): void
    {
        $binding   = $this->binding();
        $challenge = (string) $this->send($binding)->challengeId;
        $until     = $this->now->addMinutes(30);

        $this->counters->report = FactorCodeAdmission::locked($until);

        $this->recordEvents([AuthenticationFailed::class]);

        $check  = $this->verify($binding, $challenge, '000000');
        $failed = $this->recordedEvent(AuthenticationFailed::class);

        self::assertSame([FactorCodeOutcome::INVALID, $until, null], [$check->outcome, $check->lockedUntil, $check->verifiedAt]);
        self::assertSame([[$binding, $challenge, false]], array_map(static fn (array $report): array => array_slice($report, 0, 3), $this->counters->reports));
        self::assertSame([FailureReason::INVALID_CREDENTIALS, $challenge], [$failed->reason, $failed->challengeId]);
        self::assertSame([1, 1], [self::column('attempts'), self::counterHits('mobile', 'factor_code', 'per_ip', self::IP)]);

        $this->counters->report = FactorCodeAdmission::refused(FactorCodeRefusal::NOT_ACCEPTED);

        self::assertSame(
            [FactorCodeOutcome::INVALID, FactorCodeRefusal::NOT_ACCEPTED],
            [$this->verify($binding, $challenge, '000001')->outcome, $this->verify($binding, $challenge, '000002')->refusal],
        );
    }

    /**
     * Rows of `[the report's answer, the outcome, the reason]`: a matching code
     * whose report is not admitted is not verified, though the challenge is
     * used up and its attempt spent.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @return iterable<string, array{0: \Closure(): \SineMacula\Laravel\Authentication\Codes\FactorCodeAdmission, 1: \SineMacula\Laravel\Authentication\Codes\Enums\FactorCodeOutcome, 2: \SineMacula\Laravel\Authentication\Events\Enums\FailureReason}>
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    public static function provideUnadmittedReports(): iterable
    {
        yield from [
            'locked'  => [static fn (): FactorCodeAdmission => FactorCodeAdmission::locked(), FactorCodeOutcome::LOCKED, FailureReason::FACTOR_CODE_LOCKED],
            'refused' => [
                static fn (): FactorCodeAdmission => FactorCodeAdmission::refused(FactorCodeRefusal::NOT_ACCEPTED),
                FactorCodeOutcome::REFUSED,
                FailureReason::FACTOR_CODE_REFUSED,
            ],
        ];
    }

    /**
     * The report's answer is authoritative: a matching code is verified only
     * when it admits the outcome.
     *
     * @param  \Closure(): \SineMacula\Laravel\Authentication\Codes\FactorCodeAdmission  $report
     * @param  \SineMacula\Laravel\Authentication\Codes\Enums\FactorCodeOutcome  $outcome
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\FailureReason  $reason
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideUnadmittedReports')]
    public function testAMatchingCodeTheReportDoesNotAdmitIsNotVerified(\Closure $report, FactorCodeOutcome $outcome, FailureReason $reason): void
    {
        $binding   = $this->binding();
        $challenge = (string) $this->send($binding)->challengeId;

        $this->counters->report = $report();

        $this->recordEvents([AuthenticationFailed::class]);

        $check = $this->verify($binding, $challenge, self::CODE);

        self::assertSame([$outcome, null], [$check->outcome, $check->verifiedAt]);
        self::assertFalse($check->isVerified());
        self::assertSame($reason, $this->recordedEvent(AuthenticationFailed::class)->reason);
        self::assertSame([[$binding, $challenge, true]], array_map(static fn (array $entry): array => array_slice($entry, 0, 3), $this->counters->reports));
        self::assertNotNull(DB::table('one_time_codes')->value('consumed_at'));
        self::assertSame(1, self::counterHits('mobile', 'factor_code', 'per_ip', self::IP));
    }

    /**
     * Rows of `[the binding checked, the challenge id named]`: a code checked
     * against another session, another factor, another proof purpose, the other
     * kind of challenge, another identity, or naming another challenge, is
     * not found and counts and reports nothing.
     *
     * @return iterable<string, array{0: \Closure(self): \SineMacula\Laravel\Authentication\Codes\FactorCodeBinding, 1: ?string}>
     */
    public static function provideOtherTransactions(): iterable
    {
        yield from [
            'another session'   => [static fn (self $test): FactorCodeBinding => $test->binding(session: 'session-2'), null],
            'another factor'    => [static fn (self $test): FactorCodeBinding => $test->binding(factor: 'factor-2'), null],
            'a step-up'         => [static fn (self $test): FactorCodeBinding => $test->binding(Purpose::STEP_UP), null],
            'an enrolment'      => [static fn (self $test): FactorCodeBinding => $test->binding(Purpose::ENROLLMENT, grant: 'grant-1'), null],
            'another identity'  => [static fn (self $test): FactorCodeBinding => $test->binding(identity: self::seedCodeIdentity('+447700900124', 'ben@example.test')), null],
            'another challenge' => [static fn (self $test): FactorCodeBinding => $test->binding(), self::NO_CHALLENGE],
        ];
    }

    /**
     * An `mfa` code is accepted only for the very transaction it was sent for,
     * and never as an `enrollment` one; a mismatch spends nothing.
     *
     * @param  \Closure(self): \SineMacula\Laravel\Authentication\Codes\FactorCodeBinding  $other
     * @param  ?string  $challenge
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideOtherTransactions')]
    public function testACodeIsAcceptedOnlyForItsTransaction(\Closure $other, ?string $challenge): void
    {
        $live = (string) $this->send($this->binding())->challengeId;

        self::assertSame(FactorCodeOutcome::NOT_FOUND, $this->verify($other($this), $challenge ?? $live, self::CODE)->outcome);
        self::assertSame([0, null], [self::column('attempts'), DB::table('one_time_codes')->value('consumed_at')]);
        self::assertSame([], $this->counters->reports);
        self::assertTrue($this->verify($this->binding(), $live, self::CODE)->isVerified());
    }

    /**
     * An enrolment's code is never accepted as an `mfa` one either.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnEnrollmentCodeIsNeverAcceptedAsAFactorCode(): void
    {
        $enrollment = $this->binding(Purpose::ENROLLMENT, grant: 'grant-1');
        $live       = (string) $this->send($enrollment)->challengeId;

        self::assertSame(FactorCodeOutcome::NOT_FOUND, $this->verify($this->binding(), $live, self::CODE)->outcome);
        self::assertSame(FactorCodeOutcome::NOT_FOUND, $this->verify($this->binding(Purpose::ENROLLMENT, grant: 'grant-2'), $live, self::CODE)->outcome);
        self::assertSame([], $this->counters->reports);
        self::assertTrue($this->verify($enrollment, $live, self::CODE)->isVerified());
    }

    /**
     * Rows of `[what ended the challenge, the outcome, the reason]`: an expired
     * or exhausted challenge is answered so, counting and reporting nothing.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @return iterable<string, array{0: array<string, mixed>, 1: \SineMacula\Laravel\Authentication\Codes\Enums\FactorCodeOutcome, 2: \SineMacula\Laravel\Authentication\Events\Enums\FailureReason}>
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    public static function provideEndedChallenges(): iterable
    {
        yield from [
            'expired'   => [['expires_at' => '2026-04-06 12:00:00'], FactorCodeOutcome::EXPIRED, FailureReason::CODE_EXPIRED],
            'exhausted' => [['attempts' => 5], FactorCodeOutcome::EXHAUSTED, FailureReason::CODE_EXHAUSTED],
        ];
    }

    /**
     * An ended challenge says how it ended and reports nothing.
     *
     * @param  array<string, mixed>  $ending
     * @param  \SineMacula\Laravel\Authentication\Codes\Enums\FactorCodeOutcome  $outcome
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\FailureReason  $reason
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEndedChallenges')]
    public function testAnEndedChallengeReportsNothing(array $ending, FactorCodeOutcome $outcome, FailureReason $reason): void
    {
        $challenge = (string) $this->send($this->binding())->challengeId;

        DB::table('one_time_codes')->update($ending);

        $this->recordEvents([AuthenticationFailed::class]);

        self::assertSame($outcome, $this->verify($this->binding(), $challenge, self::CODE)->outcome);
        self::assertSame($reason, $this->recordedEvent(AuthenticationFailed::class)->reason);
        self::assertSame([], $this->counters->reports);
    }

    /**
     * Rows of `[binding, challenge id]` that name a challenge the binding does
     * not own once it was used up: another session, factor, purpose, grant or
     * identity, and an id the binding never had.
     *
     * @return iterable<string, array{0: \Closure(self): \SineMacula\Laravel\Authentication\Codes\FactorCodeBinding}>
     */
    public static function provideOtherBindings(): iterable
    {
        yield from [
            'another session'  => [static fn (self $test): FactorCodeBinding => $test->binding(session: 'session-2')],
            'another factor'   => [static fn (self $test): FactorCodeBinding => $test->binding(factor: 'factor-2')],
            'another purpose'  => [static fn (self $test): FactorCodeBinding => $test->binding(Purpose::STEP_UP)],
            'an enrolment'     => [static fn (self $test): FactorCodeBinding => $test->binding(Purpose::ENROLLMENT, grant: 'grant-1')],
            'another identity' => [static fn (self $test): FactorCodeBinding => $test->binding(identity: self::seedCodeIdentity('+447700900124', 'ben@example.test'))],
        ];
    }

    /**
     * A challenge of another binding is not found even once it was used up,
     * never used, so the answer says nothing of another binding's challenges;
     * nothing is counted or reported to the counters, the IP slot is taken and
     * the refusal is reported as for any other.
     *
     * @param  \Closure(self): \SineMacula\Laravel\Authentication\Codes\FactorCodeBinding  $other
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideOtherBindings')]
    public function testAUsedChallengeOfAnotherBindingIsNotFound(\Closure $other): void
    {
        $owner     = $this->binding();
        $challenge = (string) $this->send($owner)->challengeId;

        self::assertTrue($this->verify($owner, $challenge, self::CODE)->isVerified());

        $this->recordEvents([AuthenticationFailed::class]);

        $reports = $this->counters->reports;
        $check   = $this->verify($other($this), $challenge, self::CODE);
        $failed  = $this->recordedEvent(AuthenticationFailed::class);

        self::assertSame([FactorCodeOutcome::NOT_FOUND, $challenge], [$check->outcome, $check->challengeId]);
        self::assertSame([FailureReason::INVALID_CREDENTIALS, AuthenticationFlow::FACTOR_CODE, $challenge], [$failed->reason, $failed->flow, $failed->challengeId]);
        self::assertSame($reports, $this->counters->reports);
        self::assertSame(1, self::column('attempts'));
        self::assertSame(1, self::counterHits('mobile', 'factor_code', 'per_ip', self::IP));
    }

    /**
     * A well-formed challenge id nobody issued is not found: no attempt is
     * counted and nothing is reported to the counters, but the IP slot is taken
     * and the refusal is reported with the id.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnUnknownChallengeIsNotFound(): void
    {
        $this->send($this->binding());

        $this->recordEvents([AuthenticationFailed::class]);

        $check  = $this->verify($this->binding(), self::NO_CHALLENGE, self::CODE);
        $failed = $this->recordedEvent(AuthenticationFailed::class);

        self::assertSame([FactorCodeOutcome::NOT_FOUND, self::NO_CHALLENGE], [$check->outcome, $check->challengeId]);
        self::assertSame([FailureReason::INVALID_CREDENTIALS, self::NO_CHALLENGE], [$failed->reason, $failed->challengeId]);
        self::assertSame([[], 0, 1], [$this->counters->reports, self::column('attempts'), self::counterHits('mobile', 'factor_code', 'per_ip', self::IP)]);
    }

    /**
     * A challenge replaced by a newer one is not found, as the newer one is the
     * binding's challenge now.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAReplacedChallengeIsNotFound(): void
    {
        $binding = $this->binding();
        $first   = (string) $this->send($binding)->challengeId;

        DB::table('one_time_codes')->update(['consumed_at' => '2026-04-06 11:00:00']);
        CarbonImmutable::setTestNow($this->now->addDay());

        $second = (string) $this->send($binding)->challengeId;

        self::assertNotSame($first, $second);
        self::assertSame(FactorCodeOutcome::NOT_FOUND, $this->verify($binding, $first, self::CODE)->outcome);
        self::assertSame([], $this->counters->reports);
    }

    /**
     * Rows of `[what used the challenge up]`: a code that matched, and a
     * challenge that was ended, each with and without having expired since.
     *
     * @return iterable<string, array{0: array<string, mixed>}>
     */
    public static function provideUsedChallenges(): iterable
    {
        yield from [
            'ended'               => [['consumed_at' => '2026-04-06 11:59:00']],
            'ended and expired'   => [['consumed_at' => '2026-04-06 11:59:00', 'expires_at' => '2026-04-06 12:00:00']],
            'ended and exhausted' => [['consumed_at' => '2026-04-06 11:59:00', 'attempts' => 5]],
        ];
    }

    /**
     * The binding's own used challenge is used, whether or not it has expired
     * or used up its attempts since; no attempt is counted, nothing is reported
     * to the counters, and the refusal is reported as for any other.
     *
     * @param  array<string, mixed>  $state
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideUsedChallenges')]
    public function testTheBindingsOwnUsedChallengeIsUsed(array $state): void
    {
        $binding   = $this->binding();
        $challenge = (string) $this->send($binding)->challengeId;

        DB::table('one_time_codes')->update($state);

        $this->recordEvents([AuthenticationFailed::class]);

        $check  = $this->verify($binding, $challenge, self::CODE);
        $failed = $this->recordedEvent(AuthenticationFailed::class);

        self::assertSame([FactorCodeOutcome::USED, $challenge], [$check->outcome, $check->challengeId]);
        self::assertSame([FailureReason::INVALID_CREDENTIALS, $challenge], [$failed->reason, $failed->challengeId]);
        self::assertSame([[], $state['attempts'] ?? 0, 1], [$this->counters->reports, self::column('attempts'), self::counterHits('mobile', 'factor_code', 'per_ip', self::IP)]);
    }

    /**
     * A used challenge is used again and again, however wrong the code, as it
     * is never compared; a live challenge's wrong code is still invalid and
     * counted.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAWrongCodeIsStillInvalidWhileAUsedChallengeIsUsed(): void
    {
        $binding   = $this->binding();
        $challenge = (string) $this->send($binding)->challengeId;

        self::assertSame(FactorCodeOutcome::INVALID, $this->verify($binding, $challenge, '000000')->outcome);
        self::assertSame([1, 1], [self::column('attempts'), count($this->counters->reports)]);
        self::assertTrue($this->verify($binding, $challenge, self::CODE)->isVerified());
        self::assertSame(FactorCodeOutcome::USED, $this->verify($binding, $challenge, '000000')->outcome);
        self::assertSame([2, 2], [self::column('attempts'), count($this->counters->reports)]);
    }

    /**
     * Rows of `[challenge id, code, the outcome, challenge id reported]` a
     * check refuses once its IP slot is taken: a challenge id not in the form
     * the engine issues is not found and never reported, a code not in the form
     * is invalid, and a check malformed in both is not found.
     *
     * @return iterable<string, array{0: string, 1: string, 2: \SineMacula\Laravel\Authentication\Codes\Enums\FactorCodeOutcome, 3: ?string}>
     */
    public static function provideMalformedChecks(): iterable
    {
        yield from [
            'a short code'            => [self::NO_CHALLENGE, '13579', FactorCodeOutcome::INVALID, self::NO_CHALLENGE],
            'a code with a letter'    => [self::NO_CHALLENGE, '13579O', FactorCodeOutcome::INVALID, self::NO_CHALLENGE],
            'a challenge in capitals' => ['0195F4A2-7B1C-4000-8000-00000000000A', self::CODE, FactorCodeOutcome::NOT_FOUND, null],
            'an empty challenge'      => ['', self::CODE, FactorCodeOutcome::NOT_FOUND, null],
            'both malformed'          => ['', '13579', FactorCodeOutcome::NOT_FOUND, null],
        ];
    }

    /**
     * A malformed code is invalid and a malformed challenge id not found, with
     * no attempt counted, the counters not asked and nothing reported to them;
     * the IP slot is taken and kept.
     *
     * @param  string  $challenge
     * @param  string  $code
     * @param  \SineMacula\Laravel\Authentication\Codes\Enums\FactorCodeOutcome  $outcome
     * @param  ?string  $reported
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideMalformedChecks')]
    public function testAMalformedCheckKeepsItsIpSlotAndCountsNoAttempt(string $challenge, string $code, FactorCodeOutcome $outcome, ?string $reported): void
    {
        $this->send($this->binding());

        $this->counters->admitted = [];

        $this->recordEvents([AuthenticationFailed::class]);

        $check  = $this->verify($this->binding(), $challenge, $code);
        $failed = $this->recordedEvent(AuthenticationFailed::class);

        self::assertSame([$outcome, $challenge], [$check->outcome, $check->challengeId]);
        self::assertSame([FailureReason::INVALID_CREDENTIALS, AuthenticationFlow::FACTOR_CODE, $reported], [$failed->reason, $failed->flow, $failed->challengeId]);
        self::assertSame([[], []], [$this->counters->admitted, $this->counters->reports]);
        self::assertSame([0, 1], [self::column('attempts'), self::counterHits('mobile', 'factor_code', 'per_ip', self::IP)]);
    }

    /**
     * Once the IP address's checks are used up a malformed check is
     * `rate_limited`, with the wait, not `not_found` or `invalid`: the limit is
     * taken before the input is judged. The refusal is reported with the
     * rate-limited reason, and the counters are neither asked nor told.
     *
     * @param  string  $challenge
     * @param  string  $code
     * @param  \SineMacula\Laravel\Authentication\Codes\Enums\FactorCodeOutcome  $outcome
     * @param  ?string  $reported
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideMalformedChecks')]
    public function testAMalformedCheckIsRateLimitedOnceTheLimitIsUsedUp(string $challenge, string $code, FactorCodeOutcome $outcome, ?string $reported): void
    {
        unset($outcome, $reported);

        config()->set('authentication.rate_limits.factor_code.per_ip', ['max' => 1, 'decay_seconds' => 300]);

        $this->send($this->binding());

        $this->verify($this->binding(), $challenge, $code);

        $this->counters->admitted = [];

        $this->recordEvents([AuthenticationFailed::class]);

        $check  = $this->verify($this->binding(), $challenge, $code);
        $failed = $this->recordedEvent(AuthenticationFailed::class);

        self::assertSame([FactorCodeOutcome::RATE_LIMITED, 300, $challenge], [$check->outcome, $check->retryAfter, $check->challengeId]);
        self::assertSame([FailureReason::RATE_LIMITED, 300], [$failed->reason, $failed->retryAfter]);
        self::assertSame([[], []], [$this->counters->admitted, $this->counters->reports]);
        self::assertSame([0, 1], [self::column('attempts'), self::counterHits('mobile', 'factor_code', 'per_ip', self::IP)]);
    }

    /**
     * Checks are limited per IP address (`factor_code`): once its checks are
     * used up a check is `rate_limited`, with the wait, before the counters are
     * asked or the challenge is read.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testChecksAreLimitedPerIp(): void
    {
        config()->set('authentication.rate_limits.factor_code.per_ip', ['max' => 1, 'decay_seconds' => 300]);

        $challenge = (string) $this->send($this->binding())->challengeId;

        $this->verify($this->binding(), $challenge, '000000');

        $this->counters->admitted = [];

        $this->recordEvents([AuthenticationFailed::class]);

        $check  = $this->verify($this->binding(), $challenge, self::CODE);
        $failed = $this->recordedEvent(AuthenticationFailed::class);

        self::assertSame([FactorCodeOutcome::RATE_LIMITED, 300], [$check->outcome, $check->retryAfter]);
        self::assertSame([FailureReason::RATE_LIMITED, 300, $challenge], [$failed->reason, $failed->retryAfter, $failed->challengeId]);
        self::assertSame([], $this->counters->admitted);
        self::assertSame(1, self::column('attempts'));
    }

    /**
     * A send counts under `code_request` on the destination, the identity's
     * account and the IP address, before its transaction; out of requests, it
     * is `rate_limited`, before the counters are asked.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testSendsAreLimitedPerDestinationOwnerAndIp(): void
    {
        config()->set('authentication.rate_limits.code_request.per_identifier', ['max' => 1, 'decay_seconds' => 3600]);

        $this->send($this->binding());

        self::assertSame(1, self::counterHits('mobile', 'code_request', 'per_identifier', self::FACTOR_PHONE));
        self::assertSame(1, self::counterHits('code_request', 'per_account', AccountAttempts::account($this->identity)));
        self::assertSame(1, self::counterHits('mobile', 'code_request', 'per_ip', self::IP));

        $this->counters->admitted = [];

        CarbonImmutable::setTestNow($this->now->addSeconds(60));

        $request = $this->send($this->binding());

        self::assertSame(CodeRequestStatus::RATE_LIMITED, $request->status);
        self::assertSame([], $this->counters->admitted);
    }

    /**
     * A client the caller hands in, not the request's, is the one a send and a
     * check count against and report.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheClientHandedInIsTheOneCountedAndReported(): void
    {
        $binding = $this->binding();
        $client  = new ClientContext('198.51.100.9', 'Other/1.0');

        $challenge = (string) $this->codeService()->sendFactorCode($binding, $client)->challengeId;

        self::assertSame([1, 0], [self::counterHits('mobile', 'code_request', 'per_ip', '198.51.100.9'), self::counterHits('mobile', 'code_request', 'per_ip', self::IP)]);

        $this->recordEvents([AuthenticationFailed::class]);

        self::assertSame(FactorCodeOutcome::INVALID, $this->codeService()->verifyFactorCode($binding, $challenge, '000000', $client)->outcome);
        self::assertSame([1, 0], [self::counterHits('mobile', 'factor_code', 'per_ip', '198.51.100.9'), self::counterHits('mobile', 'factor_code', 'per_ip', self::IP)]);
        self::assertSame('198.51.100.9', $this->recordedEvent(AuthenticationFailed::class)->context->client->ip);
    }

    /**
     * A report that throws rolls the whole check back, its attempt and its use
     * included, and the exception propagates.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAThrowingReportRollsTheCheckBack(): void
    {
        $challenge = (string) $this->send($this->binding())->challengeId;

        $this->counters->failure = new \RuntimeException('The counters failed.');

        try {
            $this->verify($this->binding(), $challenge, self::CODE);
            self::fail('The report\'s exception did not propagate.');
        } catch (\RuntimeException $exception) {
            self::assertSame('The counters failed.', $exception->getMessage());
        }

        self::assertSame([0, null], [self::column('attempts'), DB::table('one_time_codes')->value('consumed_at')]);
    }

    /**
     * A check asks the counters before it locks the challenge's row, and
     * reports after it uses the challenge up, all in one transaction.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACheckAsksBeforeItLocksTheChallenge(): void
    {
        $challenge  = (string) $this->send($this->binding())->challengeId;
        $connection = DB::connection();

        if ($connection->getDriverName() === 'sqlite') {
            $connection->setQueryGrammar(new LockMarkingSQLiteGrammar($connection));
        }

        $order = [];

        $this->counters->admitted = [];

        $connection->listen(static function (QueryExecuted $query) use (&$order): void {
            if (!str_contains($query->sql, 'one_time_codes')) {
                return;
            }

            $order[] = strtok($query->sql, ' ') . (str_contains($query->sql, 'for update') ? ' locked' : '');
        });

        $this->counters->observer = static function (string $call) use (&$order): void {
            $order[] = $call;
        };

        self::assertTrue($this->verify($this->binding(), $challenge, self::CODE)->isVerified());
        self::assertSame(['admit', 'select locked', 'update', 'update', 'report'], $order);
    }

    /**
     * Inside a caller's transaction that rolls back, a send leaves no challenge
     * and queues nothing, and a check leaves the challenge unspent.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACallersRollbackUndoesTheSendAndTheCheck(): void
    {
        DB::beginTransaction();

        self::assertTrue($this->send($this->binding())->isSent());

        DB::rollBack();

        self::assertSame(0, DB::table('one_time_codes')->count());

        Queue::assertNothingPushed();

        self::issueCodes([self::CODE]);

        $challenge = (string) $this->send($this->binding())->challengeId;

        DB::beginTransaction();

        self::assertTrue($this->verify($this->binding(), $challenge, self::CODE)->isVerified());

        DB::rollBack();

        self::assertSame([0, null], [self::column('attempts'), DB::table('one_time_codes')->value('consumed_at')]);
        self::assertTrue($this->verify($this->binding(), $challenge, self::CODE)->isVerified());
    }

    /**
     * A resend for the same transaction keeps the challenge and its attempts;
     * one for another session, or an enrolment restarted with a new pending
     * factor and grant, is a new challenge, still under the destination's
     * cooldown and delivery cap, which neither resets.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testANewTransactionNeverResetsTheCooldownOrTheCap(): void
    {
        config()->set('authentication.codes.max_deliveries', 3);

        $first = (string) $this->send($this->binding(Purpose::ENROLLMENT, grant: 'grant-1'))->challengeId;

        $this->verify($this->binding(Purpose::ENROLLMENT, grant: 'grant-1'), $first, '000000');

        CarbonImmutable::setTestNow($this->now->addSeconds(30));

        self::assertSame(CodeRequestStatus::RATE_LIMITED, $this->send($this->binding(Purpose::ENROLLMENT, factor: 'factor-2', grant: 'grant-2'))->status);

        CarbonImmutable::setTestNow($this->now->addSeconds(60));

        self::assertSame($first, $this->send($this->binding(Purpose::ENROLLMENT, grant: 'grant-1'))->challengeId);
        self::assertSame(1, self::column('attempts'));

        CarbonImmutable::setTestNow($this->now->addSeconds(120));

        $restarted = $this->send($this->binding(Purpose::ENROLLMENT, factor: 'factor-2', grant: 'grant-2', session: 'session-2'))->challengeId;

        self::assertNotSame($first, $restarted);
        self::assertSame([0, 3], [self::column('attempts'), self::column('deliveries')]);

        CarbonImmutable::setTestNow($this->now->addSeconds(180));

        $capped = $this->send($this->binding(Purpose::ENROLLMENT, factor: 'factor-3', grant: 'grant-3', session: 'session-3'));

        self::assertSame([CodeRequestStatus::DELIVERIES_EXHAUSTED, 1620], [$capped->status, $capped->retryAfter]);
    }

    /**
     * A binding for another application than the guard's is a misconfiguration,
     * refused before anything is counted.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testABindingForAnotherApplicationIsRefused(): void
    {
        $binding = new FactorCodeBinding(new ProofBinding($this->identity, 'kiosk', 'session-1', Purpose::SIGN_IN), 'factor-1', new Channel(ChannelKind::SMS, self::FACTOR_PHONE));

        foreach ([fn (): CodeRequest => $this->send($binding), fn (): FactorCodeCheck => $this->verify($binding, self::NO_CHALLENGE, self::CODE)] as $call) {
            try {
                $call();
                self::fail('A binding for another application was accepted.');
            } catch (\InvalidArgumentException $exception) {
                self::assertSame('A factor code bound to application [kiosk] cannot be sent or checked through guard [mobile].', $exception->getMessage());
            }
        }

        self::assertSame(0, DB::table('rate_limits')->count());
    }

    /**
     * A factor code binding for the identity, on the `mobile` application.
     *
     * @param  \SineMacula\Laravel\Authentication\Proofs\Enums\Purpose  $purpose
     * @param  string  $factor
     * @param  ?string  $grant
     * @param  string  $session
     * @param  string  $destination
     * @param  \SineMacula\Laravel\Authentication\Proofs\Enums\ChannelKind  $kind
     * @param  ?\Tests\Integration\Fixtures\CodeIdentity  $identity
     * @return \SineMacula\Laravel\Authentication\Codes\FactorCodeBinding
     */
    public function binding(
        Purpose $purpose = Purpose::SIGN_IN,
        string $factor = 'factor-1',
        ?string $grant = null,
        string $session = 'session-1',
        string $destination = self::FACTOR_PHONE,
        ChannelKind $kind = ChannelKind::SMS,
        ?CodeIdentity $identity = null,
    ): FactorCodeBinding {
        return new FactorCodeBinding(new ProofBinding($identity ?? $this->identity, 'mobile', $session, $purpose), $factor, new Channel($kind, $destination), $grant);
    }

    /**
     * Configure the guards.
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

        self::configureCodeGuards($app->make(ConfigRepository::class));
    }

    /**
     * The column of the one code row, as an integer.
     *
     * @param  string  $column
     * @return int
     *
     * @phpstan-impure
     */
    private static function column(string $column): int
    {
        $value = DB::table('one_time_codes')->value($column);

        self::assertIsNumeric($value);

        return (int) $value;
    }

    /**
     * What a message delivered: its purpose, type, destination, code and
     * recipient.
     *
     * @param  \SineMacula\Laravel\Authentication\Codes\OneTimeCodeMessage  $message
     * @return list<mixed>
     */
    private static function delivered(OneTimeCodeMessage $message): array
    {
        return [$message->purpose, $message->type, $message->identifier, $message->code->reveal(), $message->identity->getAuthIdentifier()];
    }

    /**
     * Send the binding's code through the `mobile` guard from the client.
     *
     * @param  \SineMacula\Laravel\Authentication\Codes\FactorCodeBinding  $binding
     * @return \SineMacula\Laravel\Authentication\Codes\CodeRequest
     *
     * @throws \Throwable
     */
    private function send(FactorCodeBinding $binding): CodeRequest
    {
        return $this->codeService()->sendFactorCode($binding, new ClientContext(self::IP, 'Phone/1.0'));
    }

    /**
     * Check the code for the challenge against the binding through the `mobile`
     * guard from the client.
     *
     * @param  \SineMacula\Laravel\Authentication\Codes\FactorCodeBinding  $binding
     * @param  string  $challenge
     * @param  string  $code
     * @return \SineMacula\Laravel\Authentication\Codes\FactorCodeCheck
     *
     * @throws \Throwable
     */
    private function verify(FactorCodeBinding $binding, string $challenge, string $code): FactorCodeCheck
    {
        return $this->codeService()->verifyFactorCode($binding, $challenge, $code, new ClientContext(self::IP, 'Phone/1.0'));
    }
}
