<?php

declare(strict_types = 1);

namespace Tests\Feature\Codes;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Queue;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\AuthManager;
use SineMacula\Laravel\Authentication\Codes\CodeBinding;
use SineMacula\Laravel\Authentication\Codes\CodeRequest;
use SineMacula\Laravel\Authentication\Codes\CodeService;
use SineMacula\Laravel\Authentication\Codes\Enums\CodePurpose;
use SineMacula\Laravel\Authentication\Codes\Enums\CodeRequestStatus;
use SineMacula\Laravel\Authentication\Codes\Enums\VerificationOutcome;
use SineMacula\Laravel\Authentication\Codes\FactorCodeBinding;
use SineMacula\Laravel\Authentication\Codes\SendOneTimeCode;
use SineMacula\Laravel\Authentication\Contracts\FactorCodeCounters;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\Enums\AuthenticationFlow;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\IdentifierVerified;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Models\Session;
use SineMacula\Laravel\Authentication\Proofs\Channel;
use SineMacula\Laravel\Authentication\Proofs\Enums\ChannelKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\Purpose;
use SineMacula\Laravel\Authentication\Proofs\ProofBinding;
use SineMacula\Laravel\Authentication\RateLimiting\AccountAttempts;
use Tests\Concerns\InteractsWithCodeIdentities;
use Tests\Concerns\InteractsWithRateLimits;
use Tests\Fixtures\Codes\RecordingFactorCodeCounters;
use Tests\Fixtures\Events\EventContextAssertions;
use Tests\Integration\Fixtures\IntegrationIdentity;
use Tests\Integration\Fixtures\MachineClient;
use Tests\TestCase;

/**
 * Feature tests for `Auth::codes($guard)`: sending sign-in codes (the checks a
 * request passes, the limits and cooldown it is held to, the job it queues once
 * the code is committed, and what each refusal reports), and sending and
 * checking codes that verify an identity's identifier.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CodeService::class)]
#[CoversClass(CodeRequest::class)]
#[CoversClass(AuthManager::class)]
final class CodeServiceTest extends TestCase
{
    use InteractsWithCodeIdentities, InteractsWithRateLimits;

    /** @var string The code the engine issues first. */
    private const string CODE = '135790';

    /** @var \Carbon\CarbonImmutable Frozen clock reference. */
    private CarbonImmutable $now;

    /**
     * Freeze the clock, create the table, issue known codes, and fake a queue
     * that a worker would run, so a delivery is pushed as soon as it is
     * dispatched.
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
        self::issueCodes([self::CODE, '246802', '975310', '864200', '531975', '102938']);

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
     * A sign-in code is issued and its delivery queued on the configured
     * connection and queue: the job carries the binding and the issuance, and
     * no identity, since the recipient is found only when it runs. The result
     * says when the code expires and when another may be requested; nothing is
     * reported as failed.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testSendingQueuesTheDelivery(): void
    {
        config()->set('authentication.delivery.queue', ['connection' => 'deliveries', 'name' => 'codes']);
        config()->set('queue.connections.deliveries', ['driver' => 'database']);

        Event::fake([AuthenticationFailed::class]);

        $request = $this->codeService()->send('phone_code', ['phone' => ' ' . self::PHONE], self::requestClient());

        self::assertSame([CodeRequestStatus::SENT, null], [$request->status, $request->retryAfter]);
        self::assertEquals($this->now->addSeconds(600), $request->expiresAt);
        self::assertEquals($this->now->addSeconds(60), $request->resendAvailableAt);

        Queue::assertPushedOn('codes', SendOneTimeCode::class, static fn (SendOneTimeCode $job): bool => $job->connection === 'deliveries'
                && $job->identity                                                                                         === null
                && $job->binding->purpose                                                                                 === CodePurpose::SIGN_IN
                && [$job->binding->guard, $job->binding->type, $job->binding->identifier]                                 === ['mobile', 'phone', self::PHONE]
                && $job->issued->code()                                                                                   === self::CODE
                && $job->issued->issueId                                                                                  === DB::table('one_time_codes')->value('issue_id'));

        Event::assertNotDispatched(AuthenticationFailed::class);
    }

    /**
     * A number no identity has gets the same result and a queued delivery,
     * which alone finds out there is no recipient.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnUnknownNumberIsAnsweredTheSame(): void
    {
        self::seedCodeIdentity();

        $known   = $this->codeService()->send('phone_code', ['phone' => self::PHONE], self::requestClient());
        $unknown = $this->codeService()->send('phone_code', ['phone' => self::UNKNOWN_PHONE], self::requestClient());

        self::assertEquals([$known->status, $known->expiresAt, $known->retryAfter], [$unknown->status, $unknown->expiresAt, $unknown->retryAfter]);
        self::assertEquals($known->resendAvailableAt, $unknown->resendAvailableAt);
        self::assertMatchesRegularExpression(self::CHALLENGE_PATTERN, (string) $known->challengeId);
        self::assertMatchesRegularExpression(self::CHALLENGE_PATTERN, (string) $unknown->challengeId);
        self::assertNotSame($known->challengeId, $unknown->challengeId);

        Queue::assertPushed(SendOneTimeCode::class, 2);
    }

    /**
     * Rows of `[the guard's application block]`: an application that lists
     * other methods, and one that takes the package default, which lists none.
     *
     * @return iterable<string, array{0: ?array<string, mixed>}>
     */
    public static function provideApplicationsWithoutTheMethod(): iterable
    {
        yield 'one listing other methods' => [['methods' => ['sso']]];
        yield 'none, so the shipped default that lists nothing' => [null];
    }

    /**
     * A guard that does not allow the method refuses the request before
     * anything is counted or issued, and reports it with the number as given.
     *
     * @param  ?array<string, mixed>  $application
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideApplicationsWithoutTheMethod')]
    public function testAGuardThatDoesNotAllowTheMethodRefuses(?array $application): void
    {
        config()->set('auth.guards.web.application', $application);

        $this->recordEvents([AuthenticationFailed::class]);

        $request = $this->codeService('web')->send('phone_code', ['phone' => self::PHONE], self::requestClient());
        $failed  = $this->recordedEvent(AuthenticationFailed::class);

        self::assertSame(CodeRequestStatus::METHOD_NOT_ALLOWED, $request->status);
        self::assertSame([AuthenticationFlow::CODE_REQUEST, FailureReason::METHOD_NOT_ALLOWED, self::PHONE], [$failed->flow, $failed->reason, $failed->identifier]);
        self::assertSame(['phone_code', 'web'], [$failed->context->method, $failed->context->guard]);
        self::assertSame([0, 0], [DB::table('one_time_codes')->count(), DB::table('rate_limits')->count()]);

        Queue::assertNothingPushed();
    }

    /**
     * Rows of numbers the E.164 normaliser refuses.
     *
     * @return iterable<string, array{0: array<string, mixed>, 1: ?string}>
     */
    public static function provideInvalidNumbers(): iterable
    {
        yield from [
            'national format' => [['phone' => '07700 900123'], '07700 900123'],
            'spaced'          => [['phone' => '+44 7700 900123'], '+44 7700 900123'],
            'not a string'    => [['phone' => 447700900123], null],
            'missing'         => [[], null],
        ];
    }

    /**
     * A number the type's normaliser refuses is `identifier_invalid`, reported
     * as `invalid_credentials`, before anything is counted or issued.
     *
     * @param  array<string, mixed>  $input
     * @param  ?string  $given
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideInvalidNumbers')]
    public function testANumberThatIsNotOneIsRefused(array $input, ?string $given): void
    {
        $this->recordEvents([AuthenticationFailed::class]);

        $request = $this->codeService()->send('phone_code', $input, self::requestClient());
        $failed  = $this->recordedEvent(AuthenticationFailed::class);

        self::assertSame(CodeRequestStatus::IDENTIFIER_INVALID, $request->status);
        self::assertSame([AuthenticationFlow::CODE_REQUEST, FailureReason::INVALID_CREDENTIALS, $given], [$failed->flow, $failed->reason, $failed->identifier]);
        self::assertSame([0, 0], [DB::table('one_time_codes')->count(), DB::table('rate_limits')->count()]);
    }

    /**
     * A method that does not sign in with codes, or none at all, is a
     * misconfiguration.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAMethodThatIsNotACodeMethodThrows(): void
    {
        try {
            $this->codeService()->send('password', ['email' => 'ada@example.test'], self::requestClient());

            self::fail('A password method sent a code.');
        } catch (\InvalidArgumentException $exception) {
            self::assertSame('Sign-in method [password] does not sign in with one-time codes.', $exception->getMessage());
        }

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Sign-in method [sms_code] is not registered.');

        $this->codeService()->send('sms_code', ['phone' => self::PHONE], self::requestClient());
    }

    /**
     * Within the resend cooldown no code is issued: the request is rate limited
     * for the seconds left, reported with the wait, and the code already sent
     * keeps working.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheResendCooldownRateLimits(): void
    {
        $this->codeService()->send('phone_code', ['phone' => self::PHONE], self::requestClient());

        CarbonImmutable::setTestNow($this->now->addSeconds(25));

        $this->recordEvents([AuthenticationFailed::class]);

        $request = $this->codeService()->send('phone_code', ['phone' => self::PHONE], self::requestClient());
        $failed  = $this->recordedEvent(AuthenticationFailed::class);

        self::assertSame([CodeRequestStatus::RATE_LIMITED, 35, null], [$request->status, $request->retryAfter, $request->expiresAt]);
        self::assertSame([FailureReason::RATE_LIMITED, 35], [$failed->reason, $failed->retryAfter]);

        Queue::assertPushed(SendOneTimeCode::class, 1);
    }

    /**
     * Every request counts against the number's and the IP address's code
     * request limits, refused or not, and once a limit is used up the request
     * is rate limited until its window ends, without issuing a code.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testCodeRequestsAreLimitedPerNumberAndPerAddress(): void
    {
        config()->set('authentication.codes.resend_cooldown_seconds', 0);
        config()->set('authentication.rate_limits.code_request', [
            'per_identifier' => ['max' => 2, 'decay_seconds' => 3600],
            'per_ip'         => ['max' => 3, 'decay_seconds' => 3600],
        ]);

        self::assertTrue($this->codeService()->send('phone_code', ['phone' => self::PHONE], self::requestClient())->isSent());
        self::assertTrue($this->codeService()->send('phone_code', ['phone' => ' ' . self::PHONE], self::requestClient())->isSent());

        $limited = $this->codeService()->send('phone_code', ['phone' => self::PHONE], self::requestClient());

        self::assertSame([CodeRequestStatus::RATE_LIMITED, 3600], [$limited->status, $limited->retryAfter]);
        self::assertSame(2, self::counterHits('mobile', 'code_request', 'per_identifier', self::PHONE));
        self::assertTrue($this->codeService()->send('phone_code', ['phone' => self::UNKNOWN_PHONE], self::requestClient())->isSent());
        self::assertSame(CodeRequestStatus::RATE_LIMITED, $this->codeService()->send('phone_code', ['phone' => '+447700900555'], self::requestClient())->status);
        self::assertSame(3, self::counterHits('mobile', 'code_request', 'per_ip', self::CLIENT_IP));

        Queue::assertPushed(SendOneTimeCode::class, 3);
    }

    /**
     * The delivery is queued only once the code is committed on its connection:
     * inside a transaction it waits for the commit, and a rollback, which takes
     * the code back, queues nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheDeliveryIsQueuedOnlyOnceTheCodeIsCommitted(): void
    {
        config()->set('authentication.codes.resend_cooldown_seconds', 0);

        DB::beginTransaction();

        $this->codeService()->send('phone_code', ['phone' => self::PHONE], self::requestClient());

        Queue::assertNothingPushed();

        DB::rollBack();

        Queue::assertNothingPushed();
        self::assertSame(0, DB::table('one_time_codes')->count());

        DB::transaction(function (): void {
            $this->codeService()->send('phone_code', ['phone' => self::PHONE], self::requestClient());

            Queue::assertNothingPushed();
        });

        Queue::assertPushed(SendOneTimeCode::class, 1);
    }

    /**
     * The client is the request the guard serves unless one is given: the code
     * request limits count the given client's address.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheClientCanBeGiven(): void
    {
        $this->codeService()->send('phone_code', ['phone' => self::PHONE], new ClientContext('198.51.100.4', 'Kiosk/1.0'));

        self::assertSame(1, self::counterHits('mobile', 'code_request', 'per_ip', '198.51.100.4'));
        self::assertSame(0, self::counterHits('mobile', 'code_request', 'per_ip', self::CLIENT_IP));
    }

    /**
     * A verification code is bound to the identity and its current number in
     * normal form, and its delivery carries the identity.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testSendingAVerificationCodeCarriesTheIdentity(): void
    {
        $identity = self::seedCodeIdentity(verified: false);

        $request = $this->codeService()->sendVerification($identity, 'phone', self::requestClient());

        self::assertTrue($request->isSent());

        Queue::assertPushed(SendOneTimeCode::class, static fn (SendOneTimeCode $job): bool => $identity->is($job->identity)
                && $job->binding->purpose             === CodePurpose::VERIFICATION
                && self::bindingDigest($job->binding) === self::bindingDigest(CodeBinding::verification('mobile', 'phone', self::PHONE, $identity)));
    }

    /**
     * The right verification code verifies the identifier through the verifier,
     * which reports it; the code works once, and nobody is signed in.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheRightCodeVerifiesTheIdentifier(): void
    {
        $identity = self::seedCodeIdentity(verified: false);

        $this->codeService()->sendVerification($identity, 'phone', self::requestClient());
        $this->recordEvents([IdentifierVerified::class, AuthenticationFailed::class]);

        $client = new ClientContext('198.51.100.4', 'Phone/2.0');
        $result = $this->codeService()->verify($identity, 'phone', self::challenge(), self::CODE, $client);

        self::assertSame([VerificationOutcome::VERIFIED, null, true], [$result->outcome, $result->retryAfter, $result->is(VerificationOutcome::VERIFIED)]);
        self::assertTrue($identity->fresh()?->hasVerifiedIdentifier('phone'));
        self::assertSame('198.51.100.4', $this->recordedEvent(IdentifierVerified::class)->context->client->ip);
        self::assertSame(VerificationOutcome::INVALID, $this->codeService()->verify($identity, 'phone', self::challenge(), self::CODE, self::requestClient())->outcome);
        self::assertFalse(Auth::guard('mobile')->check());
        self::assertSame(0, Session::query()->count());
    }

    /**
     * Rows of `[what happens before the check, code, outcome, reason]`.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @return iterable<string, array{0: string, 1: string, 2: \SineMacula\Laravel\Authentication\Codes\Enums\VerificationOutcome, 3: \SineMacula\Laravel\Authentication\Events\Enums\FailureReason}>
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    public static function provideRefusedVerifications(): iterable
    {
        yield from [
            'a wrong code'      => ['nothing', '000000', VerificationOutcome::INVALID, FailureReason::INVALID_CREDENTIALS],
            'a malformed code'  => ['nothing', '1357', VerificationOutcome::INVALID, FailureReason::INVALID_CREDENTIALS],
            'an expired code'   => ['expire', self::CODE, VerificationOutcome::EXPIRED, FailureReason::CODE_EXPIRED],
            'an exhausted code' => ['exhaust', self::CODE, VerificationOutcome::EXHAUSTED, FailureReason::CODE_EXHAUSTED],
            'a changed number'  => ['change', self::CODE, VerificationOutcome::INVALID, FailureReason::INVALID_CREDENTIALS],
            'a removed number'  => ['remove', self::CODE, VerificationOutcome::INVALID, FailureReason::INVALID_CREDENTIALS],
        ];
    }

    /**
     * A verification code that is wrong, malformed, expired or exhausted, or
     * was sent to a number the identity no longer has, verifies nothing: the
     * outcome says why, not concealed, and the reason is reported for the
     * identity and the challenge.
     *
     * @param  string  $before
     * @param  string  $code
     * @param  \SineMacula\Laravel\Authentication\Codes\Enums\VerificationOutcome  $outcome
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\FailureReason  $reason
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideRefusedVerifications')]
    public function testARefusedVerificationReportsWhy(string $before, string $code, VerificationOutcome $outcome, FailureReason $reason): void
    {
        config()->set('authentication.codes.max_attempts', 1);

        $identity = self::seedCodeIdentity(verified: false);

        $this->codeService()->sendVerification($identity, 'phone', self::requestClient());

        match ($before) {
            'expire'  => CarbonImmutable::setTestNow($this->now->addSeconds(600)),
            'exhaust' => $this->codeService()->verify($identity, 'phone', self::challenge(), '000000', self::requestClient())->outcome,
            'change'  => $identity->forceFill(['phone' => '+447700900124'])->save(),
            'remove'  => $identity->forceFill(['phone' => null])->save(),
            default   => null,
        };

        $this->recordEvents([AuthenticationFailed::class, IdentifierVerified::class]);

        $challenge = self::challenge();

        self::assertSame($outcome, $this->codeService()->verify($identity, 'phone', $challenge, $code, self::requestClient())->outcome);

        $failed = $this->recordedEvent(AuthenticationFailed::class);

        self::assertSame([AuthenticationFlow::IDENTIFIER_VERIFICATION, $reason, null, $challenge], [$failed->flow, $failed->reason, $failed->identifier, $failed->challengeId]);
        EventContextAssertions::assertIdentity($identity, $failed->context);
        self::assertCount(1, $this->recorded);
        self::assertFalse($identity->fresh()?->hasVerifiedIdentifier('phone'));
    }

    /**
     * A malformed code is refused without counting against the code, but it
     * takes the identity's slot and the IP address's, and keeps them.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAMalformedVerificationCodeTakesItsSlotsAndCountsNoAttempt(): void
    {
        $identity = self::seedCodeIdentity(verified: false);

        $this->codeService()->sendVerification($identity, 'phone', self::requestClient());
        $this->codeService()->verify($identity, 'phone', self::challenge(), '13579', self::requestClient());

        self::assertSame(0, self::storedAttempts());
        self::assertSame(1, self::counterHits('identifier_verification', 'per_account', AccountAttempts::account($identity)));
        self::assertSame(1, self::counterHits('mobile', 'identifier_verification', 'per_ip', self::requestClient()->ip));
    }

    /**
     * Rows of `[challenge id, code]` a verification check refuses as malformed,
     * and a type the identity has no identifier of, which has no binding to
     * check against.
     *
     * @return iterable<string, array{0: ?string, 1: string, 2: bool}>
     */
    public static function provideUnjudgedVerifications(): iterable
    {
        yield from [
            'a malformed code'      => [null, '13579', true],
            'a malformed challenge' => ['0195F4A2-7B1C-4000-8000-00000000000A', self::CODE, true],
            'an unbound type'       => [null, self::CODE, false],
        ];
    }

    /**
     * Once the identity's checks are used up, a malformed check or one for an
     * unbound type is `rate_limited`, with the wait, not `invalid`: the limit
     * is taken before the input is judged.
     *
     * @param  ?string  $challengeId
     * @param  string  $code
     * @param  bool  $bound
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideUnjudgedVerifications')]
    public function testAMalformedOrUnboundVerificationIsRateLimitedOnceTheLimitIsUsedUp(?string $challengeId, string $code, bool $bound): void
    {
        config()->set('authentication.rate_limits.identifier_verification.per_identifier', ['max' => 1, 'decay_seconds' => 900]);

        $identity = self::seedCodeIdentity(verified: false);

        $this->codeService()->sendVerification($identity, 'phone', self::requestClient());

        if (!$bound) {
            $identity->forceFill(['phone' => null])->save();
        }

        $challenge = $challengeId ?? self::challenge();

        self::assertSame(VerificationOutcome::INVALID, $this->codeService()->verify($identity, 'phone', $challenge, $code, self::requestClient())->outcome);
        self::assertSame(1, self::counterHits('identifier_verification', 'per_account', AccountAttempts::account($identity)));

        $this->recordEvents([AuthenticationFailed::class]);

        $limited = $this->codeService()->verify($identity, 'phone', $challenge, $code, self::requestClient());
        $failed  = $this->recordedEvent(AuthenticationFailed::class);

        self::assertSame([VerificationOutcome::RATE_LIMITED, 900], [$limited->outcome, $limited->retryAfter]);
        self::assertSame([FailureReason::RATE_LIMITED, 900], [$failed->reason, $failed->retryAfter]);
        self::assertSame(0, self::storedAttempts());
    }

    /**
     * A verification code verifies only the identity it was sent for, and a
     * sign-in code verifies nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAVerificationCodeIsBoundToItsIdentityAndPurpose(): void
    {
        $identity = self::seedCodeIdentity(verified: false);
        $other    = self::seedCodeIdentity('+447700900124', 'ben@example.test', verified: false);

        $this->codeService()->send('phone_code', ['phone' => self::PHONE], self::requestClient());

        self::assertSame(VerificationOutcome::INVALID, $this->codeService()->verify($identity, 'phone', self::challenge(), self::CODE, self::requestClient())->outcome);

        $challenge = (string) $this->codeService()->sendVerification($other, 'phone', self::requestClient())->challengeId;

        self::assertSame(VerificationOutcome::INVALID, $this->codeService()->verify($identity, 'phone', $challenge, '246802', self::requestClient())->outcome);
        self::assertSame(VerificationOutcome::VERIFIED, $this->codeService()->verify($other, 'phone', $challenge, '246802', self::requestClient())->outcome);
    }

    /**
     * An identity whose number was verified after the code was sent is told
     * so; the code is used up.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnAlreadyVerifiedIdentifierIsSaidSo(): void
    {
        $identity = self::seedCodeIdentity();

        $this->codeService()->sendVerification($identity, 'phone', self::requestClient());

        self::assertSame(VerificationOutcome::ALREADY_VERIFIED, $this->codeService()->verify($identity, 'phone', self::challenge(), self::CODE, self::requestClient())->outcome);
        self::assertNotNull(DB::table('one_time_codes')->value('consumed_at'));
    }

    /**
     * A right code whose number changed after the identity was loaded is used
     * up and answers `mismatch`: neither number is recorded verified and
     * nothing is reported.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testANumberChangedAfterTheIdentityWasLoadedIsAMismatch(): void
    {
        $identity = self::seedCodeIdentity(verified: false);

        $this->codeService()->sendVerification($identity, 'phone', self::requestClient());

        DB::table('code_identities')->where('id', $identity->getKey())->update(['phone' => '+447700900124']);

        $this->recordEvents([IdentifierVerified::class, AuthenticationFailed::class]);

        self::assertSame(VerificationOutcome::MISMATCH, $this->codeService()->verify($identity, 'phone', self::challenge(), self::CODE, self::requestClient())->outcome);
        self::assertSame([], $this->recorded);
        self::assertNotNull(DB::table('one_time_codes')->value('consumed_at'));
        self::assertNull(DB::table('code_identities')->where('id', $identity->getKey())->value('phone_verified_at'));
        self::assertSame(VerificationOutcome::INVALID, $this->codeService()->verify($identity, 'phone', self::challenge(), self::CODE, self::requestClient())->outcome);
    }

    /**
     * An identity with no number, or one the normaliser refuses, has nothing to
     * verify: `identifier_invalid`, reported with the identity, and nothing
     * counted or issued.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnIdentityWithoutAValidNumberHasNothingToVerify(): void
    {
        $none   = self::seedCodeIdentity(null, 'none@example.test');
        $legacy = self::seedCodeIdentity(null, 'legacy@example.test');

        DB::table('code_identities')->where('id', $legacy->getKey())->update(['phone' => '07700 900123']);

        $this->recordEvents([AuthenticationFailed::class]);

        self::assertSame(CodeRequestStatus::IDENTIFIER_INVALID, $this->codeService()->sendVerification($none, 'phone', new ClientContext('198.51.100.4', 'Kiosk/1.0'))->status);
        self::assertSame(CodeRequestStatus::IDENTIFIER_INVALID, $this->codeService()->sendVerification($legacy, 'phone', self::requestClient())->status);
        $failures = array_values(array_filter($this->recorded, static fn (object $event): bool => $event instanceof AuthenticationFailed));

        $reasons = array_map(static fn (AuthenticationFailed $event): FailureReason => $event->reason, $failures);

        self::assertSame([FailureReason::INVALID_CREDENTIALS, FailureReason::INVALID_CREDENTIALS], $reasons);
        EventContextAssertions::assertIdentity($none, $failures[0]->context);
        self::assertSame(['198.51.100.4', self::CLIENT_IP], [$failures[0]->context->client->ip, $failures[1]->context->client->ip]);
        self::assertSame([0, 0], [DB::table('one_time_codes')->count(), DB::table('rate_limits')->count()]);
    }

    /**
     * Verification requests are held to the code request limits and the resend
     * cooldown like sign-in requests.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testVerificationRequestsAreLimited(): void
    {
        $identity = self::seedCodeIdentity(verified: false);

        self::assertTrue($this->codeService()->sendVerification($identity, 'phone', self::requestClient())->isSent());

        $limited = $this->codeService()->sendVerification($identity, 'phone', self::requestClient());

        self::assertSame([CodeRequestStatus::RATE_LIMITED, 60], [$limited->status, $limited->retryAfter]);
        self::assertSame(2, self::counterHits('mobile', 'code_request', 'per_identifier', self::PHONE));
    }

    /**
     * Rows of `[identity, exception, message]`: identities codes cannot verify.
     *
     * @return iterable<string, array{0: \Closure(): \SineMacula\Laravel\Authentication\Contracts\Identity, 1: class-string<\Throwable>, 2: string}>
     */
    public static function provideUnverifiableIdentities(): iterable
    {
        yield from [
            'a machine identity' => [
                static fn (): MachineClient => new MachineClient,
                \InvalidArgumentException::class,
                MachineClient::class . ' is a machine identity: it has no identifiers to verify by code.',
            ],
            'an identity that cannot verify' => [
                static fn (): IntegrationIdentity => new IntegrationIdentity,
                \LogicException::class,
                IntegrationIdentity::class . ' cannot verify identifiers',
            ],
        ];
    }

    /**
     * Sending or checking a verification code for a machine identity, or one
     * that cannot verify identifiers, is a misconfiguration.
     *
     * @param  \Closure(): \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  class-string<\Throwable>  $exception
     * @param  non-empty-string  $message
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideUnverifiableIdentities')]
    public function testIdentitiesThatCannotBeVerifiedByCodeThrow(\Closure $identity, string $exception, string $message): void
    {
        $calls = [
            fn (): CodeRequest => $this->codeService()->sendVerification($identity(), 'phone', self::requestClient()),
            fn (): mixed => $this->codeService()->verify($identity(), 'phone', self::challenge(), self::CODE, self::requestClient())->outcome,
        ];

        foreach ($calls as $call) {
            try {
                $call();

                self::fail('No exception was thrown.');
            } catch (\Throwable $thrown) {
                self::assertInstanceOf($exception, $thrown);
                self::assertStringStartsWith($message, $thrown->getMessage());
            }
        }
    }

    /**
     * An identifier type that cannot be one is a misconfiguration.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnInvalidTypeThrows(): void
    {
        $identity = self::seedCodeIdentity();

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Identifier type [Phone] must be a lower-case letter');

        $this->codeService()->sendVerification($identity, 'Phone', self::requestClient());
    }

    /**
     * `Auth::codes()` serves the named JWT guard, or the default one, and
     * refuses a guard of another driver.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAuthCodesServesJwtGuardsOnly(): void
    {
        config()->set('auth.defaults.guard', 'mobile');

        $this->freshGuard('mobile');

        self::assertTrue(Auth::codes()->send('phone_code', ['phone' => self::PHONE], self::requestClient())->isSent());

        config()->set('auth.guards.session', ['driver' => 'session', 'provider' => 'code_identities']);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Auth guard [session] is not a jwt guard, so it has no one-time code service.');

        Auth::codes('session');
    }

    /**
     * Rows of `[settings, message start]`: malformed code settings, and a key
     * that cannot be had.
     *
     * @return iterable<string, array{0: array<string, mixed>, 1: string}>
     */
    public static function provideMalformedSettings(): iterable
    {
        yield from [
            'delivery connection not configured' => [['authentication.delivery.queue.connection' => 'missing'], 'authentication.delivery.queue.connection must name a connection'],
            'code length out of range'           => [['authentication.codes.length' => 5], 'authentication.codes.length must be an integer from 6 to 10.'],
            'a code key that is too short'       => [['authentication.codes.key' => 'too-short'], 'authentication.codes.key must be a string of at least 32 bytes'],
            'no code key and no application key' => [['authentication.codes.key' => null, 'app.key' => null], 'One-time codes are keyed with `authentication.codes.key`'],
        ];
    }

    /**
     * A malformed code setting, or a key that cannot be had, fails closed
     * before any code request is counted or any code issued.
     *
     * @param  array<string, mixed>  $settings
     * @param  non-empty-string  $message
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideMalformedSettings')]
    public function testMalformedSettingsFailClosedBeforeAnythingIsCounted(array $settings, string $message): void
    {
        config()->set($settings);

        try {
            $this->codeService()->send('phone_code', ['phone' => self::PHONE], self::requestClient());

            self::fail('A code was sent with malformed settings.');
        } catch (\InvalidArgumentException $exception) {
            self::assertStringStartsWith($message, $exception->getMessage());
        }

        self::assertSame([0, 0], [DB::table('one_time_codes')->count(), DB::table('rate_limits')->count()]);
    }

    /**
     * Rows of `[settings, message start, the factor code call]`: a send reads
     * every setting a delivery needs, and a check the code key.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @return iterable<string, array{0: array<string, mixed>, 1: string, 2: \Closure(\SineMacula\Laravel\Authentication\Codes\CodeService, \SineMacula\Laravel\Authentication\Codes\FactorCodeBinding): mixed}>
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    public static function provideMalformedFactorCodeSettings(): iterable
    {
        $send  = static fn (CodeService $codes, FactorCodeBinding $binding): mixed => $codes->sendFactorCode($binding, self::requestClient());
        $check = static fn (CodeService $codes, FactorCodeBinding $binding): mixed => $codes->verifyFactorCode(
            $binding,
            '0190e1a4-0000-7000-8000-000000000001',
            self::CODE,
            self::requestClient(),
        );

        foreach (self::provideMalformedSettings() as $name => [$settings, $message]) {
            yield 'a send, ' . $name => [$settings, $message, $send];
        }

        foreach (['a code key that is too short', 'no code key and no application key'] as $name) {
            yield 'a check, ' . $name => [...iterator_to_array(self::provideMalformedSettings())[$name], $check];
        }
    }

    /**
     * A malformed setting a factor code needs, or a key that cannot be had,
     * fails a send or a check closed before anything is counted, admitted or
     * issued, with the factor package's counters ready to admit it.
     *
     * @param  array<string, mixed>  $settings
     * @param  non-empty-string  $message
     * @param  \Closure(\SineMacula\Laravel\Authentication\Codes\CodeService, \SineMacula\Laravel\Authentication\Codes\FactorCodeBinding): mixed  $call
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideMalformedFactorCodeSettings')]
    public function testMalformedSettingsFailAFactorCodeClosedBeforeAnythingIsCounted(array $settings, string $message, \Closure $call): void
    {
        $counters = new RecordingFactorCodeCounters;

        app()->instance(FactorCodeCounters::class, $counters);

        $proof   = new ProofBinding(self::seedCodeIdentity(), 'mobile', 'session-1', Purpose::SIGN_IN);
        $binding = new FactorCodeBinding($proof, 'factor-1', new Channel(ChannelKind::SMS, self::PHONE));

        config()->set($settings);

        try {
            $call($this->codeService(), $binding);

            self::fail('A factor code was sent or checked with malformed settings.');
        } catch (\InvalidArgumentException $exception) {
            self::assertStringStartsWith($message, $exception->getMessage());
        }

        self::assertSame([0, 0, [], []], [DB::table('one_time_codes')->count(), DB::table('rate_limits')->count(), $counters->admitted, $counters->reports]);
    }

    /**
     * A request answers the id of the challenge it sent; a resend after the
     * cooldown is the same challenge, with a new code, and keeps it while it
     * lives; once it is used, the next request is a new challenge.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAResendKeepsTheChallenge(): void
    {
        self::seedCodeIdentity();

        $first = $this->codeService()->send('phone_code', ['phone' => self::PHONE], self::requestClient())->challengeId;

        CarbonImmutable::setTestNow($this->now->addSeconds(60));

        $resent = $this->codeService()->send('phone_code', ['phone' => self::PHONE], self::requestClient());

        self::assertIsString($first);
        self::assertMatchesRegularExpression(self::CHALLENGE_PATTERN, $first);
        self::assertSame($first, $resent->challengeId);
        self::assertTrue(
            $this->sessions('mobile')->signIn('phone_code', ['phone' => self::PHONE, 'challenge' => $first, 'code' => '246802'], self::requestContext())->isSignedIn(),
        );

        CarbonImmutable::setTestNow($this->now->addSeconds(120));

        self::assertNotSame($first, $this->codeService()->send('phone_code', ['phone' => self::PHONE], self::requestClient())->challengeId);
    }

    /**
     * Once a number's delivery window has had all its deliveries, a request is
     * refused until the window ends, answered with the wait and reported as
     * `deliveries_exhausted` on the `code_request` flow, for a number no one
     * has exactly as for a known one.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testADestinationOutOfDeliveriesIsRefusedUntilItsWindowEnds(): void
    {
        config()->set('authentication.codes.max_deliveries', 1);

        self::seedCodeIdentity();

        foreach ([self::PHONE, self::UNKNOWN_PHONE] as $phone) {
            CarbonImmutable::setTestNow($this->now);

            self::assertTrue($this->codeService()->send('phone_code', ['phone' => $phone], self::requestClient())->isSent());

            CarbonImmutable::setTestNow($this->now->addSeconds(60));

            $this->recordEvents([AuthenticationFailed::class]);

            $request = $this->codeService()->send('phone_code', ['phone' => $phone], self::requestClient());
            $failed  = $this->recordedEvent(AuthenticationFailed::class);

            self::assertSame([CodeRequestStatus::DELIVERIES_EXHAUSTED, 1740, null], [$request->status, $request->retryAfter, $request->challengeId]);
            self::assertSame(
                [AuthenticationFlow::CODE_REQUEST, FailureReason::DELIVERIES_EXHAUSTED, 1740, $phone],
                [$failed->flow, $failed->reason, $failed->retryAfter, $failed->identifier],
            );
        }

        Queue::assertPushed(SendOneTimeCode::class, 2);
    }

    /**
     * A verification check names its challenge: a malformed id is `invalid`,
     * counts no attempt and is never reported as a challenge; another
     * challenge's id is `invalid`, spends no attempt on the live one and is
     * reported as the challenge the check answered.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAVerificationNamesItsChallenge(): void
    {
        $identity  = self::seedCodeIdentity(verified: false);
        $challenge = (string) $this->codeService()->sendVerification($identity, 'phone', self::requestClient())->challengeId;

        $this->recordEvents([AuthenticationFailed::class]);

        self::assertSame(VerificationOutcome::INVALID, $this->codeService()->verify($identity, 'phone', strtoupper($challenge), self::CODE, self::requestClient())->outcome);
        self::assertSame(1, self::counterHits('identifier_verification', 'per_account', AccountAttempts::account($identity)));
        self::assertNull($this->recordedEvent(AuthenticationFailed::class)->challengeId);

        $this->recordEvents([AuthenticationFailed::class]);

        self::assertSame(VerificationOutcome::INVALID, $this->codeService()->verify($identity, 'phone', self::NO_CHALLENGE, self::CODE, self::requestClient())->outcome);
        self::assertSame(self::NO_CHALLENGE, $this->recordedEvent(AuthenticationFailed::class)->challengeId);
        self::assertSame(0, self::storedAttempts());
        self::assertSame(VerificationOutcome::VERIFIED, $this->codeService()->verify($identity, 'phone', $challenge, self::CODE, self::requestClient())->outcome);
    }

    /**
     * A verification check counts against the identity's account and the IP
     * address (`identifier_verification`): a wrong code keeps its slots, a
     * correct one gives them back, and an identity out of checks is answered
     * `rate_limited`, reported with the wait, before its code is touched (the
     * code keeps the two attempts the earlier checks spent).
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAVerificationIsLimitedPerIdentityAndIp(): void
    {
        config()->set('authentication.rate_limits.identifier_verification.per_identifier', ['max' => 2, 'decay_seconds' => 900]);

        $identity  = self::seedCodeIdentity(verified: false);
        $client    = new ClientContext('203.0.113.7', 'Phone/1.0');
        $challenge = (string) $this->codeService()->sendVerification($identity, 'phone', self::requestClient())->challengeId;
        $account   = AccountAttempts::account($identity);

        self::assertSame(VerificationOutcome::INVALID, $this->codeService()->verify($identity, 'phone', $challenge, '000000', $client)->outcome);
        self::assertSame(
            [1, 1],
            [self::counterHits('identifier_verification', 'per_account', $account), self::counterHits('mobile', 'identifier_verification', 'per_ip', '203.0.113.7')],
        );
        self::assertSame(VerificationOutcome::VERIFIED, $this->codeService()->verify($identity, 'phone', $challenge, self::CODE, $client)->outcome);
        self::assertSame(
            [1, 1],
            [self::counterHits('identifier_verification', 'per_account', $account), self::counterHits('mobile', 'identifier_verification', 'per_ip', '203.0.113.7')],
        );

        self::assertSame(VerificationOutcome::INVALID, $this->codeService()->verify($identity, 'phone', $challenge, '000000', $client)->outcome);

        $this->recordEvents([AuthenticationFailed::class]);

        $limited = $this->codeService()->verify($identity, 'phone', $challenge, '000000', $client);
        $failed  = $this->recordedEvent(AuthenticationFailed::class);

        self::assertSame([VerificationOutcome::RATE_LIMITED, false], [$limited->outcome, $limited->is(VerificationOutcome::VERIFIED)]);
        self::assertSame([AuthenticationFlow::IDENTIFIER_VERIFICATION, FailureReason::RATE_LIMITED, $challenge], [$failed->flow, $failed->reason, $failed->challengeId]);
        self::assertGreaterThan(0, $failed->retryAfter);
        self::assertSame($failed->retryAfter, $limited->retryAfter);
        self::assertSame(2, self::storedAttempts());
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
}
