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
use SineMacula\Laravel\Authentication\Codes\SendOneTimeCode;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\Enums\AuthenticationFlow;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\IdentifierVerified;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Models\Device;
use SineMacula\Laravel\Authentication\Verification\Enums\IdentifierVerification;
use Tests\Concerns\InteractsWithCodeIdentities;
use Tests\Concerns\InteractsWithRateLimits;
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
     * says when the code expires; nothing is reported as failed.
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

        $request = $this->codeService()->send('phone_code', ['phone' => ' ' . self::PHONE]);

        self::assertSame([CodeRequestStatus::SENT, null], [$request->status, $request->retryAfter]);
        self::assertTrue($this->now->addSeconds(600)->equalTo($request->expiresAt));

        Queue::assertPushedOn('codes', SendOneTimeCode::class, static fn (SendOneTimeCode $job): bool => $job->connection === 'deliveries'
                && $job->identity                                                                                         === null
                && $job->binding->purpose                                                                                 === CodePurpose::SIGN_IN
                && [$job->binding->guard, $job->binding->type, $job->binding->identifier]                                 === ['mobile', 'phone', self::PHONE]
                && $job->issued->code                                                                                     === self::CODE
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

        $known   = $this->codeService()->send('phone_code', ['phone' => self::PHONE]);
        $unknown = $this->codeService()->send('phone_code', ['phone' => self::UNKNOWN_PHONE]);

        self::assertEquals($known, $unknown);

        Queue::assertPushed(SendOneTimeCode::class, 2);
    }

    /**
     * A guard that does not allow the method refuses the request before
     * anything is counted or issued, and reports it with the number as given.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAGuardThatDoesNotAllowTheMethodRefuses(): void
    {
        $this->recordEvents([AuthenticationFailed::class]);

        $request = $this->codeService('web')->send('phone_code', ['phone' => self::PHONE]);
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

        $request = $this->codeService()->send('phone_code', $input);
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
            $this->codeService()->send('password', ['email' => 'ada@example.test']);

            self::fail('A password method sent a code.');
        } catch (\InvalidArgumentException $exception) {
            self::assertSame('Sign-in method [password] does not sign in with one-time codes.', $exception->getMessage());
        }

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Sign-in method [sms_code] is not registered.');

        $this->codeService()->send('sms_code', ['phone' => self::PHONE]);
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
        $this->codeService()->send('phone_code', ['phone' => self::PHONE]);

        CarbonImmutable::setTestNow($this->now->addSeconds(25));

        $this->recordEvents([AuthenticationFailed::class]);

        $request = $this->codeService()->send('phone_code', ['phone' => self::PHONE]);
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

        self::assertTrue($this->codeService()->send('phone_code', ['phone' => self::PHONE])->isSent());
        self::assertTrue($this->codeService()->send('phone_code', ['phone' => ' ' . self::PHONE])->isSent());

        $limited = $this->codeService()->send('phone_code', ['phone' => self::PHONE]);

        self::assertSame([CodeRequestStatus::RATE_LIMITED, 3600], [$limited->status, $limited->retryAfter]);
        self::assertSame(2, self::counterHits('mobile', 'code_request', 'per_identifier', self::PHONE));
        self::assertTrue($this->codeService()->send('phone_code', ['phone' => self::UNKNOWN_PHONE])->isSent());
        self::assertSame(CodeRequestStatus::RATE_LIMITED, $this->codeService()->send('phone_code', ['phone' => '+447700900555'])->status);
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

        $this->codeService()->send('phone_code', ['phone' => self::PHONE]);

        Queue::assertNothingPushed();

        DB::rollBack();

        Queue::assertNothingPushed();
        self::assertSame(0, DB::table('one_time_codes')->count());

        DB::transaction(function (): void {
            $this->codeService()->send('phone_code', ['phone' => self::PHONE]);

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

        $request = $this->codeService()->sendVerification($identity, 'phone');

        self::assertTrue($request->isSent());

        Queue::assertPushed(SendOneTimeCode::class, static fn (SendOneTimeCode $job): bool => $identity->is($job->identity)
                && $job->binding->purpose             === CodePurpose::VERIFY_IDENTIFIER
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

        $this->codeService()->sendVerification($identity, 'phone');
        $this->recordEvents([IdentifierVerified::class, AuthenticationFailed::class]);

        $client = new ClientContext('198.51.100.4', 'Phone/2.0');
        $result = $this->codeService()->verify($identity, 'phone', self::CODE, $client);

        self::assertSame(IdentifierVerification::VERIFIED, $result);
        self::assertTrue($identity->fresh()?->hasVerifiedIdentifier('phone'));
        self::assertSame('198.51.100.4', $this->recordedEvent(IdentifierVerified::class)->context->client->ip);
        self::assertSame(FailureReason::INVALID_CREDENTIALS, $this->codeService()->verify($identity, 'phone', self::CODE));
        self::assertFalse(Auth::guard('mobile')->check());
        self::assertSame(0, Device::query()->count());
    }

    /**
     * Rows of `[what happens before the check, code, reason]`.
     *
     * @return iterable<string, array{0: string, 1: string, 2: \SineMacula\Laravel\Authentication\Events\Enums\FailureReason}>
     */
    public static function provideRefusedVerifications(): iterable
    {
        yield from [
            'a wrong code'      => ['nothing', '000000', FailureReason::INVALID_CREDENTIALS],
            'a malformed code'  => ['nothing', '1357', FailureReason::INVALID_CREDENTIALS],
            'an expired code'   => ['expire', self::CODE, FailureReason::CODE_EXPIRED],
            'an exhausted code' => ['exhaust', self::CODE, FailureReason::CODE_EXHAUSTED],
            'a changed number'  => ['change', self::CODE, FailureReason::INVALID_CREDENTIALS],
            'a removed number'  => ['remove', self::CODE, FailureReason::INVALID_CREDENTIALS],
        ];
    }

    /**
     * A verification code that is wrong, malformed, expired or exhausted, or
     * was sent to a number the identity no longer has, verifies nothing: the
     * reason is returned, not concealed, and reported for the identity.
     *
     * @param  string  $before
     * @param  string  $code
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\FailureReason  $reason
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideRefusedVerifications')]
    public function testARefusedVerificationReportsWhy(string $before, string $code, FailureReason $reason): void
    {
        config()->set('authentication.codes.max_attempts', 1);

        $identity = self::seedCodeIdentity(verified: false);

        $this->codeService()->sendVerification($identity, 'phone');

        match ($before) {
            'expire'  => CarbonImmutable::setTestNow($this->now->addSeconds(600)),
            'exhaust' => $this->codeService()->verify($identity, 'phone', '000000'),
            'change'  => $identity->forceFill(['phone' => '+447700900124'])->save(),
            'remove'  => $identity->forceFill(['phone' => null])->save(),
            default   => null,
        };

        $this->recordEvents([AuthenticationFailed::class, IdentifierVerified::class]);

        self::assertSame($reason, $this->codeService()->verify($identity, 'phone', $code));

        $failed = $this->recordedEvent(AuthenticationFailed::class);

        self::assertSame([AuthenticationFlow::IDENTIFIER_VERIFICATION, $reason, null], [$failed->flow, $failed->reason, $failed->identifier]);
        self::assertTrue($identity->is($failed->context->identity));
        self::assertCount(1, $this->recorded);
        self::assertFalse($identity->fresh()?->hasVerifiedIdentifier('phone'));
    }

    /**
     * A malformed code is refused without counting against the code.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAMalformedVerificationCodeCountsNothing(): void
    {
        $identity = self::seedCodeIdentity(verified: false);

        $this->codeService()->sendVerification($identity, 'phone');
        $this->codeService()->verify($identity, 'phone', '13579');

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

        $this->codeService()->send('phone_code', ['phone' => self::PHONE]);

        self::assertSame(FailureReason::INVALID_CREDENTIALS, $this->codeService()->verify($identity, 'phone', self::CODE));

        $this->codeService()->sendVerification($other, 'phone');

        self::assertSame(FailureReason::INVALID_CREDENTIALS, $this->codeService()->verify($identity, 'phone', '246802'));
        self::assertSame(IdentifierVerification::VERIFIED, $this->codeService()->verify($other, 'phone', '246802'));
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

        $this->codeService()->sendVerification($identity, 'phone');

        self::assertSame(IdentifierVerification::ALREADY_VERIFIED, $this->codeService()->verify($identity, 'phone', self::CODE));
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

        $this->codeService()->sendVerification($identity, 'phone');

        DB::table('code_identities')->where('id', $identity->getKey())->update(['phone' => '+447700900124']);

        $this->recordEvents([IdentifierVerified::class, AuthenticationFailed::class]);

        self::assertSame(IdentifierVerification::MISMATCH, $this->codeService()->verify($identity, 'phone', self::CODE));
        self::assertSame([], $this->recorded);
        self::assertNotNull(DB::table('one_time_codes')->value('consumed_at'));
        self::assertNull(DB::table('code_identities')->where('id', $identity->getKey())->value('phone_verified_at'));
        self::assertSame(FailureReason::INVALID_CREDENTIALS, $this->codeService()->verify($identity, 'phone', self::CODE));
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
        self::assertSame(CodeRequestStatus::IDENTIFIER_INVALID, $this->codeService()->sendVerification($legacy, 'phone')->status);
        $failures = array_values(array_filter($this->recorded, static fn (object $event): bool => $event instanceof AuthenticationFailed));

        $reasons = array_map(static fn (AuthenticationFailed $event): FailureReason => $event->reason, $failures);

        self::assertSame([FailureReason::INVALID_CREDENTIALS, FailureReason::INVALID_CREDENTIALS], $reasons);
        self::assertTrue($none->is($failures[0]->context->identity));
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

        self::assertTrue($this->codeService()->sendVerification($identity, 'phone')->isSent());

        $limited = $this->codeService()->sendVerification($identity, 'phone');

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
     * @param  string  $message
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideUnverifiableIdentities')]
    public function testIdentitiesThatCannotBeVerifiedByCodeThrow(\Closure $identity, string $exception, string $message): void
    {
        $calls = [
            fn (): CodeRequest => $this->codeService()->sendVerification($identity(), 'phone'),
            fn (): mixed => $this->codeService()->verify($identity(), 'phone', self::CODE),
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

        $this->codeService()->sendVerification($identity, 'Phone');
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

        self::assertTrue(Auth::codes()->send('phone_code', ['phone' => self::PHONE])->isSent());

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
     * @param  string  $message
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideMalformedSettings')]
    public function testMalformedSettingsFailClosedBeforeAnythingIsCounted(array $settings, string $message): void
    {
        config()->set($settings);

        try {
            $this->codeService()->send('phone_code', ['phone' => self::PHONE]);

            self::fail('A code was sent with malformed settings.');
        } catch (\InvalidArgumentException $exception) {
            self::assertStringStartsWith($message, $exception->getMessage());
        }

        self::assertSame([0, 0], [DB::table('one_time_codes')->count(), DB::table('rate_limits')->count()]);
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
