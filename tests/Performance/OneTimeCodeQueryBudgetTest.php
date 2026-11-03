<?php

declare(strict_types = 1);

namespace Tests\Performance;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Queue;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Codes\CodeRequest;
use SineMacula\Laravel\Authentication\Codes\CodeService;
use SineMacula\Laravel\Authentication\Codes\CodeSignIn;
use SineMacula\Laravel\Authentication\Codes\Enums\VerificationOutcome;
use SineMacula\Laravel\Authentication\Codes\FactorCodeBinding;
use SineMacula\Laravel\Authentication\Codes\FactorCodeCheck;
use SineMacula\Laravel\Authentication\Codes\OneTimeCodes;
use SineMacula\Laravel\Authentication\Codes\SendOneTimeCode;
use SineMacula\Laravel\Authentication\Contracts\FactorCodeCounters;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Proofs\Channel;
use SineMacula\Laravel\Authentication\Proofs\Enums\ChannelKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\Purpose;
use SineMacula\Laravel\Authentication\Proofs\ProofBinding;
use SineMacula\Laravel\Authentication\Sessions\SignInResult;
use SineMacula\Laravel\Authentication\Testing\FakeOneTimeCodeSender;
use Tests\Concerns\InteractsWithCodeIdentities;
use Tests\Fixtures\Codes\RecordingFactorCodeCounters;

/**
 * Query-budget contracts for one-time codes: a code request writes its limits
 * and one or two code statements and reads no identity at all; a sign-in by
 * code reads the identity and the code once each; a delivery reads the code and
 * the recipient once each; a verification by code reads the code once.
 *
 * A code request reserves a slot on the number's and the IP address's code
 * request counters (on a fresh window, for each, an update that changes nothing
 * and the insert that creates the counter; later in the window, one update
 * each), never given back. A sign-in by code reserves the sign-in counters as a
 * password sign-in does, the account's included, and gives them back when it
 * succeeds.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CodeService::class)]
#[CoversClass(CodeSignIn::class)]
#[CoversClass(OneTimeCodes::class)]
#[CoversClass(SendOneTimeCode::class)]
final class OneTimeCodeQueryBudgetTest extends PerformanceContractTestCase
{
    use InteractsWithCodeIdentities;

    /** @var string The code the engine issues first. */
    private const string CODE = '135790';

    /** @var list<string> Every statement run since recording began. */
    private array $statements = [];

    /**
     * Freeze the immutable clock with the performance clock, create the table,
     * issue known codes and record every statement.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        CarbonImmutable::setTestNow(CarbonImmutable::instance($this->now));

        self::createCodeIdentitiesTable();
        self::issueCodes([self::CODE, '246802', '975310']);

        DB::listen(function (QueryExecuted $query): void {
            $this->statements[] = $query->sql;
        });
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
     * A first code request writes four limiter statements, reads the code's
     * row, which it finds missing, and inserts it; a request after the cooldown
     * in the same window writes the two counters, reads the row and resends the
     * challenge in one update. Neither touches an identity.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACodeRequestWritesItsLimitsAndTheCodeAndReadsNoIdentity(): void
    {
        self::seedCodeIdentity();

        $codes = $this->codeService();

        $this->statements = [];

        self::assertTrue($this->assertQueryBudget(1, 5, static fn (): CodeRequest => $codes->send('phone_code', ['phone' => self::PHONE]))->isSent());

        CarbonImmutable::setTestNow(CarbonImmutable::instance($this->now)->addSeconds(60));

        self::assertTrue($this->assertQueryBudget(1, 3, static fn (): CodeRequest => $codes->send('phone_code', ['phone' => self::PHONE]))->isSent());
        self::assertSame([], array_filter($this->statements, static fn (string $sql): bool => str_contains($sql, 'code_identities')));
    }

    /**
     * A request within the cooldown writes its two counters and reads the code
     * once, which says how long to wait, writing nothing to it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARequestWithinTheCooldownReadsTheCodeOnce(): void
    {
        $codes = $this->codeService();

        $codes->send('phone_code', ['phone' => self::PHONE]);

        self::assertSame(60, $this->assertQueryBudget(1, 2, static fn (): CodeRequest => $codes->send('phone_code', ['phone' => self::PHONE]))->retryAfter);
    }

    /**
     * A sign-in by code reads the identity, the code and the new session's
     * proofs once each, and what an earlier session left under the new key in
     * the proofs and the provenance (nothing, so nothing is deleted); it writes
     * the sign-in and account reservations, the code's attempt and its use, the
     * session and its first proof, and gives the three slots back.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASignInByCodeReadsTheIdentityTheCodeAndTheProofsOnce(): void
    {
        self::seedCodeIdentity();

        $challenge = $this->codeService()->send('phone_code', ['phone' => self::PHONE])->challengeId;

        $sessions = $this->sessions('mobile');

        $signIn = static fn (): SignInResult => $sessions->signIn('phone_code', ['phone' => self::PHONE, 'challenge' => $challenge, 'code' => self::CODE]);

        self::assertTrue($this->assertQueryBudget(5, 13, $signIn)->isSignedIn());
    }

    /**
     * An email code costs what a phone code does: the request writes its limits
     * and the code, reads the code's row and no identity, and the sign-in reads
     * the identity, the code and the session's proofs once each.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnEmailCodeCostsWhatAPhoneCodeDoes(): void
    {
        self::seedCodeIdentity();

        $codes = $this->codeService();

        $this->statements = [];

        $challenge = $this->assertQueryBudget(1, 5, static fn (): CodeRequest => $codes->send('email_code', ['email' => ' Ada@Example.test']))->challengeId;

        self::assertSame([], array_filter($this->statements, static fn (string $sql): bool => str_contains($sql, 'code_identities')));

        $sessions = $this->sessions('mobile');
        $signIn   = static fn (): SignInResult => $sessions->signIn('email_code', ['email' => 'ada@example.test', 'challenge' => $challenge, 'code' => self::CODE]);

        self::assertTrue($this->assertQueryBudget(5, 13, $signIn)->isSignedIn());
    }

    /**
     * A wrong code reads the identity and the code once each and writes the
     * reservations and the attempt; a malformed one reads nothing but the
     * limits and counts nothing against the code.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFailedSignInByCodeWritesOnlyItsLimitsAndTheAttempt(): void
    {
        self::seedCodeIdentity();

        $challenge = $this->codeService()->send('phone_code', ['phone' => self::PHONE])->challengeId;

        $sessions = $this->sessions('mobile');

        $wrong     = static fn (): SignInResult => $sessions->signIn('phone_code', ['phone' => self::PHONE, 'challenge' => $challenge, 'code' => '000000']);
        $malformed = static fn (): SignInResult => $sessions->signIn('phone_code', ['phone' => self::PHONE, 'challenge' => $challenge, 'code' => '0000']);

        self::assertSame(FailureReason::INVALID_CREDENTIALS, $this->assertQueryBudget(2, 7, $wrong)->reason);
        self::assertSame(FailureReason::INVALID_CREDENTIALS, $this->assertQueryBudget(0, 2, $malformed)->reason);
    }

    /**
     * A delivery reads the code and the recipient once each, and writes
     * nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testADeliveryReadsTheCodeAndTheRecipientOnce(): void
    {
        config()->set('queue.default', 'database');
        config()->set('queue.connections.database', ['driver' => 'database']);

        Queue::fake();

        self::seedCodeIdentity();

        $this->codeService()->send('phone_code', ['phone' => self::PHONE]);

        $sender = FakeOneTimeCodeSender::fake($this->app);
        $job    = Queue::pushed(SendOneTimeCode::class)->sole();

        self::assertInstanceOf(SendOneTimeCode::class, $job);

        $this->assertQueryBudget(2, 0, static function () use ($job): void {
            $job->handle(app());
        });

        self::assertSame(1, $sender->count());
    }

    /**
     * Checking a verification code counts against the identity's account and
     * the IP address, reads the code once and writes its attempt and its use,
     * gives the two counts back, then the verifier's locked read and record.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAVerificationByCodeReadsTheCodeOnce(): void
    {
        $identity = self::seedCodeIdentity(verified: false);
        $codes    = $this->codeService();

        $challenge = (string) $codes->sendVerification($identity, 'phone')->challengeId;

        self::assertSame(VerificationOutcome::VERIFIED, $this->assertQueryBudget(2, 9, static fn (): mixed => $codes->verify($identity, 'phone', $challenge, self::CODE)->outcome));
    }

    /**
     * A factor code's first request writes its three `code_request` counters
     * (destination, owner, IP address), reads the challenge's row and inserts
     * it; its check writes the IP counter, reads the row once, locked, counts
     * the attempt, uses the challenge up and gives the IP slot back. The factor
     * package's counters, which run no query here, are asked and told inside
     * that budget.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFactorCodeHasAFixedBudget(): void
    {
        $identity = self::seedCodeIdentity();
        $codes    = $this->codeService();
        $binding  = new FactorCodeBinding(new ProofBinding($identity, 'mobile', 'session-1', Purpose::SIGN_IN), 'factor-1', new Channel(ChannelKind::SMS, '+447700900555'));

        $this->app?->instance(FactorCodeCounters::class, new RecordingFactorCodeCounters);

        $challenge = (string) $this->assertQueryBudget(1, 7, static fn (): CodeRequest => $codes->sendFactorCode($binding))->challengeId;

        self::assertTrue($this->assertQueryBudget(1, 5, static fn (): FactorCodeCheck => $codes->verifyFactorCode($binding, $challenge, self::CODE))->isVerified());
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
