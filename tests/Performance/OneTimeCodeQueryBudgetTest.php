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
use SineMacula\Laravel\Authentication\Codes\OneTimeCodes;
use SineMacula\Laravel\Authentication\Codes\SendOneTimeCode;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Sessions\SignInResult;
use SineMacula\Laravel\Authentication\Testing\FakeOneTimeCodeSender;
use SineMacula\Laravel\Authentication\Verification\Enums\IdentifierVerification;
use Tests\Concerns\InteractsWithCodeIdentities;

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
     * A first code request writes four limiter statements and the code's failed
     * update and its insert, and reads nothing; a request after the cooldown in
     * the same window writes the two counters and replaces the code in one
     * update. Neither touches an identity.
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

        self::assertTrue($this->assertQueryBudget(0, 6, static fn (): CodeRequest => $codes->send('phone_code', ['phone' => self::PHONE]))->isSent());

        CarbonImmutable::setTestNow(CarbonImmutable::instance($this->now)->addSeconds(60));

        self::assertTrue($this->assertQueryBudget(0, 3, static fn (): CodeRequest => $codes->send('phone_code', ['phone' => self::PHONE]))->isSent());
        self::assertSame([], array_filter($this->statements, static fn (string $sql): bool => str_contains($sql, 'code_identities')));
    }

    /**
     * A request within the cooldown writes its two counters, tries the code's
     * update and insert, and reads the code once to say how long to wait.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARequestWithinTheCooldownReadsTheCodeOnce(): void
    {
        $codes = $this->codeService();

        $codes->send('phone_code', ['phone' => self::PHONE]);

        self::assertSame(60, $this->assertQueryBudget(1, 4, static fn (): CodeRequest => $codes->send('phone_code', ['phone' => self::PHONE]))->retryAfter);
    }

    /**
     * A sign-in by code reads the identity and the code once each; it writes
     * the sign-in and account reservations, the code's attempt and its use, the
     * device, and gives the three slots back.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASignInByCodeReadsTheIdentityAndTheCodeOnce(): void
    {
        self::seedCodeIdentity();

        $this->codeService()->send('phone_code', ['phone' => self::PHONE]);

        $sessions = $this->sessions('mobile');

        $signIn = static fn (): SignInResult => $sessions->signIn('phone_code', ['phone' => self::PHONE, 'code' => self::CODE]);

        self::assertTrue($this->assertQueryBudget(2, 12, $signIn)->isSignedIn());
    }

    /**
     * An email code costs what a phone code does: the request writes its limits
     * and the code and reads no identity, and the sign-in reads the identity
     * and the code once each.
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

        self::assertTrue($this->assertQueryBudget(0, 6, static fn (): CodeRequest => $codes->send('email_code', ['email' => ' Ada@Example.test']))->isSent());
        self::assertSame([], array_filter($this->statements, static fn (string $sql): bool => str_contains($sql, 'code_identities')));

        $sessions = $this->sessions('mobile');
        $signIn   = static fn (): SignInResult => $sessions->signIn('email_code', ['email' => 'ada@example.test', 'code' => self::CODE]);

        self::assertTrue($this->assertQueryBudget(2, 12, $signIn)->isSignedIn());
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

        $this->codeService()->send('phone_code', ['phone' => self::PHONE]);

        $sessions = $this->sessions('mobile');

        $wrong     = static fn (): SignInResult => $sessions->signIn('phone_code', ['phone' => self::PHONE, 'code' => '000000']);
        $malformed = static fn (): SignInResult => $sessions->signIn('phone_code', ['phone' => self::PHONE, 'code' => '0000']);

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
     * Checking a verification code reads the code once and writes its attempt
     * and its use, then the verifier's locked read and record.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAVerificationByCodeReadsTheCodeOnce(): void
    {
        $identity = self::seedCodeIdentity(verified: false);
        $codes    = $this->codeService();

        $codes->sendVerification($identity, 'phone');

        self::assertSame(IdentifierVerification::VERIFIED, $this->assertQueryBudget(2, 3, static fn (): mixed => $codes->verify($identity, 'phone', self::CODE)));
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
