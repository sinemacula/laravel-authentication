<?php

declare(strict_types = 1);

namespace Tests\Performance;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Passkeys\CeremonyOptions;
use SineMacula\Laravel\Authentication\Passkeys\PasskeyAssertions;
use SineMacula\Laravel\Authentication\Passkeys\PasskeyService;
use SineMacula\Laravel\Authentication\Passkeys\PasskeySignIn;
use SineMacula\Laravel\Authentication\Sessions\SignInResult;
use Tests\Concerns\InteractsWithPasskeys;
use Tests\Concerns\InteractsWithSessions;
use Tests\Fixtures\Passkeys\VirtualAuthenticator;

/**
 * Query-budget and timing contracts for passkey ceremonies.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PasskeyService::class)]
#[CoversClass(PasskeySignIn::class)]
#[CoversClass(PasskeyAssertions::class)]
final class PasskeyQueryBudgetTest extends PerformanceContractTestCase
{
    use InteractsWithPasskeys, InteractsWithSessions;

    /** @var int Timebox for the timing contracts, in microseconds. */
    private const int TIMEBOX_MICROSECONDS = 200000;

    /**
     * Create the tables.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->createSessionTables();
    }

    /**
     * Drop the tables.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $this->dropSessionTables();

        parent::tearDown();
    }

    /**
     * A registration reads its challenge once and writes twice.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARegistrationReadsTheChallengeOnceAndWritesTwice(): void
    {
        $identity = $this->seedIdentity();
        $passkeys = Auth::passkeys('api');

        $options = $this->assertQueryBudget(1, 1, static fn (): CeremonyOptions => $passkeys->registrationOptions($identity, self::USER_NAME));
        $answer  = $this->authenticator()->create($options->options);

        self::assertTrue(
            $this->assertQueryBudget(2, 2, static fn (): mixed => $passkeys->register($identity, $options->challengeId, $answer, self::requestClient()))->isRegistered(),
        );
    }

    /**
     * Sign-in options reserve a slot on the client's IP counter and write the
     * challenge, without a read: two writes for a fresh counter, then one.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testSignInOptionsWriteTheirLimitAndTheChallengeOnly(): void
    {
        $this->freshGuard();

        $passkeys = Auth::passkeys('api');

        $this->assertQueryBudget(0, 3, static fn (): CeremonyOptions => $passkeys->signInOptions(self::requestClient()));
        $this->assertQueryBudget(0, 2, static fn (): CeremonyOptions => $passkeys->signInOptions(self::requestClient()));
    }

    /**
     * A passkey sign-in reads seven times and writes its challenge's delete,
     * the count, the session, its proof and its limits.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPasskeySignInReadsSevenTimes(): void
    {
        $this->registerPasskey($this->seedIdentity());

        $options  = $this->signInOptions();
        $input    = ['challenge' => $options->challengeId, 'credential' => $this->authenticator()->get($options->options)];
        $sessions = $this->sessions();

        self::assertTrue($this->assertQueryBudget(7, 10, static fn (): SignInResult => $sessions->signIn('passkey', $input, self::requestContext()))->isSignedIn());
    }

    /**
     * A factor ceremony reads twice and writes twice.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFactorReadsTwiceAndWritesTwice(): void
    {
        $identity = $this->seedIdentity();

        $this->registerPasskey($identity);

        $passkeys = Auth::passkeys('api');
        $ids      = [$this->authenticator()->lastCredentialId()];
        $options  = $this->assertQueryBudget(1, 1, static fn (): ?CeremonyOptions => $passkeys->factorOptions($identity, self::factorBinding($identity), $ids));

        self::assertNotNull($options);

        $answer = $this->authenticator()->get($options->options);

        $binding = self::factorBinding($identity);

        self::assertTrue(
            $this->assertQueryBudget(
                2,
                2,
                static fn (): mixed => $passkeys->verifyFactor($identity, $binding, $options->challengeId, $answer, self::requestClient()),
            )->isVerified(),
        );
    }

    /**
     * Listing reads once; removing reads the passkey to check its owner, then
     * writes once.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testListingReadsOnceAndRemovingReadsAndWritesOnce(): void
    {
        $identity = $this->seedIdentity();
        $passkey  = $this->registerPasskey($identity);
        $passkeys = Auth::passkeys('api');

        self::assertCount(1, $this->assertQueryBudget(1, 0, static fn (): array => $passkeys->passkeys($identity)));
        self::assertTrue($this->assertQueryBudget(1, 1, static fn (): bool => $passkeys->remove($identity, $passkey->id, self::requestClient())->isRemoved()));
    }

    /**
     * A failed passkey sign-in waits out the timebox whether the passkey is
     * unknown or forged.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFailedPasskeySignInWaitsOutTheTimebox(): void
    {
        $this->registerPasskey($this->seedIdentity());

        app(ConfigRepository::class)->set('authentication.timebox.credentials_microseconds', self::TIMEBOX_MICROSECONDS);

        $stranger = new VirtualAuthenticator(self::ORIGIN);

        $stranger->create(['rp' => ['id' => self::RP_ID], 'user' => ['id' => VirtualAuthenticator::encode('handle')], 'challenge' => 'challenge']);

        foreach ([$stranger, $this->authenticator()] as $authenticator) {

            $options  = $this->signInOptions();
            $answer   = $authenticator->get($options->options);
            $response = (array) $answer['response'];
            $input    = ['challenge' => $options->challengeId, 'credential' => ['response' => ['signature' => VirtualAuthenticator::encode('forged')] + $response] + $answer];
            $sessions = $this->sessions();
            $started  = hrtime(true);

            self::assertTrue($sessions->signIn('passkey', $input, self::requestContext())->isFailed());
            self::assertGreaterThanOrEqual(self::TIMEBOX_MICROSECONDS * 1000, hrtime(true) - $started);
        }
    }

    /**
     * A successful passkey sign-in returns before the timebox.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASuccessfulPasskeySignInReturnsBeforeTheTimebox(): void
    {
        $this->registerPasskey($this->seedIdentity());

        app(ConfigRepository::class)->set('authentication.timebox.credentials_microseconds', self::TIMEBOX_MICROSECONDS);

        $fastest = PHP_INT_MAX;

        for ($sample = 0; $sample < 3; $sample++) {

            $options  = $this->signInOptions();
            $input    = ['challenge' => $options->challengeId, 'credential' => $this->authenticator()->get($options->options)];
            $sessions = $this->sessions();
            $started  = hrtime(true);

            self::assertTrue($sessions->signIn('passkey', $input, self::requestContext())->isSignedIn());

            $fastest = min($fastest, hrtime(true) - $started);
        }

        self::assertLessThan(self::TIMEBOX_MICROSECONDS * 1000, $fastest);
    }

    /**
     * Configure the guards and their relying party.
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

        $config = $app->make(ConfigRepository::class);

        self::configureSessionGuards($config);
        self::configurePasskeys($config);
    }
}
