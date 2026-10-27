<?php

declare(strict_types = 1);

namespace Tests\Performance;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\AdditionalFactorPolicy;
use SineMacula\Laravel\Authentication\Factors\AdditionalFactorContext;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Sessions\PendingFactor;
use SineMacula\Laravel\Authentication\Sessions\SessionService;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;
use SineMacula\Laravel\Authentication\Sessions\SignInResult;
use Tests\Concerns\InteractsWithSessions;

/**
 * Query-budget and timing contracts for the session service: what a sign-in
 * costs on a new device, on a proven device, and when it fails, and the timebox
 * that keeps a failed sign-in as slow whether or not its identifier exists.
 *
 * A sign-in through a method also writes its attempt limits: it reserves a slot
 * on the identifier's and the IP address's counters (on a fresh window, for
 * each, an update that changes nothing and the insert that creates the counter;
 * later in the window, one update each), and a sign-in that succeeds gives both
 * back; one that asks for a further factor keeps them until it completes. A
 * password checked against an account reserves a slot on the account's counter
 * as well, given back when it matches. `start()` and `complete()` are not
 * limited.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SessionService::class)]
final class SessionServiceQueryBudgetTest extends PerformanceContractTestCase
{
    use InteractsWithSessions;

    /** @var int Timebox for the timing contracts, in microseconds. */
    private const int TIMEBOX_MICROSECONDS = 200000;

    /** @var int Successful sign-ins timed against the timebox. */
    private const int SUCCESSFUL_TIMING_SAMPLES = 3;

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
     * A sign-in on a new device reads the identity once and writes the device
     * once, besides the six reservation writes and three releases of its
     * limits: binding it records no further use, since the device already
     * records the sign-in as its last.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASignInOnANewDeviceReadsOnceAndWritesTheDeviceOnce(): void
    {
        $this->seedIdentity();

        $sessions = $this->sessions();

        self::assertTrue($this->assertQueryBudget(1, 10, static fn (): SignInResult => $sessions->signIn('password', self::credentials()))->isSignedIn());
    }

    /**
     * Continuing a proven device reads the identity and the device and writes
     * one compare-and-swap, besides reserving and releasing a slot on each of
     * the three counters the first sign-in created.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASignInOnAProvenDeviceReadsTwiceAndWritesTheDeviceOnce(): void
    {
        $this->seedIdentity();

        $first = $this->sessions()->signIn('password', self::credentials())->session;

        self::assertNotNull($first);

        $sessions = $this->sessions();
        $context  = new SignInContext(new ClientContext(self::CLIENT_IP, self::CLIENT_AGENT), refreshToken: $first->tokens->refreshToken);
        $again    = $this->assertQueryBudget(2, 7, static fn (): SignInResult => $sessions->signIn('password', self::credentials(), $context));

        self::assertFalse($again->session?->deviceCreated);
    }

    /**
     * A session started for an externally verified identity reloads it once and
     * writes the device once.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testStartReadsTheIdentityOnceAndWritesOnce(): void
    {
        $identity = $this->seedIdentity();
        $sessions = $this->sessions();

        self::assertTrue($this->assertQueryBudget(1, 1, static fn (): SignInResult => $sessions->start($identity, null, 'sso'))->isSignedIn());
    }

    /**
     * A sign-in that needs a further factor reads the identity once and writes
     * the pending sign-in once, besides its limits, whose slots it keeps;
     * looking that up reads it and the identity; and completing it reads them,
     * deletes it, writes the device and gives the two slots back.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPendingSignInCostsOneWriteToIssueAndKeepsItsSlotsUntilItCompletes(): void
    {
        $this->seedIdentity();

        self::requireAFurtherFactor();

        $sessions = $this->sessions();
        $pending  = $this->assertQueryBudget(1, 8, static fn (): SignInResult => $sessions->signIn('password', self::credentials()))->pending;

        self::assertNotNull($pending);

        $sessions = $this->sessions();

        self::assertNotNull($this->assertQueryBudget(2, 0, static fn (): ?PendingFactor => $sessions->pending($pending->token)));

        $sessions = $this->sessions();

        self::assertTrue($this->assertQueryBudget(2, 4, static fn (): SignInResult => $sessions->complete($pending->token))->isSignedIn());
    }

    /**
     * Discarding a pending sign-in reads it once and deletes it, without
     * reloading its identity; a token that names none costs the one read.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testDiscardingAPendingSignInReadsItOnceAndDeletesIt(): void
    {
        $this->seedIdentity();

        self::requireAFurtherFactor();

        $pending = $this->sessions()->signIn('password', self::credentials())->pending;

        self::assertNotNull($pending);

        $sessions = $this->sessions();

        self::assertTrue($this->assertQueryBudget(1, 1, static fn (): bool => $sessions->discard($pending->token)));
        self::assertFalse($this->assertQueryBudget(1, 0, static fn (): bool => $sessions->discard($pending->token)));
    }

    /**
     * Rows of `[credentials, writes]`: sign-ins that fail, with and without a
     * known identifier, and the reservation writes each keeps (a wrong password
     * also reserves the account's slot).
     *
     * @return iterable<string, array{0: array<string, string>, 1: int}>
     */
    public static function provideFailedCredentials(): iterable
    {
        yield from [
            'unknown identifier' => [['email' => 'nobody@example.test', 'password' => self::PASSWORD], 4],
            'wrong password'     => [['email' => 'ada@example.test', 'password' => 'wrong'], 6],
        ];
    }

    /**
     * A failed sign-in reads the identity once, writes only the reservations it
     * keeps, and waits out the real timebox whether or not the identifier
     * exists.
     *
     * @param  array<string, string>  $credentials
     * @param  int  $writes
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideFailedCredentials')]
    public function testAFailedSignInReadsOnceWritesOnlyItsLimitsAndWaitsOutTheTimebox(array $credentials, int $writes): void
    {
        $this->seedIdentity();

        $sessions = $this->sessions();

        self::assertTrue($this->assertQueryBudget(1, $writes, static fn (): SignInResult => $sessions->signIn('password', $credentials))->isFailed());

        $this->useTimebox();

        $sessions = $this->sessions();
        $started  = hrtime(true);

        self::assertTrue($sessions->signIn('password', $credentials)->isFailed());
        self::assertGreaterThanOrEqual(self::TIMEBOX_MICROSECONDS * 1000, hrtime(true) - $started);
    }

    /**
     * A successful sign-in returns as soon as it is done instead of waiting out
     * the timebox. The fastest of a few sign-ins is compared, so one scheduler
     * pause cannot fail the contract.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASuccessfulSignInReturnsBeforeTheTimebox(): void
    {
        $this->seedIdentity();
        $this->useTimebox();

        $fastest = PHP_INT_MAX;

        for ($attempt = 0; $attempt < self::SUCCESSFUL_TIMING_SAMPLES; $attempt++) {

            $sessions = $this->sessions();
            $started  = hrtime(true);

            self::assertTrue($sessions->signIn('password', self::credentials())->isSignedIn());

            $fastest = min($fastest, hrtime(true) - $started);
        }

        self::assertLessThan(self::TIMEBOX_MICROSECONDS * 1000, $fastest);
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

        self::configureSessionGuards($app->make(ConfigRepository::class));
    }

    /**
     * Bind an additional-factor policy that asks every sign-in for a further
     * factor.
     *
     * @return void
     */
    private static function requireAFurtherFactor(): void
    {
        app()->instance(AdditionalFactorPolicy::class, new class implements AdditionalFactorPolicy {
            /**
             * Always require a further factor.
             *
             * @param  \SineMacula\Laravel\Authentication\Factors\AdditionalFactorContext  $context
             * @return bool
             */
            #[\Override]
            public function requiresAdditionalFactor(AdditionalFactorContext $context): bool
            {
                return true;
            }
        });
    }

    /**
     * Use the real timebox length for the timing contracts.
     *
     * @return void
     */
    private function useTimebox(): void
    {
        app(ConfigRepository::class)->set('authentication.timebox.credentials_microseconds', self::TIMEBOX_MICROSECONDS);
    }
}
