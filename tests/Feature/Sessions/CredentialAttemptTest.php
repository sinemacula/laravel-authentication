<?php

declare(strict_types = 1);

namespace Tests\Feature\Sessions;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Admission\Refused;
use SineMacula\Laravel\Authentication\Contracts\AttemptLimiter;
use SineMacula\Laravel\Authentication\Contracts\AudiencePolicy;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\RateLimiting\AccountAttempts;
use SineMacula\Laravel\Authentication\RateLimiting\AttemptSubject;
use SineMacula\Laravel\Authentication\RateLimiting\Enums\AttemptFlow;
use SineMacula\Laravel\Authentication\Sessions\CredentialAttempt;
use Tests\Concerns\InteractsWithSessions;
use Tests\Fixtures\Sessions\RecordingAttemptLimiter;
use Tests\TestCase;

/**
 * Feature tests of the steps a credential sign-in takes the same way through
 * `attempt()` and the session service: the method check and the slot on the
 * identifier and IP limits, the refusal by an account's own limit, the windows
 * a pending sign-in keeps, and the give-back of every slot.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CredentialAttempt::class)]
final class CredentialAttemptTest extends TestCase
{
    use InteractsWithSessions;

    /** @var string The identifier the sign-in names. */
    private const string IDENTIFIER = 'ada@example.test';

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
     * A method the audience policy does not allow is refused before the limiter
     * is so much as resolved, so nothing is counted.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAMethodTheAudienceDoesNotAllowIsRefusedBeforeTheLimiterIsResolved(): void
    {
        $limiter  = new RecordingAttemptLimiter;
        $resolved = 0;

        app()->bind(AttemptLimiter::class, static function () use ($limiter, &$resolved): AttemptLimiter {
            $resolved++;

            return $limiter;
        });

        $refused = CredentialAttempt::checkMethod(app(), 'passwordless', 'password');

        self::assertInstanceOf(Refused::class, $refused);
        self::assertSame([FailureReason::METHOD_NOT_ALLOWED, null, null], [$refused->reason, $refused->retryAfter, $refused->identity]);
        self::assertSame(0, $resolved);
        self::assertSame([], $limiter->acquired);
    }

    /**
     * A method the audience policy allows answers with the policy the container
     * holds then, the one the sign-in goes on to admit with.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAMethodTheAudienceAllowsAnswersWithThePolicy(): void
    {
        self::assertSame(app(AudiencePolicy::class), CredentialAttempt::checkMethod(app(), 'api', 'password'));
    }

    /**
     * An identifier or IP address with no attempts left is refused as
     * `rate_limited` with the limiter's wait, and nothing is given back.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASubjectWithNoAttemptsLeftIsRefusedWithTheWait(): void
    {
        $limiter = new RecordingAttemptLimiter(refuse: static fn (AttemptSubject $subject): ?int => $subject->account === null ? 45 : null);
        $subject = self::subject();

        app()->instance(AttemptLimiter::class, $limiter);

        $refused = CredentialAttempt::begin(app(), app(AudiencePolicy::class), $subject);

        self::assertInstanceOf(Refused::class, $refused);
        self::assertSame([FailureReason::RATE_LIMITED, 45], [$refused->reason, $refused->retryAfter]);
        self::assertSame([$subject], $limiter->acquired);
        self::assertSame([], $limiter->released);
    }

    /**
     * A sign-in the limits grant holds the policy it was begun with, and
     * account attempts that count against the guard on the same limiter; no
     * account has refused it yet.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAGrantedAttemptHoldsThePolicyAndCountsAccountsOnTheSameLimiter(): void
    {
        $limiter  = new RecordingAttemptLimiter;
        $audience = \Mockery::mock(AudiencePolicy::class);

        app()->instance(AttemptLimiter::class, $limiter);

        $attempt = CredentialAttempt::begin(app(), $audience, self::subject());

        self::assertInstanceOf(CredentialAttempt::class, $attempt);
        self::assertSame($audience, $attempt->audience);
        self::assertNull($attempt->accountRefusal());

        $identity = $this->seedIdentity();

        self::assertTrue($attempt->accounts->reserve($identity));
        self::assertSame(
            [[null, AttemptFlow::SIGN_IN, self::IDENTIFIER], [AccountAttempts::account($identity), AttemptFlow::SIGN_IN, null]],
            array_map(static fn (AttemptSubject $subject): array => [$subject->account, $subject->flow, $subject->identifier], $limiter->acquired),
        );
        self::assertSame(['api', 'api'], array_map(static fn (AttemptSubject $subject): string => $subject->guard, $limiter->acquired));
    }

    /**
     * Once an account whose secret the sign-in checked has no attempts left,
     * the attempt refuses it as `account_rate_limited`, with that account's
     * wait.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnAccountWithNoAttemptsLeftRefusesTheSignInWithItsWait(): void
    {
        app()->instance(AttemptLimiter::class, new RecordingAttemptLimiter(refuse: static fn (AttemptSubject $subject): ?int => $subject->account === null ? null : 90));

        $attempt = CredentialAttempt::begin(app(), app(AudiencePolicy::class), self::subject());

        self::assertInstanceOf(CredentialAttempt::class, $attempt);
        self::assertFalse($attempt->accounts->reserve($this->seedIdentity()));

        $refused = $attempt->accountRefusal();

        self::assertNotNull($refused);
        self::assertSame([FailureReason::ACCOUNT_RATE_LIMITED, 90, null], [$refused->reason, $refused->retryAfter, $refused->identity]);
    }

    /**
     * The windows a pending sign-in keeps are the sign-in's own slot first and
     * then one entry for each account slot it holds, and the give-back returns
     * exactly those reservations, its own first.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheWindowsAndTheGiveBackCoverEverySlotHeldItsOwnFirst(): void
    {
        $limiter = new RecordingAttemptLimiter;

        app()->instance(AttemptLimiter::class, $limiter);

        $attempt = CredentialAttempt::begin(app(), app(AudiencePolicy::class), self::subject());

        self::assertInstanceOf(CredentialAttempt::class, $attempt);

        $ada   = $this->seedIdentity();
        $grace = $this->seedIdentity('grace@example.test');

        $attempt->accounts->reserve($ada);
        $attempt->accounts->reserve($grace);

        self::assertSame(
            [[self::IDENTIFIER => 'window'], [AccountAttempts::account($ada) => 'window'], [AccountAttempts::account($grace) => 'window']],
            $attempt->windows(),
        );
        self::assertSame([], $limiter->released);

        $attempt->release();

        self::assertSame($limiter->reservations, $limiter->released);
    }

    /**
     * Register the session tests' guards, and one over their identities that
     * does not allow the password method.
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

        $config->set('auth.guards.passwordless', ['driver' => 'jwt', 'provider' => 'identities', 'audience' => ['methods' => ['sso']]]);
    }

    /**
     * A password sign-in's subject on the `api` guard, naming the identifier
     * from the session tests' client.
     *
     * @return \SineMacula\Laravel\Authentication\RateLimiting\AttemptSubject
     */
    private static function subject(): AttemptSubject
    {
        return new AttemptSubject('api', AttemptFlow::SIGN_IN, self::IDENTIFIER, 'email', self::CLIENT_IP);
    }
}
