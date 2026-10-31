<?php

declare(strict_types = 1);

namespace Tests\Performance;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Foundation\Application;
use Illuminate\Http\Request;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Sessions\PrincipalChoice;
use SineMacula\Laravel\Authentication\Sessions\PrincipalSwitch;
use SineMacula\Laravel\Authentication\Sessions\SessionService;
use SineMacula\Laravel\Authentication\Sessions\SignInResult;
use SineMacula\Laravel\Authentication\Sessions\SwitchResult;
use Tests\Concerns\InteractsWithSessions;
use Tests\Integration\Fixtures\ActivatableTenant;
use Tests\Integration\Fixtures\ActivatableTenantMembership;
use Tests\Integration\Fixtures\ChoosingMember;
use Tests\Integration\Fixtures\ChoosingMembership;

/**
 * Query-budget and timing contracts for choosing and switching principal: a
 * sign-in held for a choice reads the identity and its principals (and each
 * one's tenant) and writes the attempt counters and the pending choice; making
 * the choice uses it up, writes the device and gives the slots back; a switch
 * reads the refresh counters, the device, its owner, the target, its tenant and
 * its owner, writes the one compare-and-swap, and then reads the principal it
 * switched from for the event, while a grace retry writes nothing and a refusal
 * writes only the counters.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SessionService::class)]
#[CoversClass(PrincipalSwitch::class)]
final class PrincipalSwitchQueryBudgetTest extends PerformanceContractTestCase
{
    use InteractsWithSessions;

    /** @var int Switches, grace retries and refusals each timed by the timing contract. */
    private const int TIMED_SWITCHES = 20;

    /** @var int Generous ceiling for each group of them, in nanoseconds (100 ms each). */
    private const int TIMED_CEILING_NANOSECONDS = self::TIMED_SWITCHES * 100000000;

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
     * A switch to another membership reads the refresh counters, the device,
     * its owner, the target, its tenant and its owner, writes the switch, and
     * reads the membership it switched from.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASwitchIsItsReadsAndOneUpdate(): void
    {
        [$member, , $tenant] = $this->seedMember();

        $second  = ActivatableTenantMembership::query()->create(['identity_id' => $member->getKey(), 'tenant_id' => $tenant->getKey()]);
        $session = $this->sessions('members')->signIn('password', self::credentials('member@example.test'))->session;

        self::assertNotNull($session);

        $sessions = $this->sessions('members');
        $result   = $this->assertQueryBudget(7, 1, static fn (): SwitchResult => $sessions->switchPrincipal($session->tokens->refreshToken, $second));

        self::assertTrue($result->isSwitched());
    }

    /**
     * A sign-in held for a choice between two memberships reads the identity,
     * its memberships and each one's tenant, and writes the six attempt-counter
     * statements a password sign-in makes and the pending choice.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAChoiceIsItsReadsTheCountersAndOneInsert(): void
    {
        $member = ChoosingMember::query()->create(['email' => 'chooser@example.test', 'password' => app(Hasher::class)->make(self::PASSWORD)]);

        foreach (['First', 'Second'] as $name) {
            $tenant = ActivatableTenant::query()->create(['name' => $name, 'is_active' => true]);

            ChoosingMembership::query()->create(['identity_id' => $member->getKey(), 'tenant_id' => $tenant->getKey()]);
        }

        $sessions = $this->sessions('choosers');
        $result   = $this->assertQueryBudget(4, 7, static fn (): SignInResult => $sessions->signIn('password', self::credentials('chooser@example.test')));

        self::assertTrue($result->requiresPrincipal());
    }

    /**
     * Reading a choice reads the pending choice, its identity, the memberships
     * and each one's tenant, and writes nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testReadingAChoiceIsItsReadsAlone(): void
    {
        $token = $this->offerChoice();

        $sessions = $this->sessions('choosers');
        $choice   = $this->assertQueryBudget(5, 0, static fn (): ?PrincipalChoice => $sessions->choice($token));

        self::assertCount(2, $choice->principals ?? []);
    }

    /**
     * Choosing reads the pending choice, its identity, the chosen membership,
     * its owner and its tenant, uses the choice up, writes the device, and
     * gives each of the choice's three attempt slots back.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testChoosingIsItsReadsTheDeviceAndTheSlotsGivenBack(): void
    {
        $token  = $this->offerChoice();
        $chosen = ChoosingMembership::query()->firstOrFail();

        $sessions = $this->sessions('choosers');
        $result   = $this->assertQueryBudget(5, 5, static fn (): SignInResult => $sessions->choose($token, $chosen));

        self::assertTrue($result->isSignedIn());
    }

    /**
     * A switch whose refresh token the request carries costs what a switch
     * costs: reading the token from the request runs no query.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASwitchFromTheRequestCostsWhatASwitchCosts(): void
    {
        [$session, $second] = $this->signInWithASecondMembership();

        $sessions = self::sessionsOf($this->guardForRequest(['refresh_token' => $session->tokens->refreshToken]));
        $result   = $this->assertQueryBudget(7, 1, static fn (): ?SwitchResult => $sessions->switchPrincipalFromRequest($second));

        self::assertTrue($result?->isSwitched());
    }

    /**
     * A lost switch response retried inside the grace window reads the refresh
     * counters, the device, its owner, the target, its tenant and its owner,
     * and writes nothing: the current credential is handed back.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAGraceRetryOfASwitchIsItsReadsAlone(): void
    {
        [$session, $second] = $this->signInWithASecondMembership();

        self::assertTrue($this->sessions('members')->switchPrincipal($session->tokens->refreshToken, $second)->isSwitched());

        $sessions = $this->sessions('members');
        $result   = $this->assertQueryBudget(6, 0, static fn (): SwitchResult => $sessions->switchPrincipal($session->tokens->refreshToken, $second));

        self::assertTrue($result->isSwitched());
    }

    /**
     * A switch to a principal of another identity reads the refresh counters,
     * the device, its owner and the identity's principals, is refused, and
     * writes nothing but the failure on the two refresh counters.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARefusedSwitchWritesNothingButTheCounters(): void
    {
        [$session]   = $this->signInWithASecondMembership();
        [, $foreign] = $this->seedMember('other@example.test');

        $sessions = $this->sessions('members');
        $result   = $this->assertQueryBudget(5, 4, static fn (): SwitchResult => $sessions->switchPrincipal($session->tokens->refreshToken, $foreign));

        self::assertSame(FailureReason::PRINCIPAL_MISMATCH, $result->reason);
    }

    /**
     * A switch the refresh limits already refuse reads the counters and nothing
     * else: neither the device nor the target is read.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARateLimitedSwitchIsRefusedFromTheLimitsAlone(): void
    {
        [$session, $second] = $this->signInWithASecondMembership();

        config()->set('auth.guards.members.rate_limits', ['refresh' => ['per_identifier' => null, 'per_ip' => ['max' => 1, 'decay_seconds' => 60]]]);

        self::assertSame(FailureReason::TOKEN_INVALID, $this->sessions('members')->switchPrincipal('not a token', $second)->reason);

        $sessions = $this->sessions('members');
        $result   = $this->assertQueryBudget(1, 0, static fn (): SwitchResult => $sessions->switchPrincipal($session->tokens->refreshToken, $second));

        self::assertSame(FailureReason::RATE_LIMITED, $result->reason);
    }

    /**
     * Warmed switches, grace retries and refusals each stay far inside a
     * generous time ceiling, so a pathological regression that adds no query,
     * such as a key derivation per check, still fails.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testSwitchesRetriesAndRefusalsStayWithinAGenerousTimeCeiling(): void
    {
        $limit = ['max' => 1000, 'decay_seconds' => 60];

        config()->set('auth.guards.members.rate_limits', ['refresh' => ['per_identifier' => $limit, 'per_ip' => $limit]]);

        [$session, $second, $first] = $this->signInWithASecondMembership();
        [, $foreign]                = $this->seedMember('other@example.test');

        $token   = $session->tokens->refreshToken;
        $targets = [$second, $first];

        self::assertNotNull($this->sessions('members')->switchPrincipal($token, $foreign)->reason);

        $started = hrtime(true);

        for ($switch = 0; $switch < self::TIMED_SWITCHES; $switch++) {
            $result = $this->sessions('members')->switchPrincipal($token, $targets[$switch % 2]);

            self::assertTrue($result->isSwitched());

            $token = $result->session?->tokens->refreshToken ?? '';
        }

        $switches = hrtime(true) - $started;
        $previous = $token;

        $this->sessions('members')->switchPrincipal($token, $targets[0]);

        $started = hrtime(true);

        for ($retry = 0; $retry < self::TIMED_SWITCHES; $retry++) {
            self::assertTrue($this->sessions('members')->switchPrincipal($previous, $targets[0])->isSwitched());
        }

        $retries = hrtime(true) - $started;
        $started = hrtime(true);

        for ($refusal = 0; $refusal < self::TIMED_SWITCHES; $refusal++) {
            self::assertSame(FailureReason::PRINCIPAL_MISMATCH, $this->sessions('members')->switchPrincipal($previous, $foreign)->reason);
        }

        $refusals = hrtime(true) - $started;

        self::assertLessThan(self::TIMED_CEILING_NANOSECONDS, $switches);
        self::assertLessThan(self::TIMED_CEILING_NANOSECONDS, $retries);
        self::assertLessThan(self::TIMED_CEILING_NANOSECONDS, $refusals);
    }

    /**
     * Register the session guards, and a guard over the choosing members.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        assert($app instanceof Application);

        $config = $app->make(ConfigRepository::class);

        self::configureSessionGuards($config);

        $config->set('auth.providers.choosers', ['driver' => 'model', 'model' => ChoosingMember::class]);
        $config->set('auth.guards.choosers', ['driver' => 'jwt', 'provider' => 'choosers', 'audience' => ['methods' => ['password']]]);
    }

    /**
     * Persist a chooser with two memberships, each in its own active tenant,
     * sign it in, and return the choice token it is offered.
     *
     * @return string
     *
     * @throws \Throwable
     */
    private function offerChoice(): string
    {
        $member = ChoosingMember::query()->create(['email' => 'chooser@example.test', 'password' => app(Hasher::class)->make(self::PASSWORD)]);

        foreach (['First', 'Second'] as $name) {
            $tenant = ActivatableTenant::query()->create(['name' => $name, 'is_active' => true]);

            ChoosingMembership::query()->create(['identity_id' => $member->getKey(), 'tenant_id' => $tenant->getKey()]);
        }

        $choice = $this->sessions('choosers')->signIn('password', self::credentials('chooser@example.test'))->choice;

        self::assertNotNull($choice);

        return $choice->token;
    }

    /**
     * Persist a member with its default membership and a second one in the same
     * tenant, and sign it in as the default.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @return array{0: \SineMacula\Laravel\Authentication\Sessions\SignedInSession, 1: \Tests\Integration\Fixtures\ActivatableTenantMembership, 2: \Tests\Integration\Fixtures\ActivatableTenantMembership}
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     *
     * @throws \Throwable
     */
    private function signInWithASecondMembership(): array
    {
        [$member, $first, $tenant] = $this->seedMember();

        $second  = ActivatableTenantMembership::query()->create(['identity_id' => $member->getKey(), 'tenant_id' => $tenant->getKey()]);
        $session = $this->sessions('members')->signIn('password', self::credentials('member@example.test'))->session;

        self::assertNotNull($session);

        return [$session, $second, $first];
    }

    /**
     * The `members` guard, resolved afresh for a request with the body.
     *
     * @param  array<string, string>  $body
     * @return \SineMacula\Laravel\Authentication\Guards\JwtGuard
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function guardForRequest(array $body): JwtGuard
    {
        app()->instance('request', Request::create('/switch', 'POST', $body, server: ['REMOTE_ADDR' => self::CLIENT_IP]));

        return $this->freshJwtGuard('members');
    }
}
