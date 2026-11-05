<?php

declare(strict_types = 1);

namespace Tests\Feature\Sessions;

use Carbon\CarbonImmutable;
use Firebase\JWT\JWT;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Foundation\Application;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversTrait;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\AdditionalFactorPolicy;
use SineMacula\Laravel\Authentication\Contracts\FreshnessPolicy;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\Reauthenticated;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Factors\Enums\FactorChange;
use SineMacula\Laravel\Authentication\Factors\FactorChangeVerdict;
use SineMacula\Laravel\Authentication\Freshness\ConfiguredFreshness;
use SineMacula\Laravel\Authentication\Freshness\FreshnessRequirement;
use SineMacula\Laravel\Authentication\Models\Session;
use SineMacula\Laravel\Authentication\Proofs\Channel;
use SineMacula\Laravel\Authentication\Proofs\Enums\ChannelKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\Purpose;
use SineMacula\Laravel\Authentication\Proofs\Evaluation;
use SineMacula\Laravel\Authentication\Proofs\ObservedProperties;
use SineMacula\Laravel\Authentication\Proofs\ProofBinding;
use SineMacula\Laravel\Authentication\Proofs\ProofResult;
use SineMacula\Laravel\Authentication\Sessions\Concerns\GatesFactorChanges;
use SineMacula\Laravel\Authentication\Sessions\Enums\PendingAction;
use SineMacula\Laravel\Authentication\Sessions\FactorChangeGate;
use SineMacula\Laravel\Authentication\Sessions\SignedInSession;
use Tests\Concerns\InteractsWithSessions;
use Tests\Concerns\MarksSharedLocks;
use Tests\Fixtures\Database\LockMarkingSQLiteGrammar;
use Tests\Fixtures\Factors\AlwaysRequireAdditionalFactor;
use Tests\Fixtures\Freshness\DecoratingFreshness;
use Tests\Fixtures\Freshness\ScriptedFreshness;
use Tests\Integration\Fixtures\MachineClient;
use Tests\TestCase;

/**
 * Feature tests of the gate the factor package asks before it changes an
 * identity's further factors, through the session service against a real
 * database: which proof each change takes, from which sessions, until when, and
 * that it writes and reports nothing.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FactorChangeGate::class)]
#[CoversTrait(GatesFactorChanges::class)]
final class FactorChangeGateTest extends TestCase
{
    use InteractsWithSessions, MarksSharedLocks;

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

        $this->clockAt($this->now);
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
     * Rows of `[change, factor]`: every change but an identity's first
     * additional factor, with the factor it names, if any.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Authentication\Factors\Enums\FactorChange, 1: ?string}>
     */
    public static function provideStepUpChanges(): iterable
    {
        yield 'adding a factor' => [FactorChange::ADD, null];
        yield 'replacing a factor' => [FactorChange::REPLACE, 'factor-old'];
        yield 'removing a factor' => [FactorChange::REMOVE, 'factor-old'];
        yield 'generating recovery codes' => [FactorChange::GENERATE_RECOVERY_CODES, null];
    }

    /**
     * A change of a further factor takes a fresh step-up: a session signed in
     * with its first factor alone is refused as `step_up_required`, and one
     * stepped up within 15 minutes is allowed, with that step-up as its proof
     * and fresh until it is 15 minutes old.
     *
     * @param  \SineMacula\Laravel\Authentication\Factors\Enums\FactorChange  $change
     * @param  ?string  $factor
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideStepUpChanges')]
    public function testAChangeTakesAFreshStepUp(FactorChange $change, ?string $factor): void
    {
        $signedIn = $this->signedIn();

        $this->assertRefused(Auth::sessions('api')->factorChange($signedIn->record, $change, factor: $factor), FailureReason::STEP_UP_REQUIRED);

        $this->stepUp($signedIn, 'factor-current', $this->now->addMinute());
        $this->clockAt($this->now->addMinutes(2));

        $verdict = Auth::sessions('api')->factorChange($signedIn->record, $change, factor: $factor);

        self::assertTrue($verdict->isAllowed());
        self::assertSame(ProofKind::ADDITIONAL_FACTOR, $verdict->proof?->kind);
        self::assertSame('factor-current', $verdict->proof->factor);
        self::assertSame($this->now->addMinute()->addSeconds(900)->getTimestamp(), $verdict->freshUntil?->getTimestamp());

        $this->clockAt($this->now->addMinute()->addSeconds(900));

        $this->assertRefused($this->sessions()->factorChange($signedIn->record, $change, factor: $factor), FailureReason::STEP_UP_REQUIRED);
    }

    /**
     * An identity's first additional factor takes a fresh reauthentication with
     * the first factor: the sign-in's own first factor, however fresh, never
     * allows it (`reauthentication_required`), nor does a further factor's
     * step-up, while a password reauthentication within 15 minutes does, until
     * it is 15 minutes old.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheFirstAdditionalFactorTakesAFreshReauthentication(): void
    {
        $signedIn = $this->signedIn();

        $this->assertRefused($this->sessions()->factorChange($signedIn->record, FactorChange::ADD_FIRST), FailureReason::REAUTHENTICATION_REQUIRED);

        $this->stepUp($signedIn, 'factor-current', $this->now);

        $this->assertRefused($this->sessions()->factorChange($signedIn->record, FactorChange::ADD_FIRST), FailureReason::REAUTHENTICATION_REQUIRED);

        $this->clockAt($this->now->addMinutes(5));

        self::assertTrue($this->sessions()->reauthenticate($signedIn->record, 'password', self::credentials())->isIssued());

        $verdict = $this->sessions()->factorChange($signedIn->record, FactorChange::ADD_FIRST);

        self::assertTrue($verdict->isAllowed());
        self::assertSame(ProofKind::FIRST_FACTOR_REAUTHENTICATION, $verdict->proof?->kind);
        self::assertSame($this->now->addMinutes(5)->addSeconds(900)->getTimestamp(), $verdict->freshUntil?->getTimestamp());

        $this->clockAt($this->now->addMinutes(20));

        $this->assertRefused($this->sessions()->factorChange($signedIn->record, FactorChange::ADD_FIRST), FailureReason::REAUTHENTICATION_REQUIRED);
    }

    /**
     * The factor a removal or a replacement names never authorises its own
     * change: a step-up made with it alone is refused, and a step-up made with
     * another factor allows it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheFactorChangedNeverAuthorizesItsOwnChange(): void
    {
        $signedIn = $this->signedIn();

        $this->stepUp($signedIn, 'factor-a', $this->now);

        $this->assertRefused($this->sessions()->factorChange($signedIn->record, FactorChange::REMOVE, factor: 'factor-a'), FailureReason::STEP_UP_REQUIRED);
        $this->assertRefused($this->sessions()->factorChange($signedIn->record, FactorChange::REPLACE, factor: 'factor-a'), FailureReason::STEP_UP_REQUIRED);

        self::assertSame('factor-a', $this->sessions()->factorChange($signedIn->record, FactorChange::REMOVE, factor: 'factor-b')->proof?->factor);
        self::assertSame('factor-a', $this->sessions()->factorChange($signedIn->record, FactorChange::ADD)->proof?->factor);
    }

    /**
     * A caller's requirement makes the configured one stricter: a step-up two
     * minutes old meets the configured 15 minutes but not the caller's one, and
     * the deadline follows the stricter age.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACallersRequirementIsAppliedWithTheConfiguredOne(): void
    {
        $signedIn = $this->signedIn();

        $this->stepUp($signedIn, 'factor-a', $this->now);
        $this->clockAt($this->now->addMinutes(2));

        $this->assertRefused($this->sessions()->factorChange($signedIn->record, FactorChange::ADD, FreshnessRequirement::within(60)), FailureReason::STEP_UP_REQUIRED);

        $verdict = $this->sessions()->factorChange($signedIn->record, FactorChange::ADD, FreshnessRequirement::within(300));

        self::assertSame($this->now->addSeconds(300)->getTimestamp(), $verdict->freshUntil?->getTimestamp());
    }

    /**
     * An operation the configuration removes, with no requirement of the
     * caller's, is never fresh: the change is refused.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnOperationWithNoRequirementRefusesTheChange(): void
    {
        $signedIn = $this->signedIn();

        $this->stepUp($signedIn, 'factor-a', $this->now);

        config()->set('auth.guards.api.freshness', ['factor_change' => null, 'first_additional_factor' => null]);

        $this->assertRefused($this->sessions()->factorChange($signedIn->record, FactorChange::ADD), FailureReason::STEP_UP_REQUIRED);
        $this->assertRefused($this->sessions()->factorChange($signedIn->record, FactorChange::ADD_FIRST), FailureReason::REAUTHENTICATION_REQUIRED);
    }

    /**
     * The bound freshness policy is the one asked, about the change's operation
     * on the session's application, with the caller's requirement and the
     * factor changed; its proof's time and the effective age give the deadline.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheBoundFreshnessPolicyIsAsked(): void
    {
        $signedIn = $this->signedIn();
        $policy   = new ScriptedFreshness(FreshnessRequirement::within(120));

        app()->instance(FreshnessPolicy::class, $policy);

        $verdict = $this->sessions()->factorChange($signedIn->record, FactorChange::REMOVE, factor: 'factor-a');

        self::assertSame(['requirement:api:factor_change', 'freshProof:factor_change:factor-a (current)'], $policy->asked);
        self::assertSame($this->now->addSeconds(120)->getTimestamp(), $verdict->freshUntil?->getTimestamp());

        $refusing = new ScriptedFreshness(null);

        app()->instance(FreshnessPolicy::class, $refusing);

        $this->assertRefused($this->sessions()->factorChange($signedIn->record, FactorChange::ADD_FIRST), FailureReason::REAUTHENTICATION_REQUIRED);
        self::assertSame(['requirement:api:first_additional_factor'], $refusing->asked);
    }

    /**
     * Rows of what makes the session unable to have a factor changed from it,
     * and the reason.
     *
     * @return iterable<string, array{0: string, 1: \SineMacula\Laravel\Authentication\Events\Enums\FailureReason}>
     */
    public static function provideRefusedSessions(): iterable
    {
        yield 'gone' => ['gone', FailureReason::SESSION_UNKNOWN];
        yield 'another session under its key' => ['replaced', FailureReason::SESSION_UNKNOWN];
        yield 'revoked' => ['revoked', FailureReason::SESSION_REVOKED];
        yield 'ended' => ['ended', FailureReason::SESSION_EXPIRED];
        yield 'pending' => ['pending', FailureReason::SESSION_PENDING];
        yield 'another guard\'s' => ['admin', FailureReason::SESSION_GUARD_MISMATCH];
        yield 'a machine\'s' => ['machine', FailureReason::MACHINE_IDENTITY];
    }

    /**
     * A session that is gone or replaced, not one of this guard's live, active
     * sessions, or a machine's, has no factor changed from it, however fresh it
     * is.
     *
     * @param  string  $state
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\FailureReason  $reason
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideRefusedSessions')]
    public function testASessionThatCannotBeChangedFromIsRefused(string $state, FailureReason $reason): void
    {
        $signedIn = $state === 'admin' ? $this->signedIn('admin') : $this->signedIn();

        $this->stepUp($signedIn, 'factor-a', $this->now);

        match ($state) {
            'gone'     => DB::table('authentication_sessions')->delete(),
            'replaced' => DB::table('authentication_sessions')->update(['generation' => str_repeat('b', 32)]),
            'revoked'  => DB::table('authentication_sessions')->update(['revoked_at' => $this->now]),
            'ended'    => DB::table('authentication_sessions')->update(['idle_expires_at' => $this->now]),
            'pending'  => DB::table('authentication_sessions')->update(['status' => 'pending']),
            'machine'  => DB::table('authentication_sessions')->update(['authenticatable_type' => MachineClient::class]),
            default    => null,
        };

        $given = in_array($state, ['gone', 'replaced'], true) ? $signedIn->record : Session::query()->sole();

        $this->assertRefused($this->sessions()->factorChange($given, FactorChange::ADD), $reason);
    }

    /**
     * A pending session's bootstrap enrolment never goes through the gate: the
     * gate refuses every pending session, while the pending credential allows
     * the bootstrap enrolment actions while the factor is outstanding.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPendingSessionEnrollsThroughItsCredentialNotTheGate(): void
    {
        $this->seedIdentity();

        app()->instance(AdditionalFactorPolicy::class, new AlwaysRequireAdditionalFactor);

        $result = $this->sessions()->signIn('password', self::credentials());

        self::assertNotNull($result->pending);
        self::assertNotNull($result->credential);

        $this->assertRefused($this->sessions()->factorChange($result->pending->session, FactorChange::ADD_FIRST), FailureReason::SESSION_PENDING);

        self::assertNotNull($this->sessions()->pending($result->credential, PendingAction::START_BOOTSTRAP_ENROLLMENT));
    }

    /**
     * Rows of `[change, factor]` the gate refuses before reading anything: a
     * replacement or removal that names no factor, or one empty or too long,
     * and any other change that names one.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Authentication\Factors\Enums\FactorChange, 1: ?string}>
     */
    public static function provideMisnamedFactors(): iterable
    {
        yield 'a removal naming none' => [FactorChange::REMOVE, null];
        yield 'a replacement naming none' => [FactorChange::REPLACE, null];
        yield 'a removal naming an empty one' => [FactorChange::REMOVE, ''];
        yield 'a removal naming one too long' => [FactorChange::REMOVE, str_repeat('f', 256)];
        yield 'an addition naming one' => [FactorChange::ADD, 'factor-a'];
        yield 'a first factor naming one' => [FactorChange::ADD_FIRST, 'factor-a'];
        yield 'recovery codes naming one' => [FactorChange::GENERATE_RECOVERY_CODES, 'factor-a'];
    }

    /**
     * A change that misnames its factor is a programming error, refused with an
     * `InvalidArgumentException` before anything is read.
     *
     * @param  \SineMacula\Laravel\Authentication\Factors\Enums\FactorChange  $change
     * @param  ?string  $factor
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideMisnamedFactors')]
    public function testAMisnamedFactorIsRefusedBeforeAnythingIsRead(FactorChange $change, ?string $factor): void
    {
        $signedIn = $this->signedIn();
        $sessions = $this->sessions();
        $queries  = 0;

        DB::listen(static function () use (&$queries): void {
            $queries++;
        });

        try {
            $sessions->factorChange($signedIn->record, $change, factor: $factor);

            self::fail('The misnamed factor was not refused.');
        } catch (\InvalidArgumentException $exception) {
            self::assertStringContainsString($change->value, $exception->getMessage());
        }

        self::assertSame(0, $queries);
    }

    /**
     * A factor of 255 characters is named in full.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFactorOf255CharactersIsNamed(): void
    {
        $signedIn = $this->signedIn();

        $this->stepUp($signedIn, 'factor-a', $this->now);

        self::assertTrue($this->sessions()->factorChange($signedIn->record, FactorChange::REMOVE, factor: str_repeat("\u{1F511}", 255))->isAllowed());
    }

    /**
     * The gate locks the session's row and writes nothing: no session column,
     * no proof and no event changes, inside or outside a caller's transaction.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheGateLocksTheSessionAndWritesNothing(): void
    {
        $signedIn = $this->signedIn();

        $this->stepUp($signedIn, 'factor-a', $this->now);

        $connection = DB::connection();

        if ($connection->getDriverName() === 'sqlite') {
            $connection->setQueryGrammar(new LockMarkingSQLiteGrammar($connection));
        }

        $before = [DB::table('authentication_sessions')->sole(), DB::table('authentication_proofs')->count()];
        $sql    = [];

        $connection->listen(static function (QueryExecuted $query) use (&$sql): void {
            $sql[] = strtolower($query->sql);
        });

        $events = [];

        Event::listen('SineMacula\Laravel\Authentication\*', static function (string $event) use (&$events): void {
            $events[] = $event;
        });

        $verdict = DB::transaction(fn (): FactorChangeVerdict => $this->sessions()->factorChange($signedIn->record, FactorChange::ADD));

        self::assertTrue($verdict->isAllowed());
        self::assertTrue(str_contains($sql[0], 'authentication_sessions') && str_contains($sql[0], 'for update'));
        self::assertSame([], array_filter($sql, static fn (string $query): bool => !str_starts_with($query, 'select')));
        self::assertEquals($before, [DB::table('authentication_sessions')->sole(), DB::table('authentication_proofs')->count()]);
        self::assertSame([], $events);

        $this->sessions()->reauthenticate($signedIn->record, 'password', self::credentials());

        self::assertContains(Reauthenticated::class, $events);
    }

    /**
     * The gate judges freshness on the session's proofs as committed: inside
     * its lock, the package's policy reads the session's row again with a
     * locking read and its proofs with a shared lock (on MySQL and MariaDB, the
     * marked SQLite included). A bound policy is asked current too, and one
     * that passes that on to the package's reads the same way.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheGateJudgesFreshnessOnTheProofsAsCommitted(): void
    {
        $signedIn = $this->signedIn();

        $this->stepUp($signedIn, 'factor-a', $this->now);

        self::markSharedLocks();

        $gate = fn (): FactorChangeVerdict => DB::transaction(fn (): FactorChangeVerdict => $this->sessions()->factorChange($signedIn->record, FactorChange::ADD));

        $verdict    = null;
        $statements = self::statementsDuring(static function () use ($gate, &$verdict): void {
            $verdict = $gate();
        });

        self::assertTrue($verdict?->isAllowed());
        self::assertCount(3, $statements);
        self::assertSame([true, true], array_map(self::locksForUpdate(...), array_slice($statements, 0, 2)));
        self::assertStringContainsString('authentication_sessions', $statements[1]);
        self::assertSame([self::takesSharedLocks()], self::proofReadLocks($gate));

        $decorating = new DecoratingFreshness(app(ConfiguredFreshness::class));

        app()->instance(FreshnessPolicy::class, $decorating);

        self::assertSame([self::takesSharedLocks()], self::proofReadLocks($gate));
        self::assertSame(['requirement', 'freshProof (current)'], $decorating->asked);
    }

    /**
     * Register the session guards.
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
     * @param  string  $guard
     * @return \SineMacula\Laravel\Authentication\Sessions\SignedInSession
     *
     * @throws \Throwable
     */
    private function signedIn(string $guard = 'api'): SignedInSession
    {
        $this->seedIdentity();

        $session = $this->sessions($guard)->signIn('password', self::credentials())->session;

        self::assertNotNull($session);

        return $session;
    }

    /**
     * Step the session up with the factor, at the time given, through the
     * session service.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignedInSession  $signedIn
     * @param  string  $factor
     * @param  \Carbon\CarbonImmutable  $at
     * @return void
     *
     * @throws \Throwable
     */
    private function stepUp(SignedInSession $signedIn, string $factor, CarbonImmutable $at): void
    {
        $guard = (string) $signedIn->record->getGuard();
        $proof = new ProofResult(
            ProofKind::ADDITIONAL_FACTOR,
            'totp',
            new Channel(ChannelKind::AUTHENTICATOR_APP),
            $factor,
            new ObservedProperties,
            new Evaluation(true, true),
            ['otp'],
            $at,
            new ProofBinding($signedIn->identity, $guard, $signedIn->record->getKey(), Purpose::STEP_UP),
        );

        $now = CarbonImmutable::now();

        $this->clockAt($at);

        self::assertTrue($this->sessions($guard)->stepUp($proof)->isIssued());

        $this->clockAt($now);
    }

    /**
     * Assert the change was refused with the reason, with no proof and no
     * deadline.
     *
     * @param  \SineMacula\Laravel\Authentication\Factors\FactorChangeVerdict  $verdict
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\FailureReason  $reason
     * @return void
     */
    private function assertRefused(FactorChangeVerdict $verdict, FailureReason $reason): void
    {
        self::assertFalse($verdict->isAllowed());
        self::assertSame($reason, $verdict->reason);
        self::assertNull($verdict->proof);
        self::assertNull($verdict->freshUntil);
    }

    /**
     * Move the clocks to the time given.
     *
     * @param  \Carbon\CarbonImmutable  $at
     * @return void
     */
    private function clockAt(CarbonImmutable $at): void
    {
        Carbon::setTestNow($at);
        CarbonImmutable::setTestNow($at);

        JWT::$timestamp = $at->getTimestamp();
    }
}
