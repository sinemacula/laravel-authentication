<?php

declare(strict_types = 1);

namespace Tests\Feature\Sessions;

use Carbon\CarbonImmutable;
use Firebase\JWT\JWT;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\ConnectionResolverInterface;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Foundation\Application;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Mockery\MockInterface;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Admission\Admitted;
use SineMacula\Laravel\Authentication\Contracts\AdditionalFactorPolicy;
use SineMacula\Laravel\Authentication\Contracts\ApplicationAccess;
use SineMacula\Laravel\Authentication\Contracts\TenantAccess;
use SineMacula\Laravel\Authentication\Database\AfterCommit;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\Enums\RevocationReason;
use SineMacula\Laravel\Authentication\Events\SessionRevoked;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Models\Session;
use SineMacula\Laravel\Authentication\Sessions\AdmissionRecheck;
use SineMacula\Laravel\Authentication\Sessions\RevocationWriter;
use SineMacula\Laravel\Authentication\Sessions\SignedInSession;
use Tests\Concerns\InteractsWithRecheckedMembers;
use Tests\Concerns\InteractsWithSessions;
use Tests\Integration\Fixtures\ActivatableTenant;
use Tests\Integration\Fixtures\IntegrationIdentity;
use Tests\Integration\Fixtures\RecheckedMember;
use Tests\Integration\Fixtures\RecheckedMembership;
use Tests\TestCase;

/**
 * Feature tests for the check a session written by a sign-in, a choice or a
 * switch is held to once committed: what it newly acts as is read again,
 * afresh, and judged on its standing alone; a session that fails is revoked
 * with the matching reason, the call answers the refusal when it has not
 * answered yet, and the reports the call scheduled run only once the check
 * passed.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AdmissionRecheck::class)]
final class AdmissionRecheckTest extends TestCase
{
    use InteractsWithRecheckedMembers, InteractsWithSessions;

    /** @var string The guard the members sign in through. */
    private const string GUARD = 'rechecked';

    /** @var string A second connection to the test database, which a subject may live on. */
    private const string ELSEWHERE = 'elsewhere';

    /**
     * Freeze the clocks and create the tables.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->freezeAt(CarbonImmutable::createStrict(2026, 4, 6, 12, 0, 0));

        $this->createSessionTables();
        $this->createRecheckedTables();
    }

    /**
     * Drop the tables and release the clocks.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $this->dropRecheckedTables();
        $this->dropSessionTables();

        Carbon::setTestNow();
        CarbonImmutable::setTestNow();

        JWT::$timestamp = null;

        parent::tearDown();
    }

    /**
     * Rows of `[what changes after the sign-in admitted the member, the
     * refusal, the revocation reason]`.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @return iterable<string, array{0: \Closure(\Tests\Integration\Fixtures\RecheckedMember, \Tests\Integration\Fixtures\RecheckedMembership, \Tests\Integration\Fixtures\ActivatableTenant): mixed, 1: \SineMacula\Laravel\Authentication\Events\Enums\FailureReason, 2: \SineMacula\Laravel\Authentication\Events\Enums\RevocationReason}>
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    public static function provideChanges(): iterable
    {
        yield 'identity soft-deleted' => [static fn (RecheckedMember $member): mixed => $member->delete(), FailureReason::IDENTITY_UNKNOWN, RevocationReason::IDENTITY_DELETED];
        yield 'identity deleted' => [static fn (RecheckedMember $member): mixed => $member->forceDelete(), FailureReason::IDENTITY_UNKNOWN, RevocationReason::IDENTITY_DELETED];
        yield 'identity deactivated' => [
            static fn (RecheckedMember $member): mixed => $member->update(['is_active' => false]),
            FailureReason::IDENTITY_INACTIVE,
            RevocationReason::IDENTITY_DEACTIVATED,
        ];
        yield 'identity cut off after the call began' => [
            static fn (RecheckedMember $member): mixed => $member->update(['tokens_valid_after' => CarbonImmutable::now()->addSecond()]),
            FailureReason::ISSUED_BEFORE_CUTOFF,
            RevocationReason::SIGNED_OUT_EVERYWHERE,
        ];
        yield 'principal soft-deleted' => [
            static fn (RecheckedMember $member, RecheckedMembership $membership): mixed => $membership->delete(),
            FailureReason::PRINCIPAL_UNRESOLVED,
            RevocationReason::PRINCIPAL_DELETED,
        ];
        yield 'principal deactivated' => [
            static fn (RecheckedMember $member, RecheckedMembership $membership): mixed => $membership->update(['is_active' => false]),
            FailureReason::PRINCIPAL_INACTIVE,
            RevocationReason::PRINCIPAL_DEACTIVATED,
        ];
        yield 'principal cut off after the call began' => [
            static fn (RecheckedMember $member, RecheckedMembership $membership): mixed => $membership->update(['tokens_valid_after' => CarbonImmutable::now()->addSecond()]),
            FailureReason::ISSUED_BEFORE_CUTOFF,
            RevocationReason::SIGNED_OUT_EVERYWHERE,
        ];
        yield 'tenant deactivated' => [
            static fn (RecheckedMember $member, RecheckedMembership $membership, ActivatableTenant $tenant): mixed => $tenant->update(['is_active' => false]),
            FailureReason::TENANT_INACTIVE,
            RevocationReason::TENANT_DEACTIVATED,
        ];
        yield 'tenant soft-deleted' => [
            static fn (RecheckedMember $member, RecheckedMembership $membership, ActivatableTenant $tenant): mixed => $tenant->delete(),
            FailureReason::TENANT_INACTIVE,
            RevocationReason::TENANT_DEACTIVATED,
        ];
    }

    /**
     * A sign-in's session whose identity, principal or tenant stopped standing
     * after the sign-in admitted it is revoked with the matching reason once
     * checked, the call is left the refusal to answer with (naming what the
     * session acted as), the reports it scheduled never run, and no
     * `SessionRevoked` is reported for a session the call never handed out.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  \Closure(\Tests\Integration\Fixtures\RecheckedMember, \Tests\Integration\Fixtures\RecheckedMembership, \Tests\Integration\Fixtures\ActivatableTenant): mixed  $change
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\FailureReason  $refusal
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\RevocationReason  $revoked
     * @return void
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     *
     * @throws \Throwable
     */
    #[DataProvider('provideChanges')]
    public function testASignInsSessionThatNoLongerStandsIsRevokedAndRefused(\Closure $change, FailureReason $refusal, RevocationReason $revoked): void
    {
        [$member, $membership, $tenant] = $this->seedRechecked();

        $session = $this->signIn();
        $recheck = $this->recheck();
        $ran     = false;

        $change($member, $membership, $tenant);

        $this->recordEvents([SessionRevoked::class]);

        $recheck->signIn($session->record, $member, $membership, $tenant);
        $recheck->then($session->record, static function () use (&$ran): void {
            $ran = true;
        });

        $refused = $recheck->refusal();

        self::assertNotNull($refused);
        self::assertSame($refusal, $refused->reason);
        self::assertSame([$member, $membership, $tenant], [$refused->identity, $refused->principal, $refused->tenant]);
        self::assertSame($revoked->value, self::revokedReasonOf($session));
        self::assertFalse($ran);
        self::assertSame([], $this->recordedClasses());
    }

    /**
     * A session whose identity, principal and tenant all still stand passes:
     * nothing is revoked, the call has no refusal, and the reports run, at once
     * with no transaction open, in the order they were scheduled.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASessionThatStillStandsPassesAndItsReportsRun(): void
    {
        [$member, $membership, $tenant] = $this->seedRechecked();

        $session = $this->signIn();
        $recheck = $this->recheck();
        $ran     = [];

        $recheck->signIn($session->record, $member, $membership, $tenant);
        $recheck->then($session->record, static function () use (&$ran): void {
            $ran[] = 'first';
        });
        $recheck->then($session->record, static function () use (&$ran): void {
            $ran[] = 'second';
        });

        self::assertNull($recheck->refusal());
        self::assertSame(['first', 'second'], $ran);
        self::assertNull(self::revokedReasonOf($session));
    }

    /**
     * Rows of `[the cutoff relative to the second the call began, whether the
     * session passes]`.
     *
     * @return iterable<string, array{0: int, 1: bool}>
     */
    public static function provideCutoffs(): iterable
    {
        yield 'a second before the call began' => [-1, true];
        yield 'the second the call began' => [0, true];
        yield 'a second after the call began' => [1, false];
    }

    /**
     * Only a cutoff strictly after the second the call began ends the session:
     * one moved in that second, or before, is the trace of a revocation the
     * session's call does not postdate.
     *
     * @param  int  $offset
     * @param  bool  $passes
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideCutoffs')]
    public function testOnlyACutoffAfterTheCallBeganEndsTheSession(int $offset, bool $passes): void
    {
        [$member, $membership, $tenant] = $this->seedRechecked();

        $session = $this->signIn();
        $recheck = $this->recheck();

        $member->update(['tokens_valid_after' => $recheck->began->addSeconds($offset)]);
        $membership->update(['tokens_valid_after' => $recheck->began->addSeconds($offset)]);

        $recheck->signIn($session->record, $member, $membership, $tenant);

        self::assertSame($passes, $recheck->refusal() === null);
    }

    /**
     * A pending sign-in that records no principal yet is checked for its
     * identity alone, with one read.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPendingSessionWithoutAPrincipalIsCheckedForItsIdentityAlone(): void
    {
        [$member, $membership, $tenant] = $this->seedRechecked();

        $session = $this->signIn();
        $passing = $this->recheck();

        $membership->update(['is_active' => false]);
        $tenant->update(['is_active' => false]);

        self::assertSame(1, self::readsOf(static fn () => $passing->signIn($session->record, $member, null, null)));
        self::assertNull($passing->refusal());

        $member->update(['is_active' => false]);

        $failing = $this->recheck();

        $failing->signIn($session->record, $member, null, null);

        self::assertSame(FailureReason::IDENTITY_INACTIVE, $failing->refusal()?->reason);
    }

    /**
     * A 2D identity, its own principal, is read once and judged as the identity
     * and as the principal.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnIdentityThatIsItsOwnPrincipalIsReadOnce(): void
    {
        $identity = $this->seedIdentity();
        $session  = $this->sessions()->signIn('password', self::credentials())->session;

        self::assertNotNull($session);

        $recheck = $this->recheck('api');

        self::assertSame(1, self::readsOf(static fn () => $recheck->signIn($session->record, $identity, $identity, null)));
        self::assertNull($recheck->refusal());

        IntegrationIdentity::query()->whereKey($identity->getKey())->update(['is_active' => false]);

        $choice = $this->recheck('api');

        $choice->choice($session->record, new Admitted($identity, $identity, null));

        self::assertSame(FailureReason::PRINCIPAL_INACTIVE, $choice->refusal()?->reason);
    }

    /**
     * A choice is checked for the principal chosen and the tenant it acts in,
     * never for the identity, which the pending session already records; a
     * failed choice ends a session the client holds, so its revocation is
     * reported, though the call has not answered, and a guard bound to it
     * forgets it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAChoiceIsCheckedForItsPrincipalAndTenantAndReportsItsRevocation(): void
    {
        [$member, $membership, $tenant] = $this->seedRechecked();

        $session = $this->signIn();
        $guard   = $this->guard();

        $member->update(['is_active' => false]);

        $passing = $this->recheck();

        $passing->choice($session->record, new Admitted($member, $membership, $tenant));

        self::assertNull($passing->refusal());

        $guard->login($member, $membership, $session->record);
        $membership->update(['is_active' => false]);

        $this->recordEvents([SessionRevoked::class]);

        $failing = $this->recheck();

        $failing->choice($session->record, new Admitted($member, $membership, $tenant));

        self::assertSame(FailureReason::PRINCIPAL_INACTIVE, $failing->refusal()?->reason);
        self::assertSame([SessionRevoked::class], $this->recordedClasses());
        self::assertSame(RevocationReason::PRINCIPAL_DEACTIVATED, $this->recordedEvent(SessionRevoked::class)->reason);
        self::assertSame(self::client(), $this->recordedEvent(SessionRevoked::class)->context->client);
        self::assertNull($guard->session());
    }

    /**
     * A switch is checked for what it changed: a switch of tenant alone reads
     * the active tenant again and not the principal's own standing, a switch
     * that changed nothing is checked for nothing and its reports run as
     * `AfterCommit` runs them, and a failed switch reports the revocation of
     * the session the client held.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASwitchIsCheckedForWhatItChanged(): void
    {
        [$member, $membership, $tenant] = $this->seedRechecked();

        $session     = $this->signIn();
        $destination = new Admitted($member, $membership, $tenant);

        $membership->update(['is_active' => false]);

        $unchanged = $this->recheck();
        $ran       = false;

        self::assertSame(0, self::readsOf(static fn () => $unchanged->switch($session->record, $destination, false, false)));

        $unchanged->then($session->record, static function () use (&$ran): void {
            $ran = true;
        });

        self::assertTrue($ran);
        self::assertNull($unchanged->refusal());

        $tenantOnly = $this->recheck();

        $tenantOnly->switch($session->record, $destination, false, true);

        self::assertNull($tenantOnly->refusal());

        $tenant->update(['is_active' => false]);

        $this->recordEvents([SessionRevoked::class]);

        $refused = $this->recheck();

        $refused->switch($session->record, $destination, false, true);

        self::assertSame(FailureReason::TENANT_INACTIVE, $refused->refusal()?->reason);
        self::assertSame(RevocationReason::TENANT_DEACTIVATED, $this->recordedEvent(SessionRevoked::class)->reason);
    }

    /**
     * No access contract is asked again: an `ApplicationAccess` or a
     * `TenantAccess` that would now refuse the principal, or a factor policy
     * that would now ask for a factor, does not end a session whose identity,
     * principal and tenant still stand.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testNoAccessContractIsAskedAgain(): void
    {
        [$member, $membership, $tenant] = $this->seedRechecked();

        $session = $this->signIn();

        $this->bindMock(ApplicationAccess::class)->shouldNotReceive('mayUse');
        $this->bindMock(TenantAccess::class)->shouldNotReceive('mayActIn');
        $this->bindMock(AdditionalFactorPolicy::class)->shouldNotReceive('requirementFor');

        $recheck = $this->recheck();

        $recheck->signIn($session->record, $member, $membership, $tenant);

        self::assertNull($recheck->refusal());
    }

    /**
     * Inside a transaction on the session's connection the check waits for its
     * commit, the reports with it, and a rollback runs neither; a check that
     * fails after the call answered reports the revocation, makes no refusal,
     * and forgets a binding to the session.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testInsideATransactionTheCheckWaitsForTheCommit(): void
    {
        [$member, $membership, $tenant] = $this->seedRechecked();

        $session = $this->signIn();
        $guard   = $this->guard();
        $ran     = false;

        DB::beginTransaction();

        $rolledBack = $this->recheck();

        $rolledBack->signIn($session->record, $member, $membership, $tenant);
        $rolledBack->then($session->record, static function () use (&$ran): void {
            $ran = true;
        });

        RecheckedMember::query()->whereKey($member->getKey())->update(['is_active' => false]);

        DB::rollBack();

        self::assertFalse($ran);
        self::assertNull($rolledBack->refusal());
        self::assertNull(self::revokedReasonOf($session));

        $this->recordEvents([SessionRevoked::class]);

        DB::beginTransaction();

        $committed = $this->recheck();

        $committed->signIn($session->record, $member, $membership, $tenant);
        $committed->then($session->record, static function () use (&$ran): void {
            $ran = true;
        });

        self::assertNull($committed->refusal());

        $guard->login($member, $membership, $session->record);

        RecheckedMember::query()->whereKey($member->getKey())->update(['is_active' => false]);

        self::assertNull(self::revokedReasonOf($session));

        DB::commit();

        self::assertFalse($ran);
        self::assertNull($committed->refusal());
        self::assertSame(RevocationReason::IDENTITY_DEACTIVATED->value, self::revokedReasonOf($session));
        self::assertSame([SessionRevoked::class], $this->recordedClasses());
        self::assertNull($guard->session());
    }

    /**
     * A transaction open on the connection a subject lives on, though none is
     * on the session's, holds the check until it commits too, since the subject
     * read through it would be read as that transaction sees it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATransactionOnASubjectsConnectionHoldsTheCheck(): void
    {
        [$member, $membership, $tenant] = $this->seedRechecked();

        $session   = $this->signIn();
        $elsewhere = (new RecheckedMember)->newFromBuilder($member->getAttributes())->setConnection(self::ELSEWHERE);
        $ran       = new \ArrayObject;

        DB::connection(self::ELSEWHERE)->beginTransaction();

        $recheck = $this->recheck();

        $recheck->signIn($session->record, $elsewhere, $membership, $tenant);
        $recheck->then($session->record, static function () use ($ran): void {
            $ran->append('report');
        });

        self::assertCount(0, $ran);

        DB::connection(self::ELSEWHERE)->commit();

        self::assertCount(1, $ran);
        self::assertNull($recheck->refusal());
    }

    /**
     * Register the guards.
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
        self::configureRecheckedGuard($config);

        $config->set('database.connections.' . self::ELSEWHERE, $config->get('database.connections.' . $config->string('database.default')));
    }

    /**
     * Sign the seeded member in and move the clocks a second on, so a check
     * begins after it.
     *
     * @return \SineMacula\Laravel\Authentication\Sessions\SignedInSession
     *
     * @throws \Throwable
     */
    private function signIn(): SignedInSession
    {
        $session = $this->sessions(self::GUARD)->signIn('password', self::credentials('rechecked@example.test'))->session;

        self::assertNotNull($session);

        $this->freezeAt(CarbonImmutable::now()->addSecond());

        return $session;
    }

    /**
     * The check of a call through the guard, for the plain client, begun now.
     *
     * @param  string  $guard
     * @return \SineMacula\Laravel\Authentication\Sessions\AdmissionRecheck
     */
    private function recheck(string $guard = self::GUARD): AdmissionRecheck
    {
        $resolved     = $this->guard($guard);
        $transactions = static fn (): mixed => app('db.transactions');

        return new AdmissionRecheck(
            $resolved->context(),
            $resolved,
            new RevocationWriter(app(ConnectionResolverInterface::class), $transactions),
            new AfterCommit($transactions),
            self::client(),
            CarbonImmutable::now()->startOfSecond(),
        );
    }

    /**
     * The guard as the auth manager holds it now.
     *
     * @param  string  $name
     * @return \SineMacula\Laravel\Authentication\Guards\JwtGuard
     */
    private function guard(string $name = self::GUARD): JwtGuard
    {
        $guard = app('auth')->guard($name);

        self::assertInstanceOf(JwtGuard::class, $guard);

        return $guard;
    }

    /**
     * The client the calls are made for.
     *
     * @return \SineMacula\Laravel\Authentication\Http\ClientContext
     */
    private static function client(): ClientContext
    {
        static $client = null;

        return $client ??= new ClientContext(self::PLAIN_IP, self::PLAIN_AGENT);
    }

    /**
     * Bind a mock of the contract in the container.
     *
     * @param  class-string  $contract
     * @return \Mockery\MockInterface
     */
    private function bindMock(string $contract): MockInterface
    {
        $mock = \Mockery::mock($contract);

        app()->instance($contract, $mock);

        return $mock;
    }

    /**
     * How many reads the work runs.
     *
     * @param  \Closure(): mixed  $work
     * @return int
     */
    private static function readsOf(\Closure $work): int
    {
        $reads = 0;

        DB::listen(static function (QueryExecuted $query) use (&$reads): void {
            $reads += str_starts_with(strtolower($query->sql), 'select') ? 1 : 0;
        });

        $work();

        return $reads;
    }

    /**
     * Why the session's row records it was revoked, if it was.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignedInSession  $session
     * @return mixed
     */
    private static function revokedReasonOf(SignedInSession $session): mixed
    {
        return Session::query()->whereKey($session->record->getKey())->value('revoked_reason');
    }

    /**
     * Freeze every clock at the time.
     *
     * @param  \Carbon\CarbonImmutable  $time
     * @return void
     */
    private function freezeAt(CarbonImmutable $time): void
    {
        Carbon::setTestNow($time);
        CarbonImmutable::setTestNow($time);

        JWT::$timestamp = $time->getTimestamp();
    }
}
