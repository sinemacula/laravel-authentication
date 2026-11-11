<?php

declare(strict_types = 1);

namespace Tests\Feature\Sessions;

use Carbon\CarbonImmutable;
use Firebase\JWT\JWT;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\ConnectionResolverInterface;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Foundation\Application;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Exceptions;
use Mockery\MockInterface;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Admission\Admitted;
use SineMacula\Laravel\Authentication\Contracts\AdditionalFactorPolicy;
use SineMacula\Laravel\Authentication\Contracts\ApplicationAccess;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\PrincipalResolver;
use SineMacula\Laravel\Authentication\Contracts\TenantAccess;
use SineMacula\Laravel\Authentication\Contracts\TenantResolver;
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
use SineMacula\Laravel\Authentication\Sessions\WatchedSessions;
use Tests\Concerns\InteractsWithRecheckedMembers;
use Tests\Concerns\InteractsWithSessions;
use Tests\Fixtures\Sessions\PlainPrincipalResolver;
use Tests\Fixtures\Tenancy\DescendantTenants;
use Tests\Integration\Fixtures\ActivatableTenant;
use Tests\Integration\Fixtures\IntegrationIdentity;
use Tests\Integration\Fixtures\RecheckedMember;
use Tests\Integration\Fixtures\RecheckedMembership;
use Tests\TestCase;
use Tests\Unit\Stubs\PlainPrincipalFixture;
use Tests\Unit\Stubs\StubPrincipal;

/**
 * Feature tests of the check a committed sign-in, choice or switch session is
 * held to.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AdmissionRecheck::class)]
#[CoversClass(WatchedSessions::class)]
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
     * Rows of `[change after admission, refusal, revocation reason]`.
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
     * A sign-in's session that no longer stands is revoked and refused, and its
     * reports never run.
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
        $stood   = false;

        $change($member, $membership, $tenant);

        $this->recordEvents([SessionRevoked::class]);

        $recheck->signIn($session->record, $member, $membership, $tenant);
        $recheck->then($session->record, static function () use (&$ran): void {
            $ran = true;
        });
        $recheck->afterCheck($session->record, static function () use (&$stood): void {
            $stood = true;
        });

        $refused = $recheck->refusal();

        self::assertNotNull($refused);
        self::assertSame($refusal, $refused->reason);
        self::assertSame([$member, $membership, $tenant, null], [$refused->identity, $refused->principal, $refused->tenant, $refused->session]);
        self::assertSame($revoked->value, self::revokedReasonOf($session));
        self::assertFalse($ran);
        self::assertTrue($stood);
        self::assertSame([], $this->recordedClasses());
    }

    /**
     * A session that still stands passes and its reports run in order.
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
     * Rows of `[cutoff relative to the call's start, whether the session
     * passes]`.
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
     * Only a cutoff strictly after the second the call began ends the session.
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
     * An identity that is its own principal is read once.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnIdentityThatIsItsOwnPrincipalIsReadOnce(): void
    {
        $identity = $this->seedIdentity();
        $session  = $this->sessions()->signIn('password', self::credentials(), self::requestContext())->session;

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
     * A choice is checked for its principal and tenant, and a failed one
     * reports its revocation.
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

        $refused = $failing->refusal();

        self::assertNotNull($refused);
        self::assertSame(FailureReason::PRINCIPAL_INACTIVE, $refused->reason);
        self::assertSame($session->record, $refused->session);
        self::assertSame([SessionRevoked::class], $this->recordedClasses());
        self::assertSame(RevocationReason::PRINCIPAL_DEACTIVATED, $this->recordedEvent(SessionRevoked::class)->reason);
        self::assertSame(self::client(), $this->recordedEvent(SessionRevoked::class)->context->client);
        self::assertNull($guard->session());
    }

    /**
     * A switch is checked only for what it changed.
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
     * No access contract or factor policy is asked again.
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
     * Inside a transaction the check and its reports wait for the commit.
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
     * A transaction on a subject's connection holds the check until it commits.
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
     * A rolled back transaction on a subject's connection still lets the check
     * run.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATransactionOnASubjectsConnectionThatRollsBackStillLetsTheCheckRun(): void
    {
        [$member, $membership, $tenant] = $this->seedRechecked();

        $session   = $this->signIn();
        $guard     = $this->guard();
        $elsewhere = (new RecheckedMember)->newFromBuilder($member->getAttributes())->setConnection(self::ELSEWHERE);
        /** @var \ArrayObject<int, string> $ran */
        $ran = new \ArrayObject;

        DB::connection(self::ELSEWHERE)->beginTransaction();

        $passing = $this->recheck();

        $passing->signIn($session->record, $elsewhere, $membership, $tenant);
        $passing->then($session->record, static function () use ($ran): void {
            $ran->append('passed');
        });

        self::assertNull($passing->refusal());
        self::assertCount(0, $ran);

        DB::connection(self::ELSEWHERE)->rollBack();

        self::assertSame(['passed'], $ran->getArrayCopy());

        DB::connection(self::ELSEWHERE)->beginTransaction();

        $failing = $this->recheck();

        $failing->signIn($session->record, $elsewhere, $membership, $tenant);
        $failing->then($session->record, static function () use ($ran): void {
            $ran->append('failed');
        });

        self::assertNull($failing->refusal());

        $guard->login($member, $membership, $session->record);

        RecheckedMember::query()->whereKey($member->getKey())->update(['is_active' => false]);

        $this->recordEvents([SessionRevoked::class]);

        DB::connection(self::ELSEWHERE)->rollBack();

        self::assertSame(['passed'], $ran->getArrayCopy());
        self::assertSame(RevocationReason::IDENTITY_DEACTIVATED->value, self::revokedReasonOf($session));
        self::assertSame([SessionRevoked::class], $this->recordedClasses());
        self::assertNull($guard->session());
    }

    /**
     * A report that stands whatever the check finds runs after the check.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAReportThatStandsWhateverTheCheckFindsRunsAfterIt(): void
    {
        [$member, $membership, $tenant] = $this->seedRechecked();

        $session = $this->signIn();
        /** @var \ArrayObject<int, string> $order */
        $order = new \ArrayObject;

        DB::beginTransaction();

        $passing = $this->recheck();

        $passing->signIn($session->record, $member, $membership, $tenant);
        $passing->afterCheck($session->record, static function () use ($order): void {
            $order->append('superseded');
        });
        $passing->then($session->record, static function () use ($order): void {
            $order->append('created');
        });

        DB::commit();

        self::assertSame(['superseded', 'created'], $order->getArrayCopy());

        DB::beginTransaction();

        $failing = $this->recheck();

        $failing->signIn($session->record, $member, $membership, $tenant);
        $failing->afterCheck($session->record, static function (): void {
            throw new \RuntimeException('listener');
        });
        $failing->then($session->record, static function () use ($order): void {
            $order->append('never');
        });

        self::assertNull($failing->refusal());

        RecheckedMember::query()->whereKey($member->getKey())->update(['is_active' => false]);

        $exceptions = Exceptions::fake();

        DB::commit();

        self::assertSame(['listener'], array_map(static fn (\Throwable $exception): string => $exception->getMessage(), $exceptions->reported()));

        self::assertSame(RevocationReason::IDENTITY_DEACTIVATED->value, self::revokedReasonOf($session));
        self::assertSame(['superseded', 'created'], $order->getArrayCopy());
    }

    /**
     * A principal other than the one recorded counts as unresolved.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnotherPrincipalAnsweredInPlaceOfTheOneRecordedIsNoneAtAll(): void
    {
        [$member, $membership, $tenant] = $this->seedRechecked();

        $session = $this->signIn();
        $other   = RecheckedMembership::query()->create(['identity_id' => $member->getKey(), 'tenant_id' => $tenant->getKey(), 'is_active' => true]);

        $membership->delete();

        $answered = $this->guard()->context()->resolver()->resolve($member, $membership->getKey());

        self::assertInstanceOf(RecheckedMembership::class, $answered);
        self::assertSame($other->getKey(), $answered->getKey());

        $signIn = $this->recheck();

        $signIn->signIn($session->record, $member, $membership, $tenant);

        self::assertSame(FailureReason::PRINCIPAL_UNRESOLVED, $signIn->refusal()?->reason);
        self::assertSame(RevocationReason::PRINCIPAL_DELETED->value, self::revokedReasonOf($session));

        $choice = $this->recheck();

        $choice->choice($session->record, new Admitted($member, $membership, $tenant));

        self::assertSame(FailureReason::PRINCIPAL_UNRESOLVED, $choice->refusal()?->reason);
    }

    /**
     * Rows of `[resolver answer for the principal, refusal or null when it
     * passes]`.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @return iterable<string, array{0: \Closure(\SineMacula\Laravel\Authentication\Contracts\Identity): ?\SineMacula\Laravel\Authentication\Contracts\Principal, 1: ?\SineMacula\Laravel\Authentication\Events\Enums\FailureReason}>
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    public static function providePlainPrincipals(): iterable
    {
        yield 'the same principal, active' => [static fn (Identity $identity): Principal => new PlainPrincipalFixture(7, $identity), null];
        yield 'the same principal, inactive' => [
            static fn (Identity $identity): Principal => new PlainPrincipalFixture(7, $identity, active: false),
            FailureReason::PRINCIPAL_INACTIVE,
        ];
        yield 'another principal' => [static fn (Identity $identity): Principal => new PlainPrincipalFixture(8, $identity), FailureReason::PRINCIPAL_UNRESOLVED];
        yield 'a principal of another type' => [static fn (): Principal => (new StubPrincipal)->forceFill(['id' => 7]), FailureReason::PRINCIPAL_UNRESOLVED];
        yield 'no principal' => [static fn (): ?Principal => null, FailureReason::PRINCIPAL_UNRESOLVED];
    }

    /**
     * A principal that is no model is resolved again through the guard's
     * resolver.
     *
     * @param  \Closure(\SineMacula\Laravel\Authentication\Contracts\Identity): ?\SineMacula\Laravel\Authentication\Contracts\Principal  $answer
     * @param  ?\SineMacula\Laravel\Authentication\Events\Enums\FailureReason  $refusal
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('providePlainPrincipals')]
    public function testAPrincipalThatIsNoModelIsResolvedAgainThroughTheGuardsResolver(\Closure $answer, ?FailureReason $refusal): void
    {
        [$member] = $this->seedRechecked();

        $session  = $this->signIn();
        $resolver = new PlainPrincipalResolver($answer($member));

        app()->instance(PrincipalResolver::class, $resolver);

        $recheck = $this->recheck();

        self::assertSame($resolver, $this->guard()->context()->resolver());

        $recheck->signIn($session->record, $member, new PlainPrincipalFixture(7, $member), null);

        self::assertSame($refusal, $recheck->refusal()?->reason);
        self::assertSame(['7'], $resolver->hints);
    }

    /**
     * A tenant switch reads the principal again to resolve its tenant.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATenantSwitchReadsThePrincipalAgainForItsTenant(): void
    {
        [$member, $membership, $tenant] = $this->seedRechecked();

        $session = $this->signIn();

        self::assertNotNull($membership->getTenant());

        $tenant->update(['is_active' => false]);

        $tenantOnly = $this->recheck();

        $tenantOnly->switch($session->record, new Admitted($member, $membership, $tenant), false, true);

        self::assertSame(FailureReason::TENANT_INACTIVE, $tenantOnly->refusal()?->reason);

        $noTenant = $this->recheck();
        $ran      = false;

        self::assertSame(0, self::readsOf(static fn () => $noTenant->switch($session->record, new Admitted($member, $membership, null), false, true)));

        $noTenant->then($session->record, static function () use (&$ran): void {
            $ran = true;
        });

        self::assertTrue($ran);
        self::assertNull($noTenant->refusal());
    }

    /**
     * Rows of a change to an active tenant other than the principal's own.
     *
     * @return iterable<string, array{0: \Closure(\Tests\Integration\Fixtures\ActivatableTenant): mixed}>
     */
    public static function provideOtherTenantChanges(): iterable
    {
        yield 'deactivated' => [static fn (ActivatableTenant $tenant): mixed => $tenant->update(['is_active' => false])];
        yield 'soft-deleted' => [static fn (ActivatableTenant $tenant): mixed => $tenant->delete()];
    }

    /**
     * An active tenant other than the principal's own is judged on its own.
     *
     * @param  \Closure(\Tests\Integration\Fixtures\ActivatableTenant): mixed  $change
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideOtherTenantChanges')]
    public function testAnActiveTenantOtherThanThePrincipalsOwnIsJudgedOnItsOwn(\Closure $change): void
    {
        [$member, $membership] = $this->seedRechecked();

        $other   = ActivatableTenant::query()->create(['name' => 'Other', 'is_active' => true]);
        $session = $this->signIn();

        app()->instance(TenantResolver::class, new DescendantTenants);

        $standing = $this->recheck();

        $standing->signIn($session->record, $member, $membership, $other);

        self::assertNull($standing->refusal());

        $change($other);

        $signIn = $this->recheck();

        $signIn->signIn($session->record, $member, $membership, $other);

        self::assertSame(FailureReason::TENANT_INACTIVE, $signIn->refusal()?->reason);
        self::assertSame(RevocationReason::TENANT_DEACTIVATED->value, self::revokedReasonOf($session));

        $choice = $this->recheck();

        $choice->choice($session->record, new Admitted($member, $membership, $other));

        self::assertSame(FailureReason::TENANT_INACTIVE, $choice->refusal()?->reason);
    }

    /**
     * A principal's own tenant is judged with the principal.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPrincipalsOwnTenantIsJudgedWithThePrincipal(): void
    {
        [$member, $membership, $own] = $this->seedRechecked();

        $other   = ActivatableTenant::query()->create(['name' => 'Other', 'is_active' => true]);
        $session = $this->signIn();

        app()->instance(TenantResolver::class, new DescendantTenants);

        $own->update(['is_active' => false]);

        $none = $this->recheck();

        $none->signIn($session->record, $member, $membership, null);

        self::assertSame(FailureReason::TENANT_INACTIVE, $none->refusal()?->reason);
        self::assertSame(RevocationReason::TENANT_DEACTIVATED->value, self::revokedReasonOf($session));

        $another = $this->recheck();

        $another->choice($session->record, new Admitted($member, $membership, $other));

        self::assertSame(FailureReason::TENANT_INACTIVE, $another->refusal()?->reason);
    }

    /**
     * A tenant switch whose principal is gone ends the session.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATenantSwitchWhosePrincipalIsGoneEndsTheSession(): void
    {
        [$member, $membership, $tenant] = $this->seedRechecked();

        $session = $this->signIn();

        self::assertNotNull($membership->getTenant());

        $membership->delete();

        $recheck = $this->recheck();

        $recheck->switch($session->record, new Admitted($member, $membership, $tenant), false, true);

        self::assertSame(FailureReason::PRINCIPAL_UNRESOLVED, $recheck->refusal()?->reason);
        self::assertSame(RevocationReason::PRINCIPAL_DELETED->value, self::revokedReasonOf($session));
    }

    /**
     * Rows of `[cutoff move after a revocation that kept the session, whether
     * it passes]`.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @return iterable<string, array{0: \Closure(\Tests\Integration\Fixtures\RecheckedMember, \Tests\Integration\Fixtures\RecheckedMembership): mixed, 1: bool}>
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    public static function provideKeptSessions(): iterable
    {
        yield 'nothing more' => [static fn (): mixed => null, true];
        yield 'the identity\'s, a second later' => [
            static fn (RecheckedMember $member): mixed => $member->update(['tokens_valid_after' => CarbonImmutable::now()->addSecond()]),
            false,
        ];
        yield 'the principal\'s, in the same second' => [
            static fn (RecheckedMember $member, RecheckedMembership $membership): mixed => $membership->update(['tokens_valid_after' => CarbonImmutable::now()]),
            false,
        ];
    }

    /**
     * A cutoff moved by a revocation that kept the session does not end it.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  \Closure(\Tests\Integration\Fixtures\RecheckedMember, \Tests\Integration\Fixtures\RecheckedMembership): mixed  $then
     * @param  bool  $passes
     * @return void
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     *
     * @throws \Throwable
     */
    #[DataProvider('provideKeptSessions')]
    public function testACutoffMovedByARevocationThatKeptTheSessionDoesNotEndIt(\Closure $then, bool $passes): void
    {
        [$member, $membership, $tenant] = $this->seedRechecked();

        $session = $this->signIn();

        DB::beginTransaction();

        $recheck = $this->recheck();

        $recheck->signIn($session->record, $member, $membership, $tenant);

        self::assertNull($recheck->refusal());

        $this->freezeAt(CarbonImmutable::now()->addSecond());

        $this->sessions(self::GUARD)->passwordChanged($member, $session->record);

        $then($member, $membership);

        DB::commit();

        self::assertSame($passes ? null : RevocationReason::SIGNED_OUT_EVERYWHERE->value, self::revokedReasonOf($session));
        self::assertGreaterThan($recheck->began->getTimestamp(), $member->refresh()->getTokensValidAfter()?->getTimestamp());
    }

    /**
     * A kept session whose check waits on a subject's connection stands.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAKeptSessionWhoseCheckWaitsForASubjectsConnectionStands(): void
    {
        [$member, $membership, $tenant] = $this->seedRechecked();

        $session   = $this->signIn();
        $elsewhere = (new RecheckedMember)->newFromBuilder($member->getAttributes())->setConnection(self::ELSEWHERE);

        DB::connection(self::ELSEWHERE)->beginTransaction();

        $recheck = $this->recheck();

        $recheck->signIn($session->record, $elsewhere, $membership, $tenant);

        self::assertNull($recheck->refusal());

        $this->freezeAt(CarbonImmutable::now()->addSecond());

        $this->sessions(self::GUARD)->passwordChanged($member, $session->record);

        DB::connection(self::ELSEWHERE)->commit();

        self::assertNull(self::revokedReasonOf($session));
        self::assertGreaterThan($recheck->began->getTimestamp(), $member->refresh()->getTokensValidAfter()?->getTimestamp());
    }

    /**
     * Rows of `[change after a later principal switch, revocation reason or
     * null]`.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @return iterable<string, array{0: \Closure(\Tests\Integration\Fixtures\RecheckedMember, \Tests\Integration\Fixtures\RecheckedMembership, \Tests\Integration\Fixtures\ActivatableTenant): mixed, 1: ?\SineMacula\Laravel\Authentication\Events\Enums\RevocationReason}>
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    public static function provideChangesAfterAPrincipalSwitch(): iterable
    {
        yield 'the principal left, deactivated' => [
            static fn (RecheckedMember $member, RecheckedMembership $left): int => self::updateRow($left, ['is_active' => false]),
            null,
        ];
        yield 'the principal left, soft-deleted' => [
            static fn (RecheckedMember $member, RecheckedMembership $left): int => self::updateRow($left, ['deleted_at' => CarbonImmutable::now()]),
            null,
        ];
        yield 'the active tenant kept, deactivated' => [
            static fn (RecheckedMember $member, RecheckedMembership $left, ActivatableTenant $kept): int => self::updateRow($kept, ['is_active' => false]),
            RevocationReason::TENANT_DEACTIVATED,
        ];
        yield 'the identity, deactivated' => [
            static fn (RecheckedMember $member): mixed => RecheckedMember::query()->whereKey($member->getKey())->update(['is_active' => false]),
            RevocationReason::IDENTITY_DEACTIVATED,
        ];
    }

    /**
     * A waiting check judges only the principal the session still acts as.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  \Closure(\Tests\Integration\Fixtures\RecheckedMember, \Tests\Integration\Fixtures\RecheckedMembership, \Tests\Integration\Fixtures\ActivatableTenant): mixed  $change
     * @param  ?\SineMacula\Laravel\Authentication\Events\Enums\RevocationReason  $revoked
     * @return void
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     *
     * @throws \Throwable
     */
    #[DataProvider('provideChangesAfterAPrincipalSwitch')]
    public function testACheckJudgesOnlyThePrincipalTheSessionStillActsAs(\Closure $change, ?RevocationReason $revoked): void
    {
        [$member, $membership, $tenant] = $this->seedRechecked();

        $active  = ActivatableTenant::query()->create(['name' => 'Active', 'is_active' => true]);
        $session = $this->signIn();
        $second  = RecheckedMembership::query()->create(['identity_id' => $member->getKey(), 'tenant_id' => $tenant->getKey(), 'is_active' => true]);

        app()->instance(TenantResolver::class, new DescendantTenants);

        DB::beginTransaction();

        $signIn = $this->recheck();

        $signIn->signIn($session->record, $member, $membership, $active);

        $switch = $this->recheck();

        $switch->switch($session->record, new Admitted($member, $second, $active), true, false);

        $change($member, $membership, $active);

        DB::commit();

        self::assertSame($revoked?->value, self::revokedReasonOf($session));
    }

    /**
     * Rows of `[change after a later tenant switch, revocation reason or
     * null]`.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @return iterable<string, array{0: \Closure(\Tests\Integration\Fixtures\RecheckedMembership, \Tests\Integration\Fixtures\ActivatableTenant): mixed, 1: ?\SineMacula\Laravel\Authentication\Events\Enums\RevocationReason}>
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    public static function provideChangesAfterATenantSwitch(): iterable
    {
        yield 'the tenant left, deactivated' => [
            static fn (RecheckedMembership $kept, ActivatableTenant $left): mixed => ActivatableTenant::query()->whereKey($left->getKey())->update(['is_active' => false]),
            null,
        ];
        yield 'the principal kept, deactivated' => [
            static fn (RecheckedMembership $kept): mixed => RecheckedMembership::query()->whereKey($kept->getKey())->update(['is_active' => false]),
            RevocationReason::PRINCIPAL_DEACTIVATED,
        ];
    }

    /**
     * A waiting check judges only the tenant the session still acts in.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  \Closure(\Tests\Integration\Fixtures\RecheckedMembership, \Tests\Integration\Fixtures\ActivatableTenant): mixed  $change
     * @param  ?\SineMacula\Laravel\Authentication\Events\Enums\RevocationReason  $revoked
     * @return void
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     *
     * @throws \Throwable
     */
    #[DataProvider('provideChangesAfterATenantSwitch')]
    public function testACheckJudgesOnlyTheTenantTheSessionStillActsIn(\Closure $change, ?RevocationReason $revoked): void
    {
        [$member, $membership, $tenant] = $this->seedRechecked();

        $left    = ActivatableTenant::query()->create(['name' => 'Left', 'is_active' => true]);
        $session = $this->signIn();

        app()->instance(TenantResolver::class, new DescendantTenants);

        DB::beginTransaction();

        $signIn = $this->recheck();

        $signIn->signIn($session->record, $member, $membership, $left);

        $switch = $this->recheck();

        $switch->switch($session->record, new Admitted($member, $membership, $tenant), false, true);

        $change($membership, $left);

        DB::commit();

        self::assertSame($revoked?->value, self::revokedReasonOf($session));
    }

    /**
     * A rolled back switch leaves the waiting check as it was.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASwitchRolledBackLeavesTheWaitingCheckAsItWas(): void
    {
        [$member, $membership, $tenant] = $this->seedRechecked();

        $session = $this->signIn();
        $second  = RecheckedMembership::query()->create(['identity_id' => $member->getKey(), 'tenant_id' => $tenant->getKey(), 'is_active' => true]);

        DB::beginTransaction();

        $signIn = $this->recheck();

        $signIn->signIn($session->record, $member, $membership, $tenant);

        DB::beginTransaction();

        $switch = $this->recheck();

        $switch->switch($session->record, new Admitted($member, $second, $tenant), true, false);

        DB::rollBack();

        RecheckedMembership::query()->whereKey($membership->getKey())->update(['is_active' => false]);

        DB::commit();

        self::assertSame(RevocationReason::PRINCIPAL_DEACTIVATED->value, self::revokedReasonOf($session));
    }

    /**
     * A report of another call that throws cannot skip the check.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAReportOfAnotherCallThatThrowsCannotSkipTheCheck(): void
    {
        [$member, $membership, $tenant] = $this->seedRechecked();

        $session = $this->signIn();

        $this->recordEvents([SessionRevoked::class]);

        DB::beginTransaction();

        $throwing = $this->recheck();

        $throwing->signIn($session->record, $member, null, null);
        $throwing->then($session->record, static function (): void {
            throw new \RuntimeException('listener');
        });

        $checked = $this->recheck();

        $checked->choice($session->record, new Admitted($member, $membership, $tenant));

        RecheckedMembership::query()->whereKey($membership->getKey())->update(['is_active' => false]);

        $exceptions = Exceptions::fake();

        DB::commit();

        self::assertSame(['listener'], array_map(static fn (\Throwable $exception): string => $exception->getMessage(), $exceptions->reported()));

        self::assertSame(RevocationReason::PRINCIPAL_DEACTIVATED->value, self::revokedReasonOf($session));
        self::assertSame([SessionRevoked::class], $this->recordedClasses());
    }

    /**
     * A guard forgets the session even when a revocation listener throws.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAGuardForgetsTheSessionWhenTheRevocationsListenerThrows(): void
    {
        [$member, $membership, $tenant] = $this->seedRechecked();

        $session = $this->signIn();
        $guard   = $this->guard();

        DB::beginTransaction();

        $recheck = $this->recheck();

        $recheck->signIn($session->record, $member, $membership, $tenant);

        self::assertNull($recheck->refusal());

        $guard->login($member, $membership, $session->record);

        RecheckedMember::query()->whereKey($member->getKey())->update(['is_active' => false]);

        Event::listen(SessionRevoked::class, static function (): void {
            throw new \RuntimeException('listener');
        });

        $exceptions = Exceptions::fake();

        DB::commit();

        self::assertSame(['listener'], array_map(static fn (\Throwable $exception): string => $exception->getMessage(), $exceptions->reported()));

        self::assertSame(RevocationReason::IDENTITY_DEACTIVATED->value, self::revokedReasonOf($session));
        self::assertNull($guard->session());
        self::assertNull($guard->principal());
        self::assertFalse($guard->check());
    }

    /**
     * A revocation that kept the session and rolled back keeps nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARevocationThatKeptTheSessionAndRolledBackKeepsNothing(): void
    {
        [$member, $membership, $tenant] = $this->seedRechecked();

        $session = $this->signIn();

        DB::beginTransaction();

        $recheck = $this->recheck();

        $recheck->signIn($session->record, $member, $membership, $tenant);

        self::assertNull($recheck->refusal());

        RecheckedMember::query()->whereKey($member->getKey())->update(['tokens_valid_after' => CarbonImmutable::now()->addSecond()]);

        $this->freezeAt(CarbonImmutable::now()->addSeconds(2));

        try {
            DB::transaction(function () use ($member, $session): void {
                $this->sessions(self::GUARD)->passwordChanged($member, $session->record);

                throw new \RuntimeException('rolled back');
            });
        } catch (\RuntimeException $exception) {
            self::assertSame('rolled back', $exception->getMessage());
        }

        DB::commit();

        self::assertSame(RevocationReason::SIGNED_OUT_EVERYWHERE->value, self::revokedReasonOf($session));
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
     * Sign the seeded member in and move the clocks a second on.
     *
     * @return \SineMacula\Laravel\Authentication\Sessions\SignedInSession
     *
     * @throws \Throwable
     */
    private function signIn(): SignedInSession
    {
        $session = $this->sessions(self::GUARD)->signIn('password', self::credentials('rechecked@example.test'), self::requestContext())->session;

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
     * Update the model's row without firing its events.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $model
     * @param  array<string, mixed>  $values
     * @return int
     */
    private static function updateRow(Model $model, array $values): int
    {
        return $model->newQuery()->whereKey($model->getKey())->update($values);
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
