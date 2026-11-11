<?php

declare(strict_types = 1);

namespace Tests\Feature\Sessions;

use Illuminate\Auth\Events\Logout;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\ConnectionResolverInterface;
use Illuminate\Events\Dispatcher;
use Illuminate\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Timebox;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Session;
use SineMacula\Laravel\Authentication\Events\Enums\RevocationReason;
use SineMacula\Laravel\Authentication\Events\SessionRevoked;
use SineMacula\Laravel\Authentication\Events\SignedOutEverywhere;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Http\RefreshTokenTransport;
use SineMacula\Laravel\Authentication\IdentifierChanges\PendingChanges;
use SineMacula\Laravel\Authentication\Models\Session as SessionModel;
use SineMacula\Laravel\Authentication\Runtime\GuardContext;
use SineMacula\Laravel\Authentication\Sessions\RevocationWriter;
use SineMacula\Laravel\Authentication\Sessions\SessionRevocations;
use SineMacula\Laravel\Authentication\Sessions\SignedInSession;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use Tests\Concerns\InteractsWithChangeableIdentities;
use Tests\Fixtures\Events\EventContextAssertions;
use Tests\Integration\Fixtures\ActivatableTenant;
use Tests\Integration\Fixtures\ActivatableTenantMember;
use Tests\Integration\Fixtures\ActivatableTenantMembership;
use Tests\Integration\Fixtures\EagerTenantMembership;
use Tests\Integration\Fixtures\IntegrationIdentity;
use Tests\TestCase;
use Tests\Unit\Stubs\StubBareSession;
use Tests\Unit\Stubs\StubTenant;

/**
 * Feature tests of a guard's session revocations on their own, without a
 * session service.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SessionRevocations::class)]
#[CoversClass(JwtGuard::class)]
final class SessionRevocationsTest extends TestCase
{
    use InteractsWithChangeableIdentities;

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
     * Signing out revokes the binding's session, reports `SessionRevoked` then
     * `Logout`, and forgets the binding.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testSigningOutRevokesTheBindingsSessionThenReportsTheLogout(): void
    {
        $identity    = $this->seedIdentity();
        $session     = $this->signIn();
        $guard       = $this->bearing($session);
        $revocations = SessionRevocations::forContext($guard->context(), app());

        $this->recordEvents([SessionRevoked::class, Logout::class]);

        self::assertTrue($revocations->signOut($guard));
        self::assertSame([SessionRevoked::class, Logout::class], $this->recordedClasses());

        $revoked = $this->recordedEvent(SessionRevoked::class);
        $logout  = $this->recordedEvent(Logout::class);

        self::assertSame(RevocationReason::SIGNED_OUT, $revoked->reason);
        self::assertSame(self::idOf($session), $revoked->context->sessionId);
        self::assertSame(IdentifierCoercion::stringify($identity->getKey()), $revoked->context->principalId);
        self::assertSame('198.51.100.40', $revoked->context->client->ip);
        self::assertSame('api', $logout->guard);
        self::assertIsModel($identity, $logout->user);
        self::assertTrue($guard->guest());
        self::assertSame('signed_out', DB::table('authentication_sessions')->value('revoked_reason'));

        $this->recordEvents([SessionRevoked::class, Logout::class]);

        self::assertFalse($revocations->signOut($guard));
        self::assertSame([], $this->recordedClasses());
    }

    /**
     * Signing out a session bound without an identity skips `Logout` and names
     * what its row records.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testSigningOutASessionBoundWithoutAnIdentityNamesWhatTheRowRecords(): void
    {
        $identity    = $this->seedIdentity();
        $session     = $this->signIn();
        $guard       = $this->freshGuard();
        $revocations = SessionRevocations::forContext($guard->context(), app());

        $guard->setSession(SessionModel::query()->findOrFail(self::idOf($session)));

        $this->recordEvents([SessionRevoked::class, Logout::class]);

        self::assertTrue($revocations->signOut($guard));
        self::assertSame([SessionRevoked::class], $this->recordedClasses());

        $context = $this->recordedEvent(SessionRevoked::class)->context;

        self::assertSame(IdentifierCoercion::stringify($identity->getKey()), $context->identityId);
        self::assertSame($identity->getMorphClass(), $context->principalType);
        self::assertSame(IdentifierCoercion::stringify($identity->getKey()), $context->principalId);
    }

    /**
     * Signing out a trusted bind whose tenant no longer resolves reports the
     * tenant its row records.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testSigningOutATrustedBindWhoseTenantNoLongerResolvesReportsTheRowsTenant(): void
    {
        $identity    = $this->seedIdentity();
        $session     = $this->signIn();
        $guard       = $this->freshGuard();
        $revocations = SessionRevocations::forContext($guard->context(), app());

        DB::table('authentication_sessions')->update(['tenant_id' => 'gone']);

        $guard->login($identity, $identity, SessionModel::query()->findOrFail(self::idOf($session)));

        $this->recordEvents([SessionRevoked::class]);

        self::assertTrue($revocations->signOut($guard));

        $context = $this->recordedEvent(SessionRevoked::class)->context;

        self::assertSame('gone', $context->tenantId);
        self::assertSame('signed_out', DB::table('authentication_sessions')->value('revoked_reason'));
    }

    /**
     * Signing out a model session that is not a package session only forgets
     * it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testSigningOutAModelSessionThatIsNotAPackageSessionOnlyForgetsIt(): void
    {
        $identity    = $this->seedIdentity();
        $guard       = $this->freshGuard();
        $revocations = SessionRevocations::forContext($guard->context(), app());

        $this->signIn();

        $guard->login($identity, $identity, (new StubBareSession)->forceFill(['id' => 'bare-session']));

        $this->recordEvents([SessionRevoked::class, Logout::class]);

        self::assertFalse($revocations->signOut($guard));
        self::assertSame([Logout::class], $this->recordedClasses());
        self::assertTrue($guard->guest());
        self::assertSame(0, DB::table('authentication_sessions')->whereNotNull('revoked_at')->count());
    }

    /**
     * A guest binding has nothing to sign out.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAGuestHasNothingToSignOut(): void
    {
        $this->seedIdentity();
        $this->signIn();

        $guard       = $this->freshGuard();
        $revocations = SessionRevocations::forContext($guard->context(), app());

        $this->recordEvents([SessionRevoked::class, Logout::class, SignedOutEverywhere::class]);

        self::assertFalse($revocations->signOut($guard));
        self::assertSame(0, $revocations->signOutEverywhere($guard, false));
        self::assertSame([], $this->recordedClasses());
        self::assertSame(0, DB::table('authentication_sessions')->whereNotNull('revoked_at')->count());
    }

    /**
     * Signing out everywhere keeps the binding's own session only when asked.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testSigningOutEverywhereKeepsTheBindingsSessionOnlyWhenAsked(): void
    {
        $identity = $this->seedIdentity();

        $current     = $this->signIn();
        $other       = $this->signIn();
        $guard       = $this->bearing($current);
        $revocations = SessionRevocations::forContext($guard->context(), app());

        $this->recordEvents([SessionRevoked::class, SignedOutEverywhere::class]);

        self::assertSame(1, $revocations->signOutEverywhere($guard, true));
        self::assertSame([SessionRevoked::class, SignedOutEverywhere::class], $this->recordedClasses());

        $revoked = $this->recordedEvent(SessionRevoked::class)->context;

        self::assertSame(self::idOf($other), $revoked->sessionId);
        self::assertSame($identity->getMorphClass(), $revoked->principalType);
        self::assertSame(IdentifierCoercion::stringify($identity->getKey()), $revoked->principalId);
        self::assertNull(DB::table('authentication_sessions')->where('id', self::idOf($current))->value('revoked_at'));
        self::assertSame('signed_out_everywhere', DB::table('authentication_sessions')->where('id', self::idOf($other))->value('revoked_reason'));
        self::assertNotNull($guard->user());

        self::assertSame(1, $revocations->signOutEverywhere($guard, false));
        self::assertSame('signed_out_everywhere', DB::table('authentication_sessions')->where('id', self::idOf($current))->value('revoked_reason'));
    }

    /**
     * Rows of `[the change, its reason, whether it keeps the session it is
     * given]`.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @return iterable<string, array{0: \Closure(\SineMacula\Laravel\Authentication\Sessions\SessionRevocations, \SineMacula\Laravel\Authentication\Contracts\Identity, \SineMacula\Laravel\Authentication\Contracts\Session): int, 1: \SineMacula\Laravel\Authentication\Events\Enums\RevocationReason, 2: bool}>
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    public static function provideChanges(): iterable
    {
        yield 'sessions revoked' => [
            static fn (SessionRevocations $revocations, Identity $identity, Session $record): int => $revocations->revokeSessions($identity, RevocationReason::REVOKED, $record),
            RevocationReason::REVOKED,
            true,
        ];

        yield 'password changed' => [
            static fn (SessionRevocations $revocations, Identity $identity, Session $record): int => $revocations->passwordChanged($identity, $record),
            RevocationReason::PASSWORD_CHANGED,
            true,
        ];

        yield 'password reset' => [
            static fn (SessionRevocations $revocations, Identity $identity): int => $revocations->passwordReset($identity),
            RevocationReason::PASSWORD_RESET,
            false,
        ];

        yield 'credential removed' => [
            static fn (SessionRevocations $revocations, Identity $identity, Session $record): int => $revocations->credentialRemoved($identity, $record),
            RevocationReason::FACTOR_REMOVED,
            true,
        ];

        yield 'identity deactivated' => [
            static fn (SessionRevocations $revocations, Identity $identity): int => $revocations->identityDeactivated($identity),
            RevocationReason::IDENTITY_DEACTIVATED,
            false,
        ];

        yield 'identity deleted' => [
            static fn (SessionRevocations $revocations, Identity $identity): int => $revocations->identityDeleted($identity),
            RevocationReason::IDENTITY_DELETED,
            false,
        ];
    }

    /**
     * Each change ends the identity's sessions with its own reason, keeping the
     * session given where the change takes one.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  \Closure(\SineMacula\Laravel\Authentication\Sessions\SessionRevocations, \SineMacula\Laravel\Authentication\Contracts\Identity, \SineMacula\Laravel\Authentication\Contracts\Session): int  $change
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\RevocationReason  $reason
     * @param  bool  $keeps
     * @return void
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     *
     * @throws \Throwable
     */
    #[DataProvider('provideChanges')]
    public function testEachChangeEndsTheSessionsWithItsReason(\Closure $change, RevocationReason $reason, bool $keeps): void
    {
        $identity    = $this->seedIdentity();
        $kept        = $this->signIn();
        $ended       = $this->signIn();
        $revocations = SessionRevocations::forContext($this->freshGuard()->context(), app());

        self::assertSame($keeps ? 1 : 2, $change($revocations, $identity, $kept->record));
        self::assertSame($reason->value, DB::table('authentication_sessions')->where('id', self::idOf($ended))->value('revoked_reason'));
        self::assertSame($keeps ? null : $reason->value, DB::table('authentication_sessions')->where('id', self::idOf($kept))->value('revoked_reason'));
    }

    /**
     * Rows of `[revocation of the member's identity, principal or tenant,
     * whether it ends the scopes again at the commit]`.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @return iterable<string, array{0: \Closure(\SineMacula\Laravel\Authentication\Sessions\SessionRevocations, \Tests\Integration\Fixtures\ActivatableTenantMember, \Tests\Integration\Fixtures\ActivatableTenantMembership, \Tests\Integration\Fixtures\ActivatableTenant): int, 1: bool}>
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    public static function provideSecondPasses(): iterable
    {
        yield 'identity deactivated' => [
            static fn (
                SessionRevocations $revocations,
                ActivatableTenantMember $member,
                ActivatableTenantMembership $membership,
                ActivatableTenant $tenant,
            ): int => $revocations->identityDeactivated($member),
            true,
        ];
        yield 'identity deleted' => [
            static fn (
                SessionRevocations $revocations,
                ActivatableTenantMember $member,
                ActivatableTenantMembership $membership,
                ActivatableTenant $tenant,
            ): int => $revocations->identityDeleted($member),
            true,
        ];
        yield 'principal deactivated' => [
            static fn (
                SessionRevocations $revocations,
                ActivatableTenantMember $member,
                ActivatableTenantMembership $membership,
                ActivatableTenant $tenant,
            ): int => $revocations->principalDeactivated($membership),
            true,
        ];
        yield 'principal deleted' => [
            static fn (
                SessionRevocations $revocations,
                ActivatableTenantMember $member,
                ActivatableTenantMembership $membership,
                ActivatableTenant $tenant,
            ): int => $revocations->principalDeleted($membership),
            true,
        ];
        yield 'tenant deactivated' => [
            static fn (
                SessionRevocations $revocations,
                ActivatableTenantMember $member,
                ActivatableTenantMembership $membership,
                ActivatableTenant $tenant,
            ): int => $revocations->tenantDeactivated($tenant, [$membership]),
            true,
        ];
        yield 'password reset' => [
            static fn (
                SessionRevocations $revocations,
                ActivatableTenantMember $member,
                ActivatableTenantMembership $membership,
                ActivatableTenant $tenant,
            ): int => $revocations->passwordReset($member),
            false,
        ];
    }

    /**
     * A deactivation or deletion inside a transaction ends its scopes again
     * once the transaction commits.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  \Closure(\SineMacula\Laravel\Authentication\Sessions\SessionRevocations, \Tests\Integration\Fixtures\ActivatableTenantMember, \Tests\Integration\Fixtures\ActivatableTenantMembership, \Tests\Integration\Fixtures\ActivatableTenant): int  $revoke
     * @param  bool  $again
     * @return void
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     *
     * @throws \Throwable
     */
    #[DataProvider('provideSecondPasses')]
    public function testADeactivationOrDeletionInsideATransactionEndsItsScopesAgainAtTheCommit(\Closure $revoke, bool $again): void
    {
        [$member, $membership, $tenant] = $this->seedMember();

        $first       = self::sessionsOf($this->freshGuard('members'))->signIn('password', self::credentials('member@example.test'), self::requestContext())->session;
        $revocations = SessionRevocations::forContext($this->freshGuard('members')->context(), app());

        self::assertNotNull($first);

        $this->recordEvents([SessionRevoked::class, SignedOutEverywhere::class]);

        DB::beginTransaction();

        self::assertSame(1, $revoke($revocations, $member, $membership, $tenant));

        $late = self::sessionsOf($this->freshGuard('members'))->signIn('password', self::credentials('member@example.test'), self::requestContext())->session;

        self::assertNotNull($late);

        $reported = $this->recordedClasses();

        DB::commit();

        self::assertSame([], $reported);
        self::assertCount($again ? 2 : 1, array_filter($this->recorded, static fn (object $event): bool => $event instanceof SessionRevoked));
        self::assertCount(1, array_filter($this->recorded, static fn (object $event): bool => $event instanceof SignedOutEverywhere));
        self::assertSame($again, DB::table('authentication_sessions')->where('id', self::idOf($late))->whereNotNull('revoked_at')->exists());
    }

    /**
     * Rows of `[a deactivation's or deletion's revocation of the seeded
     * member's identity, principal or tenant]`.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @return iterable<string, array{0: \Closure(\SineMacula\Laravel\Authentication\Sessions\SessionRevocations, \Tests\Integration\Fixtures\ActivatableTenantMember, \Tests\Integration\Fixtures\ActivatableTenantMembership, \Tests\Integration\Fixtures\ActivatableTenant): int}>
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    public static function provideDeactivationsAndDeletions(): iterable
    {
        foreach (self::provideSecondPasses() as $name => [$revoke, $again]) {

            if (!$again) {
                continue;
            }

            yield $name => [$revoke];
        }
    }

    /**
     * A listener that throws on the first pass's report at the commit cannot
     * skip the second pass.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  \Closure(\SineMacula\Laravel\Authentication\Sessions\SessionRevocations, \Tests\Integration\Fixtures\ActivatableTenantMember, \Tests\Integration\Fixtures\ActivatableTenantMembership, \Tests\Integration\Fixtures\ActivatableTenant): int  $revoke
     * @return void
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     *
     * @throws \Throwable
     */
    #[DataProvider('provideDeactivationsAndDeletions')]
    public function testAListenerThatThrowsOnTheFirstPassCannotSkipTheSecond(\Closure $revoke): void
    {
        [$member, $membership, $tenant] = $this->seedMember();

        $first       = self::sessionsOf($this->freshGuard('members'))->signIn('password', self::credentials('member@example.test'), self::requestContext())->session;
        $revocations = SessionRevocations::forContext($this->freshGuard('members')->context(), app());

        self::assertNotNull($first);

        $firstId = self::idOf($first);

        Event::listen(SessionRevoked::class, static function (SessionRevoked $event) use ($firstId): void {
            if ($event->context->sessionId !== $firstId) {
                return;
            }

            throw new \RuntimeException('first pass');
        });

        DB::beginTransaction();

        $revoke($revocations, $member, $membership, $tenant);

        $late = self::sessionsOf($this->freshGuard('members'))->signIn('password', self::credentials('member@example.test'), self::requestContext())->session;

        self::assertNotNull($late);

        try {
            DB::commit();

            self::fail('Expected the listener to throw.');
        } catch (\RuntimeException $exception) {
            self::assertSame('first pass', $exception->getMessage());
        }

        self::assertTrue(DB::table('authentication_sessions')->where('id', self::idOf($late))->whereNotNull('revoked_at')->exists());
    }

    /**
     * Revoking one session, or a principal's sessions on its deactivation, ends
     * them with the reason given.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testOneSessionOrAPrincipalsSessionsEnd(): void
    {
        $identity    = $this->seedIdentity();
        $first       = $this->signIn();
        $second      = $this->signIn();
        $revocations = SessionRevocations::forContext($this->freshGuard()->context(), app());

        $this->recordEvents([SessionRevoked::class]);

        self::assertTrue($revocations->revokeSession($identity, self::idOf($first), RevocationReason::REVOKED));
        self::assertFalse($revocations->revokeSession($identity, self::idOf($first), RevocationReason::REVOKED));

        $context = $this->recordedEvent(SessionRevoked::class)->context;

        self::assertSame($identity->getMorphClass(), $context->principalType);
        self::assertSame(IdentifierCoercion::stringify($identity->getKey()), $context->principalId);
        self::assertSame(1, $revocations->principalDeactivated($identity));
        self::assertSame('revoked', DB::table('authentication_sessions')->where('id', self::idOf($first))->value('revoked_reason'));
        self::assertSame('principal_deactivated', DB::table('authentication_sessions')->where('id', self::idOf($second))->value('revoked_reason'));
    }

    /**
     * Revoking an identity's sessions for a client given reports that client on
     * every event.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRevokingForAClientGivenReportsItOnEveryEvent(): void
    {
        $identity = $this->seedIdentity();

        $this->signIn();
        $this->signIn();

        $guard       = $this->bearing($this->signIn());
        $revocations = SessionRevocations::forContext($guard->context(), app());
        $client      = new ClientContext('192.0.2.44', 'Worker/1.0');

        $this->recordEvents([SessionRevoked::class, SignedOutEverywhere::class]);

        self::assertSame(3, $revocations->revokeSessions($identity, RevocationReason::PASSWORD_RESET, client: $client));
        self::assertSame([SessionRevoked::class, SessionRevoked::class, SessionRevoked::class, SignedOutEverywhere::class], $this->recordedClasses());
        self::assertSame([$client, $client, $client, $client], array_map(
            static fn (SessionRevoked|SignedOutEverywhere $event): ClientContext => $event->context->client,
            $this->recordedAs(SessionRevoked::class, SignedOutEverywhere::class),
        ));

        $this->recordEvents([SessionRevoked::class, SignedOutEverywhere::class]);

        self::assertSame(0, $revocations->revokeSessions($identity, RevocationReason::REVOKED));
        self::assertSame('198.51.100.40', $this->recordedEvent(SignedOutEverywhere::class)->context->client->ip);
    }

    /**
     * Revoking every session acting as a principal keeps the one given, and
     * ends the rest with the reason given.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPrincipalsSessionsEndButTheOneKept(): void
    {
        $identity    = $this->seedIdentity();
        $kept        = $this->signIn();
        $ended       = $this->signIn();
        $revocations = SessionRevocations::forContext($this->freshGuard()->context(), app());

        self::assertSame(1, $revocations->revokePrincipalSessions($identity, RevocationReason::REVOKED, $kept->record));
        self::assertNull(DB::table('authentication_sessions')->where('id', self::idOf($kept))->value('revoked_at'));
        self::assertSame('revoked', DB::table('authentication_sessions')->where('id', self::idOf($ended))->value('revoked_reason'));
    }

    /**
     * A principal's deletion ends every session acting as it, with
     * `principal_deleted`, and a second call finds none left to end.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPrincipalsDeletionEndsTheSessionsActingAsIt(): void
    {
        $identity    = $this->seedIdentity();
        $first       = $this->signIn();
        $second      = $this->signIn();
        $revocations = SessionRevocations::forContext($this->freshGuard()->context(), app());

        self::assertSame(2, $revocations->principalDeleted($identity));
        self::assertSame(0, $revocations->principalDeleted($identity));
        self::assertSame('principal_deleted', DB::table('authentication_sessions')->where('id', self::idOf($first))->value('revoked_reason'));
        self::assertSame('principal_deleted', DB::table('authentication_sessions')->where('id', self::idOf($second))->value('revoked_reason'));
    }

    /**
     * Ending an identity's sessions cancels its pending changes only when its
     * identifiers can change.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testEndingAnIdentitysSessionsCancelsItsChangesOnlyWhenItsIdentifiersChange(): void
    {
        self::createChangeableIdentitiesTable();

        try {
            $changeable  = self::seedChangeable();
            $plain       = $this->seedIdentity();
            $revocations = SessionRevocations::forContext($this->freshGuard()->context(), app());

            self::insertPendingChange(PendingChanges::key($changeable, 'email'), '0195f4a2-7b1c-4000-8000-000000000001');
            self::insertPendingChange(PendingChanges::key($plain, 'email'), '0195f4a2-7b1c-4000-8000-000000000002');

            $revocations->revokeSessions($changeable, RevocationReason::REVOKED);
            $revocations->revokeSessions($plain, RevocationReason::REVOKED);

            self::assertSame([PendingChanges::key($plain, 'email')], DB::table('identifier_changes')->pluck('id')->all());
        } finally {
            self::dropChangeableIdentitiesTable();
        }
    }

    /**
     * A tenant's deactivation ends each listed principal's sessions once, with
     * one `SignedOutEverywhere` each.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATenantsDeactivationEndsEachPrincipalListedForIt(): void
    {
        [, $membership, $tenant] = $this->seedMember();

        $eager = EagerTenantMembership::query()->findOrFail(self::modelKey($membership));

        self::sessionsOf($this->freshGuard('members'))->signIn('password', self::credentials('member@example.test'), self::requestContext());

        $revocations = SessionRevocations::forContext($this->freshGuard('members')->context(), app());

        $this->recordEvents([SignedOutEverywhere::class]);

        self::assertSame(1, $revocations->tenantDeactivated($tenant, [$membership, $membership, $eager]));

        $principals = array_map(static fn (object $event): ?string => $event instanceof SignedOutEverywhere ? $event->context->principalType : null, $this->recorded);

        self::assertSame([ActivatableTenantMembership::class, EagerTenantMembership::class], $principals);
        self::assertSame('tenant_deactivated', DB::table('authentication_sessions')->value('revoked_reason'));
    }

    /**
     * With no principal listed, a tenant's deactivation ends every session
     * acting in the tenant.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATenantsDeactivationEndsTheSessionsActingInIt(): void
    {
        [, , $tenant] = $this->seedMember();

        $this->seedMember('other@example.test');

        self::sessionsOf($this->freshGuard('members'))->signIn('password', self::credentials('member@example.test'), self::requestContext());
        self::sessionsOf($this->freshGuard('members'))->signIn('password', self::credentials('other@example.test'), self::requestContext());

        $revocations = SessionRevocations::forContext($this->freshGuard('members')->context(), app());

        $this->recordEvents([SessionRevoked::class, SignedOutEverywhere::class]);

        self::assertSame(1, $revocations->tenantDeactivated($tenant, []));
        self::assertSame([SessionRevoked::class], $this->recordedClasses());
        EventContextAssertions::assertTenant($tenant, $this->recordedEvent(SessionRevoked::class)->context);
        self::assertSame(RevocationReason::TENANT_DEACTIVATED, $this->recordedEvent(SessionRevoked::class)->reason);
        self::assertSame(1, DB::table('authentication_sessions')->whereNull('revoked_at')->count());
        self::assertSame(0, $revocations->tenantDeactivated($tenant, []));
    }

    /**
     * Rows of `[tenant to deactivate, member's own, principal listed after the
     * member]`, one acting outside the tenant.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @return iterable<string, array{0: \Closure(\Tests\Integration\Fixtures\ActivatableTenant): \SineMacula\Laravel\Authentication\Contracts\Tenant, 1: \Closure(\Tests\Feature\Sessions\SessionRevocationsTest): ?\SineMacula\Laravel\Authentication\Contracts\Principal}>
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    public static function provideOutsiders(): iterable
    {
        yield 'a principal of another tenant' => [
            static fn (ActivatableTenant $tenant): ActivatableTenant => $tenant,
            static fn (self $test): ActivatableTenantMembership => $test->seedMember('outsider@example.test')[1],
        ];

        yield 'a principal of no tenant' => [
            static fn (ActivatableTenant $tenant): ActivatableTenant => $tenant,
            static fn (self $test): IntegrationIdentity => $test->seedIdentity(),
        ];

        yield 'the member under a tenant of another class with its key' => [
            static fn (ActivatableTenant $tenant): StubTenant => (new StubTenant)->forceFill(['id' => $tenant->getKey()]),
            static fn (): null => null,
        ];
    }

    /**
     * A tenant's deactivation refuses a principal that does not act within the
     * tenant, before anything is written, even when listed after one that does.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  \Closure(\Tests\Integration\Fixtures\ActivatableTenant): \SineMacula\Laravel\Authentication\Contracts\Tenant  $tenantOf
     * @param  \Closure(\Tests\Feature\Sessions\SessionRevocationsTest): ?\SineMacula\Laravel\Authentication\Contracts\Principal  $outsider
     * @return void
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     *
     * @throws \Throwable
     */
    #[DataProvider('provideOutsiders')]
    public function testATenantsDeactivationRefusesAPrincipalThatDoesNotActWithinIt(\Closure $tenantOf, \Closure $outsider): void
    {
        [, $membership, $tenant] = $this->seedMember();

        self::sessionsOf($this->freshGuard('members'))->signIn('password', self::credentials('member@example.test'), self::requestContext());

        $revocations = SessionRevocations::forContext($this->freshGuard('members')->context(), app());
        $deactivated = $tenantOf($tenant);
        $listed      = array_filter([$membership, $outsider($this)]);

        try {
            $revocations->tenantDeactivated($deactivated, $listed);
            self::fail('A principal that does not act within the tenant was accepted.');
        } catch (\InvalidArgumentException $exception) {
            self::assertStringContainsString('does not act within tenant ' . $deactivated::class, $exception->getMessage());
        }

        self::assertSame(0, DB::table('authentication_sessions')->whereNotNull('revoked_at')->count());
    }

    /**
     * A deferred report reaches the guard's dispatcher as it is at the commit.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testADeferredReportReachesTheDispatcherAsItIsAtTheCommit(): void
    {
        $identity    = $this->seedIdentity();
        $session     = $this->signIn();
        $guard       = $this->freshGuard();
        $revocations = SessionRevocations::forContext($guard->context(), app());
        $swapped     = new Dispatcher(app());
        $received    = [];

        $swapped->listen(SessionRevoked::class, static function (SessionRevoked $event) use (&$received): void {
            $received[] = $event->reason;
        });

        $this->recordEvents([SessionRevoked::class]);

        DB::transaction(static function () use ($revocations, $identity, $session, $guard, $swapped): void {
            self::assertTrue($revocations->revokeSession($identity, self::idOf($session), RevocationReason::REVOKED));

            $guard->setDispatcher($swapped);
        });

        self::assertSame([RevocationReason::REVOKED], $received);
        self::assertSame([], $this->recordedClasses());
    }

    /**
     * A JWT guard's `logout()` signs the session out without a session service,
     * revoking before `Logout`.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheGuardsLogoutNeedsNoSessionService(): void
    {
        $this->seedIdentity();

        $session  = $this->signIn();
        $resolved = $this->freshGuard();
        $built    = [];
        $guard    = new JwtGuard(
            'api',
            $resolved->getProvider(),
            $resolved->getPrincipalResolver(),
            app('events'),
            Request::create('/logout', 'POST', server: ['HTTP_AUTHORIZATION' => 'Bearer ' . $session->tokens->accessToken->reveal()]),
            new Timebox,
            Auth::jwt('api'),
            static function (GuardContext $context) use (&$built): SessionRevocations {
                $built[] = $context;

                return new SessionRevocations(
                    $context,
                    new RevocationWriter(app(ConnectionResolverInterface::class), static fn (): mixed => app('db.transactions')),
                    app(),
                );
            },
            static fn (): RefreshTokenTransport => RefreshTokenTransport::forGuard('api', config()),
        );

        $this->recordEvents([SessionRevoked::class, Logout::class]);

        $guard->logout();

        self::assertSame([$guard->context()], $built);
        self::assertSame([SessionRevoked::class, Logout::class], $this->recordedClasses());
        self::assertTrue($guard->guest());
        self::assertSame('signed_out', DB::table('authentication_sessions')->where('id', self::idOf($session))->value('revoked_reason'));
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
     * Sign the identity in on the `api` guard.
     *
     * @return \SineMacula\Laravel\Authentication\Sessions\SignedInSession
     *
     * @throws \Throwable
     */
    private function signIn(): SignedInSession
    {
        $session = $this->sessions()->signIn('password', self::credentials(), self::requestContext())->session;

        self::assertNotNull($session);

        return $session;
    }

    /**
     * A fresh `api` guard serving a request that bears the session's access
     * token, not resolved yet.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignedInSession  $session
     * @return \SineMacula\Laravel\Authentication\Guards\JwtGuard
     */
    private function bearing(SignedInSession $session): JwtGuard
    {
        return $this->freshGuard()->setRequest(Request::create('/logout', 'POST', server: [
            'REMOTE_ADDR'        => '198.51.100.40',
            'HTTP_AUTHORIZATION' => 'Bearer ' . $session->tokens->accessToken->reveal(),
        ]));
    }

    /**
     * Insert a pending change of the email address under the key, for the
     * request.
     *
     * @param  string  $key
     * @param  string  $requestId
     * @return void
     */
    private static function insertPendingChange(string $key, string $requestId): void
    {
        DB::table('identifier_changes')->insert([
            'id'           => $key,
            'guard'        => 'api',
            'type'         => 'email',
            'previous'     => null,
            'identifier'   => 'ada@new.example.test',
            'request_id'   => $requestId,
            'requested_at' => '2026-04-06 12:00:00',
            'expires_at'   => '2026-04-06 13:00:00',
        ]);
    }

    /**
     * The identifier of the session.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignedInSession  $session
     * @return string
     */
    private static function idOf(SignedInSession $session): string
    {
        return (string) IdentifierCoercion::stringify($session->record->getSessionIdentifier());
    }
}
