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
use Illuminate\Support\Timebox;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\Device;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Events\DeviceRevoked;
use SineMacula\Laravel\Authentication\Events\Enums\RevocationReason;
use SineMacula\Laravel\Authentication\Events\SignedOutEverywhere;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Http\RefreshTokenTransport;
use SineMacula\Laravel\Authentication\IdentifierChanges\PendingChanges;
use SineMacula\Laravel\Authentication\Models\Device as DeviceModel;
use SineMacula\Laravel\Authentication\Runtime\GuardContext;
use SineMacula\Laravel\Authentication\Sessions\DeviceRevocations;
use SineMacula\Laravel\Authentication\Sessions\SessionRevocations;
use SineMacula\Laravel\Authentication\Sessions\SignedInSession;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use Tests\Concerns\InteractsWithChangeableIdentities;
use Tests\Integration\Fixtures\ActivatableTenant;
use Tests\Integration\Fixtures\ActivatableTenantMembership;
use Tests\Integration\Fixtures\EagerTenantMembership;
use Tests\Integration\Fixtures\IntegrationIdentity;
use Tests\TestCase;
use Tests\Unit\Stubs\StubBareDevice;
use Tests\Unit\Stubs\StubTenant;

/**
 * Feature tests of a guard's session revocations on their own, without a
 * session service: signing out the binding they are given and signing it out
 * everywhere, each security change ending the sessions with its reason, a
 * tenant's deactivation ending only its principals' sessions, a deferred report
 * reaching the guard's dispatcher as it is at the commit, and the guard's
 * `logout()` signing out through them alone.
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
     * Signing out the binding resolves the session the request carries, then
     * revokes its device (`signed_out`), reports `DeviceRevoked` and then
     * `Logout` under the guard's name, and forgets the binding; signing out
     * again revokes and reports nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testSigningOutRevokesTheBindingsDeviceThenReportsTheLogout(): void
    {
        $identity    = $this->seedIdentity();
        $session     = $this->signIn();
        $guard       = $this->bearing($session);
        $revocations = SessionRevocations::forContext($guard->context(), app());

        $this->recordEvents([DeviceRevoked::class, Logout::class]);

        self::assertTrue($revocations->signOut($guard));
        self::assertSame([DeviceRevoked::class, Logout::class], $this->recordedClasses());

        $revoked = $this->recordedEvent(DeviceRevoked::class);
        $logout  = $this->recordedEvent(Logout::class);

        self::assertSame(RevocationReason::SIGNED_OUT, $revoked->reason);
        self::assertSame(self::idOf($session), $revoked->context->deviceId);
        self::assertSame(IdentifierCoercion::stringify($identity->getKey()), $revoked->context->principalId);
        self::assertSame('198.51.100.40', $revoked->context->client->ip);
        self::assertSame('api', $logout->guard);
        self::assertTrue($identity->is($logout->user));
        self::assertTrue($guard->guest());
        self::assertSame('signed_out', DB::table('devices')->value('revoked_reason'));

        $this->recordEvents([DeviceRevoked::class, Logout::class]);

        self::assertFalse($revocations->signOut($guard));
        self::assertSame([], $this->recordedClasses());
    }

    /**
     * Signing out a binding that holds only a device (no identity) revokes it
     * without `Logout`, and the revocation names the owner and the principal
     * the device row records.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testSigningOutADeviceBoundWithoutAnIdentityNamesWhatTheRowRecords(): void
    {
        $identity    = $this->seedIdentity();
        $session     = $this->signIn();
        $guard       = $this->freshGuard();
        $revocations = SessionRevocations::forContext($guard->context(), app());

        $guard->setDevice(DeviceModel::query()->findOrFail(self::idOf($session)));

        $this->recordEvents([DeviceRevoked::class, Logout::class]);

        self::assertTrue($revocations->signOut($guard));
        self::assertSame([DeviceRevoked::class], $this->recordedClasses());

        $context = $this->recordedEvent(DeviceRevoked::class)->context;

        self::assertNull($context->identity);
        self::assertSame(IdentifierCoercion::stringify($identity->getKey()), $context->identityId);
        self::assertSame($identity->getMorphClass(), $context->principalMorphClass);
        self::assertSame(IdentifierCoercion::stringify($identity->getKey()), $context->principalId);
    }

    /**
     * Signing out a binding whose device is an Eloquent model but not a package
     * device only forgets it: nothing is revoked, and only `Logout` reports the
     * sign-out.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testSigningOutAModelDeviceThatIsNotAPackageDeviceOnlyForgetsIt(): void
    {
        $identity    = $this->seedIdentity();
        $guard       = $this->freshGuard();
        $revocations = SessionRevocations::forContext($guard->context(), app());

        $this->signIn();

        $guard->login($identity, $identity, (new StubBareDevice)->forceFill(['id' => 'bare-device']));

        $this->recordEvents([DeviceRevoked::class, Logout::class]);

        self::assertFalse($revocations->signOut($guard));
        self::assertSame([Logout::class], $this->recordedClasses());
        self::assertTrue($guard->guest());
        self::assertSame(0, DB::table('devices')->whereNotNull('revoked_at')->count());
    }

    /**
     * A guest binding has nothing to sign out: nothing is revoked or reported,
     * and signing it out everywhere revokes nothing.
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

        $this->recordEvents([DeviceRevoked::class, Logout::class, SignedOutEverywhere::class]);

        self::assertFalse($revocations->signOut($guard));
        self::assertSame(0, $revocations->signOutEverywhere($guard, false));
        self::assertSame([], $this->recordedClasses());
        self::assertSame(0, DB::table('devices')->whereNotNull('revoked_at')->count());
    }

    /**
     * Signing the binding out everywhere ends the identity's other sessions and
     * keeps the binding's own when asked, with the binding still bound, each
     * revoked device reported with the principal its row records; without
     * keeping it, the binding's session ends too.
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

        $this->recordEvents([DeviceRevoked::class, SignedOutEverywhere::class]);

        self::assertSame(1, $revocations->signOutEverywhere($guard, true));
        self::assertSame([DeviceRevoked::class, SignedOutEverywhere::class], $this->recordedClasses());

        $revoked = $this->recordedEvent(DeviceRevoked::class)->context;

        self::assertSame(self::idOf($other), $revoked->deviceId);
        self::assertNull($revoked->principal);
        self::assertSame($identity->getMorphClass(), $revoked->principalMorphClass);
        self::assertSame(IdentifierCoercion::stringify($identity->getKey()), $revoked->principalId);
        self::assertNull(DB::table('devices')->where('id', self::idOf($current))->value('revoked_at'));
        self::assertSame('signed_out_everywhere', DB::table('devices')->where('id', self::idOf($other))->value('revoked_reason'));
        self::assertNotNull($guard->user());

        self::assertSame(1, $revocations->signOutEverywhere($guard, false));
        self::assertSame('signed_out_everywhere', DB::table('devices')->where('id', self::idOf($current))->value('revoked_reason'));
    }

    /**
     * Rows of `[the change, its reason, whether it keeps the device it is
     * given]`.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @return iterable<string, array{0: \Closure(\SineMacula\Laravel\Authentication\Sessions\SessionRevocations, \SineMacula\Laravel\Authentication\Contracts\Identity, \SineMacula\Laravel\Authentication\Contracts\Device): int, 1: \SineMacula\Laravel\Authentication\Events\Enums\RevocationReason, 2: bool}>
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    public static function provideChanges(): iterable
    {
        yield 'devices revoked' => [
            static fn (SessionRevocations $revocations, Identity $identity, Device $device): int => $revocations->revokeDevices($identity, RevocationReason::REVOKED, $device),
            RevocationReason::REVOKED,
            true,
        ];

        yield 'password changed' => [
            static fn (SessionRevocations $revocations, Identity $identity, Device $device): int => $revocations->passwordChanged($identity, $device),
            RevocationReason::PASSWORD_CHANGED,
            true,
        ];

        yield 'password reset' => [
            static fn (SessionRevocations $revocations, Identity $identity): int => $revocations->passwordReset($identity),
            RevocationReason::PASSWORD_RESET,
            false,
        ];

        yield 'factor removed' => [
            static fn (SessionRevocations $revocations, Identity $identity, Device $device): int => $revocations->factorRemoved($identity, $device),
            RevocationReason::FACTOR_REMOVED,
            true,
        ];

        yield 'identity deactivated' => [
            static fn (SessionRevocations $revocations, Identity $identity): int => $revocations->identityDeactivated($identity),
            RevocationReason::IDENTITY_DEACTIVATED,
            false,
        ];
    }

    /**
     * Each change ends the identity's sessions with its own reason, keeping the
     * device given where the change takes one.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  \Closure(\SineMacula\Laravel\Authentication\Sessions\SessionRevocations, \SineMacula\Laravel\Authentication\Contracts\Identity, \SineMacula\Laravel\Authentication\Contracts\Device): int  $change
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

        self::assertSame($keeps ? 1 : 2, $change($revocations, $identity, $kept->device));
        self::assertSame($reason->value, DB::table('devices')->where('id', self::idOf($ended))->value('revoked_reason'));
        self::assertSame($keeps ? null : $reason->value, DB::table('devices')->where('id', self::idOf($kept))->value('revoked_reason'));
    }

    /**
     * Revoking one device of its owner, or every device acting as a principal
     * on its deactivation, ends those sessions with the reason given or the
     * principal's; the one device's revocation names the principal its row
     * records.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testOneDeviceOrAPrincipalsDevicesEnd(): void
    {
        $identity    = $this->seedIdentity();
        $first       = $this->signIn();
        $second      = $this->signIn();
        $revocations = SessionRevocations::forContext($this->freshGuard()->context(), app());

        $this->recordEvents([DeviceRevoked::class]);

        self::assertTrue($revocations->revokeDevice($identity, self::idOf($first), RevocationReason::REVOKED));
        self::assertFalse($revocations->revokeDevice($identity, self::idOf($first), RevocationReason::REVOKED));

        $context = $this->recordedEvent(DeviceRevoked::class)->context;

        self::assertNull($context->principal);
        self::assertSame($identity->getMorphClass(), $context->principalMorphClass);
        self::assertSame(IdentifierCoercion::stringify($identity->getKey()), $context->principalId);
        self::assertSame(1, $revocations->principalDeactivated($identity));
        self::assertSame('revoked', DB::table('devices')->where('id', self::idOf($first))->value('revoked_reason'));
        self::assertSame('principal_deactivated', DB::table('devices')->where('id', self::idOf($second))->value('revoked_reason'));
    }

    /**
     * Revoking every device acting as a principal keeps the one given, and ends
     * the rest with the reason given.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPrincipalsDevicesEndButTheOneKept(): void
    {
        $identity    = $this->seedIdentity();
        $kept        = $this->signIn();
        $ended       = $this->signIn();
        $revocations = SessionRevocations::forContext($this->freshGuard()->context(), app());

        self::assertSame(1, $revocations->revokePrincipalDevices($identity, RevocationReason::REVOKED, $kept->device));
        self::assertNull(DB::table('devices')->where('id', self::idOf($kept))->value('revoked_at'));
        self::assertSame('revoked', DB::table('devices')->where('id', self::idOf($ended))->value('revoked_reason'));
    }

    /**
     * Revoking every device of an identity whose identifiers can be changed
     * cancels its pending changes; another identity's, whose identifiers cannot
     * be changed, keeps the row its key would name.
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

            $revocations->revokeDevices($changeable, RevocationReason::REVOKED);
            $revocations->revokeDevices($plain, RevocationReason::REVOKED);

            self::assertSame([PendingChanges::key($plain, 'email')], DB::table('identifier_changes')->pluck('id')->all());
        } finally {
            self::dropChangeableIdentitiesTable();
        }
    }

    /**
     * A tenant's deactivation ends the sessions of the principals listed for
     * it, principals of two types with one identifier each, and reports one
     * `SignedOutEverywhere` per principal, however often one is listed; with
     * none listed it ends nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATenantsDeactivationEndsEachPrincipalListedForIt(): void
    {
        [, $membership, $tenant] = $this->seedMember();

        $eager = EagerTenantMembership::query()->findOrFail($membership->getKey());

        self::sessionsOf($this->freshGuard('members'))->signIn('password', self::credentials('member@example.test'));

        $revocations = SessionRevocations::forContext($this->freshGuard('members')->context(), app());

        $this->recordEvents([SignedOutEverywhere::class]);

        self::assertSame(0, $revocations->tenantDeactivated($tenant, []));
        self::assertSame([], $this->recordedClasses());
        self::assertSame(1, $revocations->tenantDeactivated($tenant, [$membership, $membership, $eager]));

        $principals = array_map(static fn (object $event): ?string => $event instanceof SignedOutEverywhere ? $event->context->principalMorphClass : null, $this->recorded);

        self::assertSame([ActivatableTenantMembership::class, EagerTenantMembership::class], $principals);
        self::assertSame('tenant_deactivated', DB::table('devices')->value('revoked_reason'));
    }

    /**
     * Rows of `[the tenant to deactivate, from the member's own, the principal
     * listed after the member, if any]`: in each, one of them does not act
     * within the tenant.
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

        self::sessionsOf($this->freshGuard('members'))->signIn('password', self::credentials('member@example.test'));

        $revocations = SessionRevocations::forContext($this->freshGuard('members')->context(), app());
        $deactivated = $tenantOf($tenant);
        $listed      = array_filter([$membership, $outsider($this)]);

        try {
            $revocations->tenantDeactivated($deactivated, $listed);
            self::fail('A principal that does not act within the tenant was accepted.');
        } catch (\InvalidArgumentException $exception) {
            self::assertStringContainsString('does not act within tenant ' . $deactivated::class, $exception->getMessage());
        }

        self::assertSame(0, DB::table('devices')->whereNotNull('revoked_at')->count());
    }

    /**
     * A revocation inside a transaction reports `DeviceRevoked` once it
     * commits, to the guard's dispatcher as it is then: a dispatcher swapped in
     * before the commit receives it, and the one replaced receives nothing.
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

        $swapped->listen(DeviceRevoked::class, static function (DeviceRevoked $event) use (&$received): void {
            $received[] = $event->reason;
        });

        $this->recordEvents([DeviceRevoked::class]);

        DB::transaction(static function () use ($revocations, $identity, $session, $guard, $swapped): void {
            self::assertTrue($revocations->revokeDevice($identity, self::idOf($session), RevocationReason::REVOKED));

            $guard->setDispatcher($swapped);
        });

        self::assertSame([RevocationReason::REVOKED], $received);
        self::assertSame([], $this->recordedClasses());
    }

    /**
     * A JWT guard's `logout()` signs the session out through session
     * revocations it builds on its own context for the sign-out, with no
     * session service, and the device is revoked and reported before `Logout`.
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
            Request::create('/logout', 'POST', server: ['HTTP_AUTHORIZATION' => 'Bearer ' . $session->tokens->accessToken]),
            new Timebox,
            Auth::jwt('api'),
            static function (GuardContext $context) use (&$built): SessionRevocations {
                $built[] = $context;

                return new SessionRevocations(
                    $context,
                    new DeviceRevocations(app(ConnectionResolverInterface::class), static fn (): mixed => app('db.transactions')),
                    app(),
                );
            },
            static fn (): RefreshTokenTransport => RefreshTokenTransport::forGuard('api', config()),
        );

        $this->recordEvents([DeviceRevoked::class, Logout::class]);

        $guard->logout();

        self::assertSame([$guard->context()], $built);
        self::assertSame([DeviceRevoked::class, Logout::class], $this->recordedClasses());
        self::assertTrue($guard->guest());
        self::assertSame('signed_out', DB::table('devices')->where('id', self::idOf($session))->value('revoked_reason'));
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
        $session = $this->sessions()->signIn('password', self::credentials())->session;

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
            'HTTP_AUTHORIZATION' => 'Bearer ' . $session->tokens->accessToken,
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
     * The identifier of the session's device.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignedInSession  $session
     * @return string
     */
    private static function idOf(SignedInSession $session): string
    {
        return (string) IdentifierCoercion::stringify($session->device->getDeviceIdentifier());
    }
}
