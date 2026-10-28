<?php

declare(strict_types = 1);

namespace Tests\Feature\Sessions;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Eloquent\Relations\Relation;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversTrait;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\Device;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Events\DeviceRevoked;
use SineMacula\Laravel\Authentication\Events\Enums\RevocationReason;
use SineMacula\Laravel\Authentication\Events\SignedOutEverywhere;
use SineMacula\Laravel\Authentication\Jwt\IdentifierCoercion;
use SineMacula\Laravel\Authentication\Sessions\Concerns\RevokesOnSecurityChanges;
use SineMacula\Laravel\Authentication\Sessions\DeviceRevocations;
use SineMacula\Laravel\Authentication\Sessions\SessionService;
use SineMacula\Laravel\Authentication\Sessions\SignedInSession;
use Tests\Concerns\InteractsWithSessions;
use Tests\Integration\Fixtures\ActivatableTenant;
use Tests\Integration\Fixtures\ActivatableTenantMembership;
use Tests\Integration\Fixtures\CutoffIdentity;
use Tests\Integration\Fixtures\EagerTenantMembership;
use Tests\TestCase;

/**
 * Feature tests of the session service's answers to security changes: each ends
 * the affected sessions with its own reason and moves the scope's cutoff,
 * keeping a device only where the method lets the caller name one; a tenant's
 * deactivation ends its principals' sessions only once every principal is
 * proven to act within it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SessionService::class)]
#[CoversClass(DeviceRevocations::class)]
#[CoversTrait(RevokesOnSecurityChanges::class)]
final class RevokesOnSecurityChangesTest extends TestCase
{
    use InteractsWithSessions;

    /** @var string The frozen time every revocation happens at. */
    private const string NOW = '2027-01-15 10:00:00';

    /**
     * Freeze the clock and create the tables.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        CarbonImmutable::setTestNow(CarbonImmutable::parse(self::NOW));

        $this->createSessionTables();

        Schema::create('cutoff_identities', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('email')->unique();
            $blueprint->string('password')->nullable();
            $blueprint->boolean('is_active')->default(true);
            $blueprint->dateTime('tokens_valid_after', 0)->nullable();
            $blueprint->timestamps();
        });
    }

    /**
     * Release the clock and drop the tables.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        CarbonImmutable::setTestNow();

        Schema::dropIfExists('cutoff_identities');

        $this->dropSessionTables();

        parent::tearDown();
    }

    /**
     * Rows of `[the change, its reason, whether it keeps a device it is
     * given]`.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @return iterable<string, array{0: \Closure(\SineMacula\Laravel\Authentication\Sessions\SessionService, \SineMacula\Laravel\Authentication\Contracts\Identity, \SineMacula\Laravel\Authentication\Contracts\Device): int, 1: \SineMacula\Laravel\Authentication\Events\Enums\RevocationReason, 2: bool}>
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    public static function provideIdentityChanges(): iterable
    {
        yield 'password changed' => [
            static fn (SessionService $sessions, Identity $identity, Device $device): int => $sessions->passwordChanged($identity, $device),
            RevocationReason::PASSWORD_CHANGED,
            true,
        ];

        yield 'password reset' => [
            static fn (SessionService $sessions, Identity $identity): int => $sessions->passwordReset($identity),
            RevocationReason::PASSWORD_RESET,
            false,
        ];

        yield 'factor removed' => [
            static fn (SessionService $sessions, Identity $identity, Device $device): int => $sessions->factorRemoved($identity, $device),
            RevocationReason::FACTOR_REMOVED,
            true,
        ];

        yield 'identity deactivated' => [
            static fn (SessionService $sessions, Identity $identity): int => $sessions->identityDeactivated($identity),
            RevocationReason::IDENTITY_DEACTIVATED,
            false,
        ];
    }

    /**
     * Each change of an identity ends its sessions with the change's reason and
     * moves its cutoff; a change that may keep the device it was made from
     * keeps it when given one.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  \Closure(\SineMacula\Laravel\Authentication\Sessions\SessionService, \SineMacula\Laravel\Authentication\Contracts\Identity, \SineMacula\Laravel\Authentication\Contracts\Device): int  $change
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
    #[DataProvider('provideIdentityChanges')]
    public function testAnIdentitysChangeEndsItsSessionsWithItsReason(\Closure $change, RevocationReason $reason, bool $keeps): void
    {
        $identity = $this->cutoffIdentity();
        $kept     = $this->signIn($identity);
        $other    = $this->signIn($identity);

        $this->recordEvents([DeviceRevoked::class, SignedOutEverywhere::class]);

        $revoked = $change($this->sessions(), $identity, $kept->device);

        self::assertSame($keeps ? 1 : 2, $revoked);
        self::assertSame($reason->value, DB::table('devices')->where('id', $other->device->getKey())->value('revoked_reason'));
        self::assertSame($keeps ? null : $reason->value, DB::table('devices')->where('id', $kept->device->getKey())->value('revoked_reason'));
        self::assertSame(self::NOW, DB::table('cutoff_identities')->value('tokens_valid_after'));

        $scope = $this->recordedEvent(SignedOutEverywhere::class);

        self::assertSame($reason, $scope->reason);
        self::assertSame(self::NOW, $scope->tokensValidAfter?->format('Y-m-d H:i:s'));
    }

    /**
     * A principal's deactivation ends only the sessions acting as it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPrincipalsDeactivationEndsItsSessions(): void
    {
        [, $membership, $tenant] = $this->seedMember();

        $this->seedMember('other@example.test', $tenant);

        $this->memberSignIn('member@example.test');
        $this->memberSignIn('other@example.test');

        self::assertSame(1, $this->sessions('members')->principalDeactivated($membership));
        self::assertSame(['principal_deactivated'], DB::table('devices')->whereNotNull('revoked_at')->pluck('revoked_reason')->all());
    }

    /**
     * A tenant's deactivation ends the sessions of every principal listed for
     * it, a principal listed twice once, in one transaction, with one report
     * per principal carrying the tenant.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATenantsDeactivationEndsItsPrincipalsSessions(): void
    {
        [, $first, $tenant] = $this->seedMember();
        [, $second]         = $this->seedMember('other@example.test', $tenant);
        [, $outsider]       = $this->seedMember('outsider@example.test');

        $this->memberSignIn('member@example.test');
        $this->memberSignIn('other@example.test');
        $this->memberSignIn('outsider@example.test');

        $this->recordEvents([DeviceRevoked::class, SignedOutEverywhere::class]);

        self::assertSame(2, $this->sessions('members')->tenantDeactivated($tenant, [$first, $second, $first]));

        self::assertSame(
            [DeviceRevoked::class, SignedOutEverywhere::class, DeviceRevoked::class, SignedOutEverywhere::class],
            $this->recordedClasses(),
        );

        foreach ($this->recorded as $event) {
            self::assertTrue($event instanceof DeviceRevoked || $event instanceof SignedOutEverywhere);
            self::assertSame($tenant, $event->context->tenant);
            self::assertSame(RevocationReason::TENANT_DEACTIVATED, $event->reason);
        }

        self::assertSame(IdentifierCoercion::stringify($outsider->getKey()), DB::table('devices')->whereNull('revoked_at')->value('principal_id'));
    }

    /**
     * Principals of different types with the same identifier are different
     * principals: each is its own scope with its own report.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testPrincipalsOfDifferentTypesWithOneIdentifierAreBothEnded(): void
    {
        [, $membership, $tenant] = $this->seedMember();

        $eager = EagerTenantMembership::query()->findOrFail($membership->getKey());

        $this->recordEvents([SignedOutEverywhere::class]);

        $this->sessions('members')->tenantDeactivated($tenant, [$membership, $eager]);

        $principals = array_map(static fn (object $event): ?string => $event instanceof SignedOutEverywhere ? $event->context->principalType : null, $this->recorded);

        self::assertSame([ActivatableTenantMembership::class, EagerTenantMembership::class], $principals);
    }

    /**
     * A principal that does not act within the tenant is refused before
     * anything is written, even when listed after one that does.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATenantsDeactivationRefusesAPrincipalOfAnotherTenant(): void
    {
        [, $member, $tenant] = $this->seedMember();
        [, $outsider]        = $this->seedMember('outsider@example.test');

        $this->memberSignIn('member@example.test');

        $sessions = $this->sessions('members');

        try {
            $sessions->tenantDeactivated($tenant, [$member, $outsider]);
            self::fail('A principal of another tenant was accepted.');
        } catch (\InvalidArgumentException $exception) {
            $expected = 'does not act within tenant ' . ActivatableTenant::class . ' ' . IdentifierCoercion::stringify($tenant->getKey());

            self::assertStringContainsString($expected, $exception->getMessage());
        }

        self::assertSame(0, DB::table('devices')->whereNotNull('revoked_at')->count());
    }

    /**
     * A principal that acts within no tenant is refused too.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATenantsDeactivationRefusesAPrincipalWithoutATenant(): void
    {
        [, , $tenant] = $this->seedMember();

        $identity = $this->cutoffIdentity();

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('does not act within tenant');

        $this->sessions('members')->tenantDeactivated($tenant, [$identity]);
    }

    /**
     * A tenant already soft-deleted, or deleted outright, can no longer be
     * loaded through its principals, but a principal naming it still acts
     * within it: its sessions end, so restoring the tenant revives none. A
     * principal naming another deleted tenant is still refused.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testADeletedTenantsDeactivationEndsItsPrincipalsSessions(): void
    {
        [, $member, $tenant]   = $this->seedMember();
        [, $other, $elsewhere] = $this->seedMember('other@example.test');

        $this->memberSignIn('member@example.test');

        $tenant->delete();
        $elsewhere->forceDelete();

        try {
            $this->sessions('members')->tenantDeactivated($tenant, [$other->fresh()]);
            self::fail('A principal of another deleted tenant was accepted.');
        } catch (\InvalidArgumentException $exception) {
            self::assertStringContainsString('does not act within tenant', $exception->getMessage());
        }

        self::assertSame(1, $this->sessions('members')->tenantDeactivated($tenant, [$member->fresh()]));
        self::assertSame('tenant_deactivated', DB::table('devices')->value('revoked_reason'));

        [, $last, $gone] = $this->seedMember('last@example.test');

        $this->memberSignIn('last@example.test');

        $gone->forceDelete();

        self::assertSame(1, $this->sessions('members')->tenantDeactivated($gone, [$last->fresh()]));
    }

    /**
     * Two principals whose recorded type and identifier run together into the
     * same string (`member` with `12`, `member1` with `2`) are two principals,
     * both ended.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testPrincipalsWhoseTypeAndIdentifierRunTogetherAreBothEnded(): void
    {
        Relation::morphMap(['member' => ActivatableTenantMembership::class, 'member1' => EagerTenantMembership::class]);

        try {
            $tenant = ActivatableTenant::query()->create(['name' => 'Tenant', 'is_active' => true]);

            foreach ([12, 2] as $id) {
                DB::table('activatable_tenant_memberships')->insert(['id' => $id, 'identity_id' => $id, 'tenant_id' => $tenant->getKey()]);
            }

            $this->recordEvents([SignedOutEverywhere::class]);

            $this->sessions('members')->tenantDeactivated($tenant, [
                ActivatableTenantMembership::query()->findOrFail(12),
                EagerTenantMembership::query()->findOrFail(2),
            ]);

            $principals = array_map(
                static fn (object $event): ?string => $event instanceof SignedOutEverywhere ? $event->context->principalType . ':' . $event->context->principalId : null,
                $this->recorded,
            );

            self::assertSame(['member:12', 'member1:2'], $principals);
        } finally {
            Relation::morphMap([], false);
        }
    }

    /**
     * A tenant with no principals listed has nothing to end.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATenantWithNoPrincipalsListedEndsNothing(): void
    {
        [, , $tenant] = $this->seedMember();

        $this->recordEvents([SignedOutEverywhere::class]);

        self::assertSame(0, $this->sessions('members')->tenantDeactivated($tenant, []));
        self::assertSame([], $this->recorded);
    }

    /**
     * Register the session guards, and a guard over the identities that record
     * a cutoff.
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

        $config->set('auth.providers.identities', ['driver' => 'model', 'model' => CutoffIdentity::class]);
    }

    /**
     * Persist an identity that records a cutoff, with the test password.
     *
     * @return \Tests\Integration\Fixtures\CutoffIdentity
     */
    private function cutoffIdentity(): CutoffIdentity
    {
        $identity = new CutoffIdentity;
        $identity->forceFill(['email' => 'ada@example.test', 'password' => bcrypt(self::PASSWORD)])->save();

        return CutoffIdentity::query()->findOrFail($identity->id);
    }

    /**
     * Start a session for the identity.
     *
     * @param  \Tests\Integration\Fixtures\CutoffIdentity  $identity
     * @return \SineMacula\Laravel\Authentication\Sessions\SignedInSession
     *
     * @throws \Throwable
     */
    private function signIn(CutoffIdentity $identity): SignedInSession
    {
        $session = $this->sessions()->start($identity, null, 'sso')->session;

        self::assertNotNull($session);

        return $session;
    }

    /**
     * Sign the member with the email in on the `members` guard.
     *
     * @param  string  $email
     * @return void
     *
     * @throws \Throwable
     */
    private function memberSignIn(string $email): void
    {
        self::assertTrue($this->sessions('members')->signIn('password', self::credentials($email))->isSignedIn());
    }
}
