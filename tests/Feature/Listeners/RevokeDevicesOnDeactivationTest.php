<?php

declare(strict_types = 1);

namespace Tests\Feature\Listeners;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Authentication\Events\SignedOutEverywhere;
use SineMacula\Laravel\Authentication\Listeners\Concerns\RevokesOnceCommitted;
use SineMacula\Laravel\Authentication\Listeners\RevokeDevicesOnDeactivation;
use Tests\Concerns\InteractsWithSessions;
use Tests\Integration\Fixtures\ActivatableTenant;
use Tests\Integration\Fixtures\ActivatableTenantMember;
use Tests\Integration\Fixtures\ActiveMembership;
use Tests\Integration\Fixtures\IntegrationIdentity;
use Tests\TestCase;
use Tests\Unit\Stubs\StubModel;

/**
 * Feature tests of the optional `RevokeDevicesOnDeactivation` listener,
 * registered by the test as an application registers it: turning an identity or
 * a principal from active to inactive revokes its sessions once the update
 * commits.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RevokeDevicesOnDeactivation::class)]
#[CoversTrait(RevokesOnceCommitted::class)]
final class RevokeDevicesOnDeactivationTest extends TestCase
{
    use InteractsWithSessions;

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
        Schema::dropIfExists('active_memberships');

        $this->dropSessionTables();

        parent::tearDown();
    }

    /**
     * Turning an identity from active to inactive revokes its sessions, with
     * `identity_deactivated`; any other update does not.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testDeactivatingAnIdentityRevokesItsSessions(): void
    {
        $identity = $this->seedIdentity();

        $this->signIn();

        IntegrationIdentity::observe(RevokeDevicesOnDeactivation::class);

        $identity->forceFill(['email' => 'ada.lovelace@example.test'])->save();

        self::assertSame(0, DB::table('devices')->whereNotNull('revoked_at')->count());

        $identity->forceFill(['is_active' => false])->save();

        self::assertSame('identity_deactivated', DB::table('devices')->value('revoked_reason'));
        self::assertFalse($identity->is_active);

        DB::table('devices')->update(['revoked_at' => null, 'revoked_reason' => null]);

        $identity->forceFill(['email' => 'ada@example.test'])->save();

        self::assertSame(0, DB::table('devices')->whereNotNull('revoked_at')->count());
    }

    /**
     * Turning a principal from active to inactive revokes the sessions acting
     * as it, with `principal_deactivated`.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testDeactivatingAPrincipalRevokesItsSessions(): void
    {
        $principal = $this->seedPrincipalSession();

        ActiveMembership::observe(RevokeDevicesOnDeactivation::class);

        $principal->forceFill(['is_active' => false])->save();

        self::assertSame('principal_deactivated', DB::table('devices')->value('revoked_reason'));
    }

    /**
     * Deactivating an identity in a transaction revokes nothing until the
     * transaction commits, and nothing at all when it is rolled back.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testDeactivatingAnIdentityRevokesOnlyOnceItCommits(): void
    {
        $identity = $this->seedIdentity();

        $this->signIn();

        IntegrationIdentity::observe(RevokeDevicesOnDeactivation::class);

        $this->rollBack(static fn () => $identity->forceFill(['is_active' => false])->save());

        $identity->refresh();

        self::assertTrue($identity->is_active);

        DB::transaction(static function () use ($identity): void {

            $identity->forceFill(['is_active' => false])->save();

            self::assertSame(0, DB::table('devices')->whereNotNull('revoked_at')->count());
        });

        self::assertSame('identity_deactivated', DB::table('devices')->value('revoked_reason'));
    }

    /**
     * Deactivating a principal in a transaction revokes nothing until the
     * transaction commits, and nothing at all when it is rolled back.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testDeactivatingAPrincipalRevokesOnlyOnceItCommits(): void
    {
        $principal = $this->seedPrincipalSession();

        ActiveMembership::observe(RevokeDevicesOnDeactivation::class);

        $this->rollBack(static fn () => $principal->forceFill(['is_active' => false])->save());

        $principal->refresh();

        self::assertTrue($principal->is_active);

        DB::transaction(static function () use ($principal): void {

            $principal->forceFill(['is_active' => false])->save();

            self::assertSame(0, DB::table('devices')->whereNotNull('revoked_at')->count());
        });

        self::assertSame('principal_deactivated', DB::table('devices')->value('revoked_reason'));
    }

    /**
     * A model that is not activatable is left alone, as is an activatable one
     * that stays active.
     *
     * @return void
     *
     * @throws \LogicException
     */
    public function testModelsTheListenerDoesNotApplyToAreLeftAlone(): void
    {
        $this->recordEvents([SignedOutEverywhere::class]);

        app(RevokeDevicesOnDeactivation::class)->updated(new StubModel);
        app(RevokeDevicesOnDeactivation::class)->updated($this->tenantChangingFrom(true, true));

        self::assertSame([], $this->recorded);
    }

    /**
     * Deactivating an activatable model that is neither an identity nor a
     * principal, such as a tenant, cannot end its sessions here: the observer
     * was registered where it cannot act, which is reported.
     *
     * @return void
     */
    public function testATenantsDeactivationIsReported(): void
    {
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('Model ' . ActivatableTenant::class . ' is neither an identity nor a principal, so deactivating it ends no sessions here.');

        app(RevokeDevicesOnDeactivation::class)->updated($this->tenantChangingFrom(true, false));
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

        $app->make(ConfigRepository::class)->set('auth.defaults.guard', 'api');
    }

    /**
     * A 3D principal with one live session acting as it, held by its owner.
     *
     * @return \Tests\Integration\Fixtures\ActiveMembership
     */
    private function seedPrincipalSession(): ActiveMembership
    {
        Schema::create('active_memberships', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->unsignedInteger('identity_id');
            $blueprint->boolean('is_active')->default(true);
            $blueprint->timestamps();
        });

        $member = ActivatableTenantMember::query()->create(['email' => 'member@example.test', 'password' => 'unused']);

        $principal = new ActiveMembership;
        $principal->forceFill(['identity_id' => $member->id, 'is_active' => true])->save();

        DB::table('devices')->insert([
            'id'                   => (string) Str::uuid7(),
            'authenticatable_type' => $member->getMorphClass(),
            'authenticatable_id'   => (string) $member->id,
            'principal_type'       => $principal->getMorphClass(),
            'principal_id'         => (string) $principal->id,
            'guard'                => 'members',
            'signed_in_at'         => now(),
            'idle_expires_at'      => now()->addDay(),
            'absolute_expires_at'  => now()->addWeek(),
        ]);

        return $principal;
    }

    /**
     * An activatable tenant as an observer sees it after an update of its
     * activity from one value to another.
     *
     * @param  bool  $before
     * @param  bool  $after
     * @return \Tests\Integration\Fixtures\ActivatableTenant
     */
    private function tenantChangingFrom(bool $before, bool $after): ActivatableTenant
    {
        $tenant = new ActivatableTenant;
        $tenant->setRawAttributes(['id' => 1, 'is_active' => $before], true);
        $tenant->setRawAttributes(['id' => 1, 'is_active' => $after]);

        return $tenant;
    }

    /**
     * Run the change in a transaction that is rolled back, and check it revoked
     * nothing.
     *
     * @param  \Closure(): mixed  $change
     * @return void
     *
     * @throws \Throwable
     */
    private function rollBack(\Closure $change): void
    {
        try {
            DB::transaction(static function () use ($change): never {
                $change();

                throw new \RuntimeException('roll back');
            });
        } catch (\RuntimeException $exception) {
            self::assertSame('roll back', $exception->getMessage());
        }

        self::assertSame(0, DB::table('devices')->whereNotNull('revoked_at')->count());
    }

    /**
     * Sign the seeded identity in.
     *
     * @return void
     *
     * @throws \Throwable
     */
    private function signIn(): void
    {
        self::assertTrue($this->sessions()->signIn('password', self::credentials())->isSignedIn());
    }
}
