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
use Tests\Integration\Fixtures\Coexist3dPrincipal;
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
        Schema::dropIfExists('coexist_3d_principals');

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
        Schema::create('coexist_3d_principals', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->unsignedInteger('identity_id');
            $blueprint->string('name');
            $blueprint->boolean('is_active')->default(true);
            $blueprint->timestamps();
        });

        $principal = new Coexist3dPrincipal;
        $principal->forceFill(['identity_id' => 1, 'name' => 'Member', 'is_active' => true])->save();

        DB::table('devices')->insert([
            'id'                   => (string) Str::uuid7(),
            'authenticatable_type' => 'identity',
            'authenticatable_id'   => '1',
            'principal_type'       => Coexist3dPrincipal::class,
            'principal_id'         => (string) $principal->id,
            'guard'                => 'api',
            'signed_in_at'         => now(),
            'idle_expires_at'      => now()->addDay(),
            'absolute_expires_at'  => now()->addWeek(),
        ]);

        Coexist3dPrincipal::observe(RevokeDevicesOnDeactivation::class);

        $principal->forceFill(['is_active' => false])->save();

        self::assertSame('principal_deactivated', DB::table('devices')->value('revoked_reason'));
    }

    /**
     * A model the listener does not apply to is left alone: one that is not
     * activatable, or activatable but neither an identity nor a principal.
     *
     * @return void
     */
    public function testModelsTheListenersDoNotApplyToAreLeftAlone(): void
    {
        $this->recordEvents([SignedOutEverywhere::class]);

        $tenant = new ActivatableTenant;
        $tenant->setRawAttributes(['id' => 1, 'is_active' => false]);
        $tenant->syncOriginal();
        $tenant->setRawAttributes(['id' => 1, 'is_active' => true], true);
        $tenant->setRawAttributes(['id' => 1, 'is_active' => false]);

        app(RevokeDevicesOnDeactivation::class)->updated(new StubModel);
        app(RevokeDevicesOnDeactivation::class)->updated($tenant);

        self::assertSame([], $this->recorded);
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
