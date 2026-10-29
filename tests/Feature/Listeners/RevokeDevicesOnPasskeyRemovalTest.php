<?php

declare(strict_types = 1);

namespace Tests\Feature\Listeners;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Events\EventContext;
use SineMacula\Laravel\Authentication\Events\PasskeyRemoved;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Listeners\RevokeDevicesOnPasskeyRemoval;
use Tests\Concerns\InteractsWithPasskeys;
use Tests\Concerns\InteractsWithSessions;
use Tests\TestCase;

/**
 * Feature tests of the optional `RevokeDevicesOnPasskeyRemoval` listener,
 * registered as an application registers it: removing a passkey ends every
 * session of its owner, once the removal commits.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RevokeDevicesOnPasskeyRemoval::class)]
final class RevokeDevicesOnPasskeyRemovalTest extends TestCase
{
    use InteractsWithPasskeys, InteractsWithSessions;

    /**
     * Create the tables and register the listener.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->createSessionTables();

        Event::listen(PasskeyRemoved::class, RevokeDevicesOnPasskeyRemoval::class);
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
     * Removing a passkey revokes every session of its owner, the one signed in
     * with it and a password session alike, with `factor_removed`; another
     * identity's sessions are left alone.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRemovingAPasskeyRevokesEverySessionOfItsOwner(): void
    {
        $identity = $this->seedIdentity();
        $passkey  = $this->registerPasskey($identity);

        $this->seedIdentity('grace@example.test');

        self::assertTrue($this->signInWithPasskey()->isSignedIn());
        self::assertTrue($this->sessions()->signIn('password', self::credentials())->isSignedIn());
        self::assertTrue($this->sessions()->signIn('password', self::credentials('grace@example.test'))->isSignedIn());

        Auth::passkeys('api')->remove($identity, $passkey->id);

        self::assertSame(['factor_removed', 'factor_removed'], DB::table('devices')->where('authenticatable_id', (string) $identity->id)->pluck('revoked_reason')->all());
        self::assertSame([null], DB::table('devices')->where('authenticatable_id', '!=', (string) $identity->id)->pluck('revoked_reason')->all());
    }

    /**
     * A removal that is rolled back revokes nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARemovalThatRollsBackRevokesNothing(): void
    {
        $identity = $this->seedIdentity();
        $passkey  = $this->registerPasskey($identity);

        self::assertTrue($this->signInWithPasskey()->isSignedIn());

        DB::beginTransaction();

        Auth::passkeys('api')->remove($identity, $passkey->id);

        DB::rollBack();

        self::assertSame([null], DB::table('devices')->pluck('revoked_reason')->all());
    }

    /**
     * An event that carries no identity revokes nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnEventWithoutAnIdentityRevokesNothing(): void
    {
        $this->registerPasskey($this->seedIdentity());

        self::assertTrue($this->signInWithPasskey()->isSignedIn());

        event(new PasskeyRemoved(new EventContext('api', new ClientContext(null, null), method: 'passkey', credentialId: 'removed')));

        self::assertSame([null], DB::table('devices')->pluck('revoked_reason')->all());
    }

    /**
     * Configure the guards and their relying party.
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
        self::configurePasskeys($config);
    }
}
