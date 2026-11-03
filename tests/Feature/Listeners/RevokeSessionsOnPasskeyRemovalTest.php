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
use SineMacula\Laravel\Authentication\Listeners\RevokeSessionsOnPasskeyRemoval;
use Tests\Concerns\InteractsWithPasskeys;
use Tests\Concerns\InteractsWithSessions;
use Tests\TestCase;
use Tests\Unit\Stubs\PlainIdentityFixture;

/**
 * Feature tests of the optional `RevokeSessionsOnPasskeyRemoval` listener,
 * registered as an application registers it: removing a passkey ends every
 * session of its owner, once the removal commits.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RevokeSessionsOnPasskeyRemoval::class)]
final class RevokeSessionsOnPasskeyRemovalTest extends TestCase
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

        Event::listen(PasskeyRemoved::class, RevokeSessionsOnPasskeyRemoval::class);
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

        $reasons = DB::table('authentication_sessions')->where('authenticatable_id', (string) $identity->id)->pluck('revoked_reason')->all();

        self::assertSame(['factor_removed', 'factor_removed'], $reasons);
        self::assertSame([null], DB::table('authentication_sessions')->where('authenticatable_id', '!=', (string) $identity->id)->pluck('revoked_reason')->all());
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

        self::assertSame([null], DB::table('authentication_sessions')->pluck('revoked_reason')->all());
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

        self::assertSame([null], DB::table('authentication_sessions')->pluck('revoked_reason')->all());
    }

    /**
     * An identity the guard's provider no longer finds, or one the provider
     * finds under the identifier but of another type than the event names, has
     * nothing revoked: the identity the event names is not the provider's.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnIdentityTheProviderDoesNotReturnRevokesNothing(): void
    {
        $identity = $this->seedIdentity();

        $this->registerPasskey($identity);

        self::assertTrue($this->signInWithPasskey()->isSignedIn());

        $client = new ClientContext(null, null);

        event(new PasskeyRemoved(new EventContext('api', $client, new PlainIdentityFixture($identity->id), method: 'passkey', credentialId: 'removed')));
        event(new PasskeyRemoved(new EventContext('api', $client, new PlainIdentityFixture($identity->id + 1), method: 'passkey', credentialId: 'removed')));

        self::assertSame([null], DB::table('authentication_sessions')->pluck('revoked_reason')->all());
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
