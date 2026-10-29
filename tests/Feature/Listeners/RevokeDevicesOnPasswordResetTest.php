<?php

declare(strict_types = 1);

namespace Tests\Feature\Listeners;

use Illuminate\Auth\Events\PasswordReset;
use Illuminate\Auth\GenericUser;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Authentication\Events\SignedOutEverywhere;
use SineMacula\Laravel\Authentication\Listeners\Concerns\RevokesOnceCommitted;
use SineMacula\Laravel\Authentication\Listeners\RevokeDevicesOnPasswordReset;
use Tests\Concerns\InteractsWithSessions;
use Tests\TestCase;
use Tests\Unit\Stubs\PlainIdentityFixture;

/**
 * Feature tests of the optional `RevokeDevicesOnPasswordReset` listener,
 * registered by the test as an application registers it: a reset through
 * Laravel's password broker revokes every session of the identity once the
 * reset commits.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RevokeDevicesOnPasswordReset::class)]
#[CoversTrait(RevokesOnceCommitted::class)]
final class RevokeDevicesOnPasswordResetTest extends TestCase
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
     * A password reset through the broker revokes every session of the
     * identity, with `password_reset`.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPasswordResetRevokesEverySession(): void
    {
        $identity = $this->seedIdentity();

        $this->signIn();
        $this->signIn();

        Event::listen(PasswordReset::class, RevokeDevicesOnPasswordReset::class);

        event(new PasswordReset($identity));

        self::assertSame(['password_reset', 'password_reset'], DB::table('devices')->pluck('revoked_reason')->all());
    }

    /**
     * A reset that is rolled back revokes nothing; one that commits revokes
     * once it commits. A user that is not an identity is left alone.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPasswordResetRevokesOnlyOnceItCommits(): void
    {
        $identity = $this->seedIdentity();

        $this->signIn();

        Event::listen(PasswordReset::class, RevokeDevicesOnPasswordReset::class);

        event(new PasswordReset(new GenericUser(['id' => $identity->id])));

        try {
            DB::transaction(static function () use ($identity): never {
                event(new PasswordReset($identity));

                throw new \RuntimeException('roll back');
            });
        } catch (\RuntimeException) {
            self::assertSame(0, DB::table('devices')->whereNotNull('revoked_at')->count());
        }

        DB::transaction(static function () use ($identity): void {

            event(new PasswordReset($identity));

            self::assertSame(0, DB::table('devices')->whereNotNull('revoked_at')->count());
        });

        self::assertSame(1, DB::table('devices')->whereNotNull('revoked_at')->count());
    }

    /**
     * An identity that is not an Eloquent model has no transaction to wait for:
     * its reset is answered as it is dispatched, and reported.
     *
     * @return void
     */
    public function testAResetOfAnIdentityThatIsNotAModelIsAnswered(): void
    {
        Event::listen(PasswordReset::class, RevokeDevicesOnPasswordReset::class);

        $this->recordEvents([SignedOutEverywhere::class]);

        event(new PasswordReset(new PlainIdentityFixture(7)));

        self::assertSame('7', $this->recordedEvent(SignedOutEverywhere::class)->context->identityId);
    }

    /**
     * A route guarded by another driver makes that driver's guard the default
     * (`shouldUse()`); the listener still revokes, through the first jwt guard
     * configured, and reports that guard as the acting one.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARouteGuardedByAnotherDriverStillRevokes(): void
    {
        $identity = $this->seedIdentity();

        $this->signIn();

        Event::listen(PasswordReset::class, RevokeDevicesOnPasswordReset::class);

        $this->recordEvents([SignedOutEverywhere::class]);

        Auth::shouldUse('web');

        event(new PasswordReset($identity));

        self::assertSame(['password_reset'], DB::table('devices')->pluck('revoked_reason')->all());
        self::assertSame('api', $this->recordedEvent(SignedOutEverywhere::class)->context->guard);
    }

    /**
     * A jwt guard that is the default acts, whichever it is.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheDefaultJwtGuardActs(): void
    {
        $identity = $this->seedIdentity();

        Event::listen(PasswordReset::class, RevokeDevicesOnPasswordReset::class);

        $this->recordEvents([SignedOutEverywhere::class]);

        Auth::shouldUse('members');

        event(new PasswordReset($identity));

        self::assertSame('members', $this->recordedEvent(SignedOutEverywhere::class)->context->guard);
    }

    /**
     * A guard given to the listener through a contextual binding acts, though
     * the default is another jwt guard.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAGuardGivenToTheListenerActs(): void
    {
        $identity = $this->seedIdentity();

        app()->when(RevokeDevicesOnPasswordReset::class)->needs('$guard')->give('admin');

        Event::listen(PasswordReset::class, RevokeDevicesOnPasswordReset::class);

        $this->recordEvents([SignedOutEverywhere::class]);

        event(new PasswordReset($identity));

        self::assertSame('admin', $this->recordedEvent(SignedOutEverywhere::class)->context->guard);
    }

    /**
     * With no jwt guard configured there is no session service to revoke
     * through: a misconfiguration, reported rather than ignored.
     *
     * @return void
     */
    public function testNoJwtGuardConfiguredIsReported(): void
    {
        $identity = $this->seedIdentity();

        config()->set('auth.guards', ['web' => ['driver' => 'session', 'provider' => 'identities']]);
        config()->set('auth.defaults.guard', 'web');

        Event::listen(PasswordReset::class, RevokeDevicesOnPasswordReset::class);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('No jwt guard is configured, so no session service can revoke the sessions.');

        event(new PasswordReset($identity));
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
