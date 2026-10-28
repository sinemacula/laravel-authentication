<?php

declare(strict_types = 1);

namespace Tests\Feature\Listeners;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Authentication\Events\SignedOutEverywhere;
use SineMacula\Laravel\Authentication\Listeners\Concerns\RevokesOnceCommitted;
use SineMacula\Laravel\Authentication\Listeners\RevokeDevicesOnPasswordChange;
use SineMacula\Laravel\Authentication\Sessions\Methods\Rehashing;
use Tests\Concerns\InteractsWithSessions;
use Tests\Integration\Fixtures\IntegrationIdentity;
use Tests\TestCase;
use Tests\Unit\Stubs\StubModel;

/**
 * Feature tests of the optional `RevokeDevicesOnPasswordChange` listener,
 * registered by the test as an application registers it: a password saved
 * through Eloquent revokes every session of the identity once it commits, and
 * the automatic rehash on sign-in revokes nothing.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RevokeDevicesOnPasswordChange::class)]
#[CoversTrait(RevokesOnceCommitted::class)]
final class RevokeDevicesOnPasswordChangeTest extends TestCase
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
     * Saving a new password revokes every session of the identity, with
     * `password_changed`; saving anything else revokes nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAChangedPasswordRevokesEverySession(): void
    {
        $identity = $this->seedIdentity();

        $this->signIn();

        IntegrationIdentity::observe(RevokeDevicesOnPasswordChange::class);

        $identity->forceFill(['email' => 'ada.lovelace@example.test'])->save();

        self::assertSame(0, DB::table('devices')->whereNotNull('revoked_at')->count());

        $identity->forceFill(['password' => app(Hasher::class)->make('a new password')])->save();

        self::assertSame('password_changed', DB::table('devices')->value('revoked_reason'));
    }

    /**
     * A password saved while an automatic rehash runs is not a change of
     * password, and a password sign-in's rehash runs marked so.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheAutomaticRehashRevokesNothing(): void
    {
        $identity = $this->seedIdentity();

        $this->signIn();

        IntegrationIdentity::observe(RevokeDevicesOnPasswordChange::class);

        app(Rehashing::class)->during(static function () use ($identity): void {
            $identity->forceFill(['password' => app(Hasher::class)->make(self::PASSWORD)])->save();
        });

        self::assertSame(0, DB::table('devices')->whereNotNull('revoked_at')->count());
        self::assertFalse(app(Rehashing::class)->isRunning());
    }

    /**
     * A change of password made in a transaction revokes nothing until the
     * transaction commits, and nothing at all when it is rolled back.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAChangedPasswordRevokesOnlyOnceItCommits(): void
    {
        $identity = $this->seedIdentity();

        $this->signIn();

        IntegrationIdentity::observe(RevokeDevicesOnPasswordChange::class);

        try {
            DB::transaction(static function () use ($identity): never {
                $identity->forceFill(['password' => app(Hasher::class)->make('a new password')])->save();

                throw new \RuntimeException('roll back');
            });
        } catch (\RuntimeException) {
            self::assertSame(0, DB::table('devices')->whereNotNull('revoked_at')->count());
        }

        DB::transaction(static function () use ($identity): void {

            $identity->forceFill(['password' => app(Hasher::class)->make('another password')])->save();

            self::assertSame(0, DB::table('devices')->whereNotNull('revoked_at')->count());
        });

        self::assertSame(1, DB::table('devices')->whereNotNull('revoked_at')->count());
    }

    /**
     * A model that is not an identity is left alone.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAModelThatIsNotAnIdentityIsLeftAlone(): void
    {
        $this->recordEvents([SignedOutEverywhere::class]);

        $model = new StubModel;
        $model->setRawAttributes(['password' => 'old'], true);
        $model->setRawAttributes(['password' => 'new']);
        $model->syncChanges();

        app(RevokeDevicesOnPasswordChange::class)->updated($model);

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
