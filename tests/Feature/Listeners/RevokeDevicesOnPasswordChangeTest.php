<?php

declare(strict_types = 1);

namespace Tests\Feature\Listeners;

use Illuminate\Auth\SessionGuard;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversTrait;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Events\DeviceRevoked;
use SineMacula\Laravel\Authentication\Events\Enums\RevocationReason;
use SineMacula\Laravel\Authentication\Events\SignedOutEverywhere;
use SineMacula\Laravel\Authentication\Jwt\IdentifierCoercion;
use SineMacula\Laravel\Authentication\Listeners\Concerns\RevokesOnceCommitted;
use SineMacula\Laravel\Authentication\Listeners\RevokeDevicesOnPasswordChange;
use SineMacula\Laravel\Authentication\Sessions\Methods\Rehashing;
use SineMacula\Laravel\Authentication\Sessions\SignedInSession;
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

    /** @var string A bcrypt hash of the password at a cost above the configured one, so it needs a rehash. */
    private const string OUTDATED_HASH = '$2y$05$FUGa4CVUj5UzYQ3xqFzx.OPRl9hwbG1FvcqaKKSd9dC1YsmE4WhWO';

    /**
     * Create the tables and register the route.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->createSessionTables();

        Route::middleware('auth:api')->get('/me', static fn (): array => ['identity' => Auth::id()]);
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
     * password, and a password sign-in's rehash runs marked so; the same save
     * once the rehash is over is a change.
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

        app(Rehashing::class)->during($identity, static function () use ($identity): void {
            $identity->forceFill(['password' => app(Hasher::class)->make(self::PASSWORD)])->save();
        });

        self::assertSame(0, DB::table('devices')->whereNotNull('revoked_at')->count());

        $identity->forceFill(['password' => app(Hasher::class)->make(self::PASSWORD)])->save();

        self::assertSame('password_changed', DB::table('devices')->value('revoked_reason'));
    }

    /**
     * Laravel's own guard rehashes an outdated hash on `attempt()` through its
     * Eloquent user provider, which saves the model: not a change of password,
     * so nothing is revoked, though the stored hash was upgraded. Once the
     * attempt has ended, the same save is a change.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testLaravelsRehashOnAttemptRevokesNothing(): void
    {
        $identity = $this->seedOutdatedHash();

        self::assertTrue($this->webGuard()->attempt(self::credentials()));

        self::assertNotSame(self::OUTDATED_HASH, $identity->fresh()?->getAuthPassword());
        self::assertSame(0, DB::table('devices')->whereNotNull('revoked_at')->count());

        $identity->forceFill(['password' => app(Hasher::class)->make(self::PASSWORD)])->save();

        self::assertSame('password_changed', DB::table('devices')->value('revoked_reason'));
    }

    /**
     * The same holds for `once()`, which rehashes and then binds the user with
     * `Authenticated` alone, and `attemptWhen()`.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testLaravelsRehashOnOnceAndAttemptWhenRevokesNothing(): void
    {
        $identity = $this->seedOutdatedHash();

        self::assertTrue($this->webGuard()->once(self::credentials()));
        self::assertNotSame(self::OUTDATED_HASH, $identity->fresh()?->getAuthPassword());

        DB::table('integration_identities')->update(['password' => self::OUTDATED_HASH]);

        self::assertTrue($this->webGuard()->attemptWhen(self::credentials(), static fn (): bool => true));

        self::assertNotSame(self::OUTDATED_HASH, $identity->fresh()?->getAuthPassword());
        self::assertSame(0, DB::table('devices')->whereNotNull('revoked_at')->count());
    }

    /**
     * Confirming the current password with `validate()` before changing it is
     * not an attempt, so the change that follows revokes, as it does after an
     * attempt that failed or that its callbacks refused.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAChangeAfterAValidationOrAFailedAttemptRevokes(): void
    {
        $identity = $this->seedOutdatedHash();
        $guard    = $this->webGuard();

        self::assertFalse($guard->attempt(['email' => 'ada@example.test', 'password' => 'wrong']));
        self::assertFalse($guard->attemptWhen(self::credentials(), static fn (): bool => false));
        self::assertTrue($guard->validate(self::credentials()));

        $identity->forceFill(['password' => app(Hasher::class)->make('a new password')])->save();

        self::assertSame('password_changed', DB::table('devices')->value('revoked_reason'));
    }

    /**
     * Rows of `[whether the callback admits the attempt]`.
     *
     * @return iterable<string, array{0: bool}>
     */
    public static function provideCallbackAnswers(): iterable
    {
        yield 'a callback that admits the attempt' => [true];
        yield 'a callback that refuses the attempt' => [false];
    }

    /**
     * No event separates `attemptWhen()`'s callbacks from the guard's rehash,
     * so a callback that saves a new password changes it, and revokes, whether
     * it then admits the attempt or refuses it.
     *
     * @param  bool  $admits
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideCallbackAnswers')]
    public function testANewPasswordSavedByAnAttemptsCallbackRevokes(bool $admits): void
    {
        $this->seedOutdatedHash();

        $attempted = $this->webGuard()->attemptWhen(self::credentials(), static function (IntegrationIdentity $user) use ($admits): bool {
            $user->forceFill(['password' => app(Hasher::class)->make('a new password')])->save();

            return $admits;
        });

        self::assertSame($admits, $attempted);
        self::assertSame('password_changed', DB::table('devices')->value('revoked_reason'));
    }

    /**
     * An attempt that threw after validating its user never ended, yet a save
     * of its user's password afterwards, a fresh hash of the same password
     * included, revokes: only a save of the very instance the attempt validated
     * is taken for its rehash.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPasswordSavedAfterAnAttemptThatThrewRevokes(): void
    {
        $identity = $this->seedOutdatedHash();

        try {
            $this->webGuard()->attemptWhen(self::credentials(), static function (): never {
                throw new \RuntimeException('callback failed');
            });
        } catch (\RuntimeException $exception) { // @phpstan-ignore catch.neverThrown
            self::assertSame('callback failed', $exception->getMessage());
        }

        $identity->forceFill(['password' => app(Hasher::class)->make(self::PASSWORD)])->save();

        self::assertSame('password_changed', DB::table('devices')->value('revoked_reason'));
    }

    /**
     * Rows of `[whether the changes run inside the attempt's callback rather
     * than after an attempt whose callback threw, the instance the change back
     * is saved through]`.
     *
     * @return iterable<string, array{0: bool, 1: string}>
     */
    public static function provideChangesBack(): iterable
    {
        foreach (['after an attempt whose callback threw' => false, 'inside the attempt\'s own callback' => true] as $attempt => $inside) {
            yield "{$attempt}, back through the instance that changed it" => [$inside, 'changer'];
            yield "{$attempt}, back through the instance the attempt validated" => [$inside, 'validated'];
            yield "{$attempt}, back through an instance loaded before the change" => [$inside, 'stale'];
        }
    }

    /**
     * While an attempt made with the password is open, or was abandoned by an
     * exception, a change of password revokes, and so does a change back to
     * that password through any instance of the identity, even one still
     * holding the hash from before the change: it is not the attempt's rehash,
     * so the session started between the two changes is ended, its tokens are
     * refused at the `auth` middleware and its refresh token refreshes nothing.
     *
     * @param  bool  $inside
     * @param  string  $back
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideChangesBack')]
    public function testAChangeBackToTheAttemptsPasswordRevokesTheSessionStartedBetween(bool $inside, string $back): void
    {
        $identity = $this->seedIdentity();
        $first    = $this->signIn();
        $stale    = IntegrationIdentity::query()->whereKey($identity->getKey())->firstOrFail();

        IntegrationIdentity::observe(RevokeDevicesOnPasswordChange::class);

        $changes = function (IntegrationIdentity $validated) use ($identity, $stale, $back): SignedInSession {

            $identity->forceFill(['password' => app(Hasher::class)->make('a new password')])->save();

            $between = $this->signIn(['email' => 'ada@example.test', 'password' => 'a new password']);

            $this->recordEvents([DeviceRevoked::class, SignedOutEverywhere::class]);

            $instance = match ($back) {
                'changer'   => $identity,
                'validated' => $validated,
                default     => $stale,
            };

            $instance->forceFill(['password' => app(Hasher::class)->make(self::PASSWORD)])->save();

            return $between;
        };

        $between = null;

        if ($inside) {
            self::assertTrue($this->webGuard()->attemptWhen(self::credentials(), static function (IntegrationIdentity $validated) use ($changes, &$between): bool {
                $between = $changes($validated);

                return true;
            }));
        } else {
            $validated = null;

            try {
                $this->webGuard()->attemptWhen(self::credentials(), static function (IntegrationIdentity $user) use (&$validated): never {
                    $validated = $user;

                    throw new \RuntimeException('callback failed');
                });
            } catch (\RuntimeException $exception) { // @phpstan-ignore catch.neverThrown
                self::assertSame('callback failed', $exception->getMessage());
            }

            self::assertInstanceOf(IntegrationIdentity::class, $validated);

            $between = $changes($validated);
        }

        self::assertInstanceOf(SignedInSession::class, $between);
        self::assertSame('password_changed', DB::table('devices')->where('id', $first->device->getKey())->value('revoked_reason'));
        self::assertSame('password_changed', DB::table('devices')->where('id', $between->device->getKey())->value('revoked_reason'));

        $revoked = $this->recordedEvent(DeviceRevoked::class);

        self::assertSame(RevocationReason::PASSWORD_CHANGED, $revoked->reason);
        self::assertSame(IdentifierCoercion::stringify($between->device->getDeviceIdentifier()), $revoked->context->deviceId);
        self::assertSame(IdentifierCoercion::stringify($identity->getAuthIdentifier()), $revoked->context->identityId);
        self::assertSame(1, $this->recordedEvent(SignedOutEverywhere::class)->revoked);

        Auth::forgetGuards();

        $this->withHeaders(['Authorization' => 'Bearer ' . $between->tokens->accessToken])->getJson('/me')->assertUnauthorized();

        self::assertNull($this->freshGuard()->refresh($between->tokens->refreshToken));
    }

    /**
     * Rows of `[what runs inside another attempt's callback on the same
     * guard]`.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideNestedAttempts(): iterable
    {
        yield 'an attempt refused for the same user' => ['refused'];
        yield 'an attempt for no user' => ['nobody'];
        yield 'an attempt admitted for another user' => ['another'];
        yield 'an attempt admitted for the same user' => ['same'];
        yield 'the resolution of the session\'s user' => ['session'];
    }

    /**
     * An attempt made inside another attempt's callback on the same guard, or
     * the session's user resolved there, ends nothing of the outer attempt, so
     * the outer attempt's own rehash revokes nothing: the session it would have
     * ended still reaches the `auth` middleware and still refreshes.
     *
     * @param  string  $nested
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideNestedAttempts')]
    public function testAnAttemptInsideAnotherOnTheSameGuardLeavesItsRehashAlone(string $nested): void
    {
        $this->seedIdentity('grace@example.test');

        $identity = $this->seedIdentity();
        $session  = $this->signIn();

        DB::table('integration_identities')->where('id', $identity->getKey())->update(['password' => self::OUTDATED_HASH]);

        IntegrationIdentity::observe(RevokeDevicesOnPasswordChange::class);

        if ($nested === 'session') {
            $this->webGuard()->login($identity);

            Auth::forgetGuards();
        }

        self::assertTrue($this->webGuard()->attemptWhen(self::credentials(), function () use ($nested, $identity): bool {

            $guard = $this->webGuard();

            match ($nested) {
                'refused' => self::assertFalse($guard->attempt(['email' => 'ada@example.test', 'password' => 'wrong'])),
                'nobody'  => self::assertFalse($guard->attempt(['email' => 'nobody@example.test', 'password' => self::PASSWORD])),
                'another' => self::assertTrue($guard->attempt(self::credentials('grace@example.test'))),
                'same'    => self::assertTrue($guard->attempt(self::credentials())),
                default   => self::assertSame($identity->getKey(), $guard->user()?->getAuthIdentifier()),
            };

            return true;
        }));

        self::assertNotSame(self::OUTDATED_HASH, $identity->fresh()?->getAuthPassword());
        self::assertSame(0, DB::table('devices')->whereNotNull('revoked_at')->count());

        Auth::forgetGuards();

        $this->withHeaders(['Authorization' => 'Bearer ' . $session->tokens->accessToken])->getJson('/me')->assertOk();

        self::assertNotNull($this->freshGuard()->refresh($session->tokens->refreshToken));
    }

    /**
     * `logoutOtherDevices()` forces a rehash to sign the user's other sessions
     * out, so it ends the package sessions too.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testLogoutOtherDevicesRevokes(): void
    {
        $this->seedOutdatedHash();

        $guard = $this->webGuard();

        self::assertTrue($guard->attempt(self::credentials()));

        $guard->logoutOtherDevices(self::PASSWORD);

        self::assertSame('password_changed', DB::table('devices')->value('revoked_reason'));
    }

    /**
     * Rows of `[how the web attempt for the identity is left open, the instance
     * whose other devices are signed out, whether a listener of the forced save
     * makes another web attempt before the sign-out's event]`.
     *
     * @return iterable<string, array{0: string, 1: string, 2: bool}>
     */
    public static function provideOpenAttempts(): iterable
    {
        foreach (['after an attempt whose callback threw' => 'abandoned', 'from inside the attempt\'s own callback' => 'callback'] as $name => $attempt) {
            yield "{$name}, through the instance the attempt validated" => [$attempt, 'validated', false];
            yield "{$name}, through another instance" => [$attempt, 'another', false];
            yield "{$name}, through the instance the attempt validated, with a nested attempt" => [$attempt, 'validated', true];
        }
    }

    /**
     * `logoutOtherDevices()` saves a fresh hash of the same password, which an
     * open attempt for the user would take for its own rehash when it saves the
     * instance the attempt validated: whether that attempt threw after
     * validating the user and never ended, or the forced rehash runs inside its
     * callback, and even when another listener of the forced save makes an
     * attempt of the same guard before `OtherDeviceLogout`, the sign-out still
     * ends every package session, so its tokens are refused at the `auth`
     * middleware and its refresh token refreshes nothing.
     *
     * @param  string  $attempt
     * @param  string  $through
     * @param  bool  $nested
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideOpenAttempts')]
    public function testLogoutOtherDevicesWhileAnAttemptIsOpenRevokes(string $attempt, string $through, bool $nested): void
    {
        $identity = $this->seedIdentity();
        $session  = $this->signIn();

        IntegrationIdentity::observe(RevokeDevicesOnPasswordChange::class);

        if ($nested) {
            IntegrationIdentity::updated(function (): void {
                self::assertFalse($this->webGuard()->attempt(['email' => 'ada@example.test', 'password' => 'wrong']));
            });
        }

        $logout = static function (IntegrationIdentity $validated) use ($identity, $through): bool {

            $guard = Auth::guard('console');

            self::assertInstanceOf(SessionGuard::class, $guard);

            $guard->setUser($through === 'validated' ? $validated : $identity);
            $guard->logoutOtherDevices(self::PASSWORD);

            return true;
        };

        if ($attempt === 'callback') {
            self::assertTrue($this->webGuard()->attemptWhen(self::credentials(), $logout));
        } else {
            $validated = null;

            try {
                $this->webGuard()->attemptWhen(self::credentials(), static function (IntegrationIdentity $user) use (&$validated): never {
                    $validated = $user;

                    throw new \RuntimeException('callback failed');
                });
            } catch (\RuntimeException $exception) { // @phpstan-ignore catch.neverThrown
                self::assertSame('callback failed', $exception->getMessage());
            }

            self::assertInstanceOf(IntegrationIdentity::class, $validated);

            $logout($validated);
        }

        self::assertSame('password_changed', DB::table('devices')->value('revoked_reason'));

        Auth::forgetGuards();

        $this->withHeaders(['Authorization' => 'Bearer ' . $session->tokens->accessToken])->getJson('/me')->assertUnauthorized();

        self::assertNull($this->freshGuard()->refresh($session->tokens->refreshToken));
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

        $config = $app->make(ConfigRepository::class);

        $config->set('auth.defaults.guard', 'api');
        $config->set('auth.providers.users', ['driver' => 'eloquent', 'model' => IntegrationIdentity::class]);
        $config->set('auth.guards.web', ['driver' => 'session', 'provider' => 'users']);
        $config->set('auth.guards.console', ['driver' => 'session', 'provider' => 'users']);
        $config->set('auth.timebox_duration', 1);
        $config->set('session.driver', 'array');
    }

    /**
     * Seed an identity with a session and an outdated hash of its password, and
     * observe its model.
     *
     * @return \Tests\Integration\Fixtures\IntegrationIdentity
     *
     * @throws \Throwable
     */
    private function seedOutdatedHash(): IntegrationIdentity
    {
        $identity = $this->seedIdentity();

        $this->signIn();

        DB::table('integration_identities')->update(['password' => self::OUTDATED_HASH]);

        IntegrationIdentity::observe(RevokeDevicesOnPasswordChange::class);

        return $identity;
    }

    /**
     * Laravel's session guard over an Eloquent user provider of the identity
     * model.
     *
     * @return \Illuminate\Auth\SessionGuard
     */
    private function webGuard(): SessionGuard
    {
        $guard = Auth::guard('web');

        self::assertInstanceOf(SessionGuard::class, $guard);

        return $guard;
    }

    /**
     * Sign the seeded identity in, with its credentials unless others are
     * given.
     *
     * @param  ?array<string, string>  $credentials
     * @return \SineMacula\Laravel\Authentication\Sessions\SignedInSession
     *
     * @throws \Throwable
     */
    private function signIn(?array $credentials = null): SignedInSession
    {
        $session = $this->sessions()->signIn('password', $credentials ?? self::credentials())->session;

        self::assertNotNull($session);

        return $session;
    }
}
