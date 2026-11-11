<?php

declare(strict_types = 1);

namespace Tests\Feature\Listeners;

use Illuminate\Auth\EloquentUserProvider;
use Illuminate\Auth\SessionGuard;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Container\Container;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Foundation\Application;
use Illuminate\Hashing\BcryptHasher;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversTrait;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Events\Enums\RevocationReason;
use SineMacula\Laravel\Authentication\Events\SessionRevoked;
use SineMacula\Laravel\Authentication\Events\SignedOutEverywhere;
use SineMacula\Laravel\Authentication\Listeners\Concerns\RevokesOnceCommitted;
use SineMacula\Laravel\Authentication\Listeners\RevokeSessionsOnPasswordChange;
use SineMacula\Laravel\Authentication\Sessions\Methods\Rehashing;
use SineMacula\Laravel\Authentication\Sessions\SignedInSession;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use Tests\Concerns\InteractsWithSessions;
use Tests\Integration\Fixtures\AttributeObservedIdentity;
use Tests\Integration\Fixtures\EloquentIdentityProvider;
use Tests\Integration\Fixtures\IntegrationIdentity;
use Tests\TestCase;
use Tests\Unit\Stubs\StubModel;

/**
 * Feature tests of the optional `RevokeSessionsOnPasswordChange` listener.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RevokeSessionsOnPasswordChange::class)]
#[CoversTrait(RevokesOnceCommitted::class)]
final class RevokeSessionsOnPasswordChangeTest extends TestCase
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

        IntegrationIdentity::observe(RevokeSessionsOnPasswordChange::class);

        $identity->forceFill(['email' => 'ada.lovelace@example.test'])->save();

        self::assertSame(0, DB::table('authentication_sessions')->whereNotNull('revoked_at')->count());

        $identity->forceFill(['password' => app(Hasher::class)->make('a new password')])->save();

        self::assertSame('password_changed', DB::table('authentication_sessions')->value('revoked_reason'));
    }

    /**
     * A save rehashing the sign-in password during the package's automatic
     * rehash is not a change; once it is over it is.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheAutomaticRehashRevokesNothing(): void
    {
        $identity = $this->seedOutdatedHash()->refresh();

        app(Rehashing::class)->during($identity, self::PASSWORD, static function () use ($identity): void {
            $identity->forceFill(['password' => app(Hasher::class)->make(self::PASSWORD)])->save();
        });

        self::assertSame(0, DB::table('authentication_sessions')->whereNotNull('revoked_at')->count());

        $identity->forceFill(['password' => app(Hasher::class)->make(self::PASSWORD)])->save();

        self::assertSame('password_changed', DB::table('authentication_sessions')->value('revoked_reason'));
    }

    /**
     * `logoutOtherDevices()` called from a listener of the automatic rehash's
     * save still ends every package session.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testLogoutOtherDevicesInsideTheAutomaticRehashRevokes(): void
    {
        $identity = $this->seedIdentity();
        $session  = $this->signIn();

        DB::table('integration_identities')->update(['password' => self::OUTDATED_HASH]);

        IntegrationIdentity::observe(RevokeSessionsOnPasswordChange::class);

        $listening = true;

        IntegrationIdentity::updated(static function (IntegrationIdentity $saved) use (&$listening): void {

            if (!$listening) {
                return;
            }

            $listening = false;

            $guard = Auth::guard('console');

            self::assertInstanceOf(SessionGuard::class, $guard);

            $guard->setUser($saved);
            $guard->logoutOtherDevices(self::PASSWORD);
        });

        $identity->refresh();

        app(Rehashing::class)->during($identity, self::PASSWORD, static function () use ($identity): void {
            $identity->forceFill(['password' => app(Hasher::class)->make(self::PASSWORD)])->save();
        });

        self::assertSame('password_changed', DB::table('authentication_sessions')->value('revoked_reason'));

        Auth::forgetGuards();

        $this->withHeaders(['Authorization' => 'Bearer ' . $session->tokens->accessToken->reveal()])->getJson('/me')->assertUnauthorized();

        self::assertNull(
            self::sessionsOf($this->freshGuard())->refresh(self::bodyToken($session->tokens), self::requestClient())->session,
        );
    }

    /**
     * A new password saved during the package's automatic rehash is a change.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testANewPasswordSavedDuringTheAutomaticRehashRevokes(): void
    {
        $identity = $this->seedOutdatedHash()->refresh();

        app(Rehashing::class)->during($identity, self::PASSWORD, static function () use ($identity): void {
            IntegrationIdentity::query()->whereKey($identity->getKey())->firstOrFail()->forceFill(['password' => app(Hasher::class)->make('a new password')])->save();
        });

        self::assertSame('password_changed', DB::table('authentication_sessions')->value('revoked_reason'));
    }

    /**
     * A change back to the sign-in password inside an evented provider's rehash
     * ends the session started between the changes.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAChangeBackInsideTheAutomaticRehashRevokesTheSessionStartedBetween(): void
    {
        $identity = $this->seedOutdatedHash();
        $first    = DB::table('authentication_sessions')->value('id');

        $this->useEventedProvider();

        $listening = true;
        $between   = null;

        IntegrationIdentity::updated(function (IntegrationIdentity $saved) use (&$listening, &$between): void {

            if (!$listening) {
                return;
            }

            $listening = false;

            IntegrationIdentity::query()->whereKey($saved->getKey())->firstOrFail()->forceFill(['password' => app(Hasher::class)->make('a new password')])->save();

            $between = $this->signIn(['email' => 'ada@example.test', 'password' => 'a new password']);

            $this->recordEvents([SessionRevoked::class, SignedOutEverywhere::class]);

            $saved->forceFill(['password' => app(Hasher::class)->make(self::PASSWORD)])->save();
        });

        $outer = $this->signIn();

        self::assertFalse($listening);
        self::assertInstanceOf(SignedInSession::class, $between);
        self::assertTrue(app(Hasher::class)->check(self::PASSWORD, (string) $identity->fresh()?->getAuthPassword()));
        self::assertSame('password_changed', DB::table('authentication_sessions')->where('id', $first)->value('revoked_reason'));
        self::assertSame('password_changed', DB::table('authentication_sessions')->where('id', $between->record->getKey())->value('revoked_reason'));

        $revoked = $this->recordedEvent(SessionRevoked::class);

        self::assertSame(RevocationReason::PASSWORD_CHANGED, $revoked->reason);
        self::assertSame(IdentifierCoercion::stringify($between->record->getSessionIdentifier()), $revoked->context->sessionId);
        self::assertSame(IdentifierCoercion::stringify($identity->getAuthIdentifier()), $revoked->context->identityId);
        self::assertSame(1, $this->recordedEvent(SignedOutEverywhere::class)->revoked);

        Auth::forgetGuards();

        $this->withHeaders(['Authorization' => 'Bearer ' . $between->tokens->accessToken->reveal()])->getJson('/me')->assertUnauthorized();

        self::assertNull(
            self::sessionsOf($this->freshGuard())->refresh(self::bodyToken($between->tokens), self::requestClient())->session,
        );

        Auth::forgetGuards();

        $this->withHeaders(['Authorization' => 'Bearer ' . $outer->tokens->accessToken->reveal()])->getJson('/me')->assertOk();
    }

    /**
     * Laravel's rehash on `attempt()` revokes nothing, while the same save
     * after the attempt does.
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
        self::assertSame(0, DB::table('authentication_sessions')->whereNotNull('revoked_at')->count());

        $identity->forceFill(['password' => app(Hasher::class)->make(self::PASSWORD)])->save();

        self::assertSame('password_changed', DB::table('authentication_sessions')->value('revoked_reason'));
    }

    /**
     * The listener reads the rehash mark of the serving application, not the
     * one that built it, as under Octane.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheMarkIsTheServingApplicationsWhateverBuiltTheListener(): void
    {
        $identity = $this->seedOutdatedHash();
        $booted   = $this->app;

        self::assertInstanceOf(Application::class, $booted);

        $booted->forgetScopedInstances();

        Container::setInstance(clone $booted);

        try {
            self::assertTrue($this->webGuard()->attempt(self::credentials()));
        } finally {
            Container::setInstance($booted);
        }

        self::assertNotSame(self::OUTDATED_HASH, $identity->fresh()?->getAuthPassword());
        self::assertSame(0, DB::table('authentication_sessions')->whereNotNull('revoked_at')->count());
    }

    /**
     * A rehash on `attempt()` by a provider with its own hasher revokes
     * nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARehashByAProviderWithItsOwnHasherRevokesNothing(): void
    {
        $identity = $this->seedIdentity();

        $this->signIn();

        IntegrationIdentity::observe(RevokeSessionsOnPasswordChange::class);

        Auth::provider('costlier', static fn (): EloquentUserProvider => new EloquentUserProvider(new BcryptHasher(['rounds' => 5]), IntegrationIdentity::class));

        config()->set('auth.providers.costlier', ['driver' => 'costlier']);
        config()->set('auth.guards.costlier', ['driver' => 'session', 'provider' => 'costlier']);

        $hash  = $identity->getAuthPassword();
        $guard = Auth::guard('costlier');

        self::assertInstanceOf(SessionGuard::class, $guard);
        self::assertTrue($guard->attempt(self::credentials()));
        self::assertNotSame($hash, $identity->fresh()?->getAuthPassword());
        self::assertSame(0, DB::table('authentication_sessions')->whereNotNull('revoked_at')->count());
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
        self::assertSame(0, DB::table('authentication_sessions')->whereNotNull('revoked_at')->count());
    }

    /**
     * Laravel's rehash revokes nothing for an observer registered through
     * `#[ObservedBy]`, while a later change does.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testLaravelsRehashRevokesNothingForAnObserverRegisteredByAttribute(): void
    {
        $this->seedIdentity();

        config()->set('auth.providers.identities.model', AttributeObservedIdentity::class);
        config()->set('auth.providers.users.model', AttributeObservedIdentity::class);

        Auth::forgetGuards();

        $this->signIn();

        DB::table('integration_identities')->update(['password' => self::OUTDATED_HASH]);

        AttributeObservedIdentity::flushEventListeners();
        AttributeObservedIdentity::clearBootedModels();

        $observed = 'eloquent.updated: ' . AttributeObservedIdentity::class;

        self::assertFalse(Event::hasListeners($observed));
        self::assertTrue($this->webGuard()->attempt(self::credentials()));
        self::assertTrue(Event::hasListeners($observed));

        $identity = AttributeObservedIdentity::query()->firstOrFail();

        self::assertNotSame(self::OUTDATED_HASH, $identity->getAuthPassword());
        self::assertSame(0, DB::table('authentication_sessions')->whereNotNull('revoked_at')->count());

        $identity->forceFill(['password' => app(Hasher::class)->make('a new password')])->save();

        self::assertSame('password_changed', DB::table('authentication_sessions')->value('revoked_reason'));
    }

    /**
     * A change after `validate()`, a failed attempt or a refused one revokes.
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

        self::assertSame('password_changed', DB::table('authentication_sessions')->value('revoked_reason'));
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
     * An `attemptWhen()` callback that saves a new password revokes, whether it
     * admits the attempt or not.
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
        self::assertSame('password_changed', DB::table('authentication_sessions')->value('revoked_reason'));
    }

    /**
     * A password saved after an attempt that threw revokes, a fresh hash of the
     * same password included.
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

        self::assertSame('password_changed', DB::table('authentication_sessions')->value('revoked_reason'));
    }

    /**
     * After an attempt that threw, a quiet change followed by a change back to
     * its password revokes.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAChangeBackAfterAQuietChangeRevokes(): void
    {
        $this->seedIdentity();

        $first = $this->signIn();

        IntegrationIdentity::observe(RevokeSessionsOnPasswordChange::class);

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

        $validated->forceFill(['password' => app(Hasher::class)->make('a new password')])->saveQuietly();

        self::assertNull(DB::table('authentication_sessions')->where('id', $first->record->getKey())->value('revoked_at'));

        $validated->forceFill(['password' => app(Hasher::class)->make(self::PASSWORD)])->save();

        self::assertSame('password_changed', DB::table('authentication_sessions')->where('id', $first->record->getKey())->value('revoked_reason'));
    }

    /**
     * Rows of `[whether the changes run inside the attempt's callback, the
     * instance the change back is saved through]`.
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
     * A change back to an open attempt's password through any instance ends the
     * session started between the changes.
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

        IntegrationIdentity::observe(RevokeSessionsOnPasswordChange::class);

        $changes = function (IntegrationIdentity $validated) use ($identity, $stale, $back): SignedInSession {

            $identity->forceFill(['password' => app(Hasher::class)->make('a new password')])->save();

            $between = $this->signIn(['email' => 'ada@example.test', 'password' => 'a new password']);

            $this->recordEvents([SessionRevoked::class, SignedOutEverywhere::class]);

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
        self::assertSame('password_changed', DB::table('authentication_sessions')->where('id', $first->record->getKey())->value('revoked_reason'));
        self::assertSame('password_changed', DB::table('authentication_sessions')->where('id', $between->record->getKey())->value('revoked_reason'));

        $revoked = $this->recordedEvent(SessionRevoked::class);

        self::assertSame(RevocationReason::PASSWORD_CHANGED, $revoked->reason);
        self::assertSame(IdentifierCoercion::stringify($between->record->getSessionIdentifier()), $revoked->context->sessionId);
        self::assertSame(IdentifierCoercion::stringify($identity->getAuthIdentifier()), $revoked->context->identityId);
        self::assertSame(1, $this->recordedEvent(SignedOutEverywhere::class)->revoked);

        Auth::forgetGuards();

        $this->withHeaders(['Authorization' => 'Bearer ' . $between->tokens->accessToken->reveal()])->getJson('/me')->assertUnauthorized();

        self::assertNull(
            self::sessionsOf($this->freshGuard())->refresh(self::bodyToken($between->tokens), self::requestClient())->session,
        );
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
     * An attempt nested in another's callback on the same guard leaves the
     * outer attempt's rehash revoking nothing.
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

        IntegrationIdentity::observe(RevokeSessionsOnPasswordChange::class);

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
        self::assertSame(0, DB::table('authentication_sessions')->whereNotNull('revoked_at')->count());

        Auth::forgetGuards();

        $this->withHeaders(['Authorization' => 'Bearer ' . $session->tokens->accessToken->reveal()])->getJson('/me')->assertOk();

        self::assertNotNull(
            self::sessionsOf($this->freshGuard())->refresh(self::bodyToken($session->tokens), self::requestClient())->session,
        );
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

        self::assertSame('password_changed', DB::table('authentication_sessions')->value('revoked_reason'));
    }

    /**
     * Rows of `[how the web attempt is left open, the instance signed out from,
     * what another listener does first]`.
     *
     * @return iterable<string, array{0: string, 1: string, 2: string}>
     */
    public static function provideOpenAttempts(): iterable
    {
        foreach (['after an attempt whose callback threw' => 'abandoned', 'from inside the attempt\'s own callback' => 'callback'] as $name => $attempt) {
            yield "{$name}, through another instance" => [$attempt, 'another', 'nothing'];
            yield "{$name}, through the instance the attempt validated" => [$attempt, 'validated', 'nothing'];
            yield "{$name}, through the validated instance, with a nested attempt" => [$attempt, 'validated', 'attempt'];
            yield "{$name}, through the validated instance, binding it to a guard" => [$attempt, 'validated', 'bind'];
            yield "{$name}, through the validated instance, with a change rolled back" => [$attempt, 'validated', 'rollback'];
            yield "{$name}, through the validated instance, binding it and attempting again" => [$attempt, 'validated', 'bind, attempt'];
            yield "{$name}, through the validated instance, with a change rolled back and another attempt" => [$attempt, 'validated', 'rollback, attempt'];
            yield "{$name}, through the validated instance, with the package's own rehash" => [$attempt, 'validated', 'rehash'];
        }
    }

    /**
     * `logoutOtherDevices()` while an attempt is open still ends every package
     * session, whatever another listener does first.
     *
     * @param  string  $attempt
     * @param  string  $through
     * @param  string  $listener
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideOpenAttempts')]
    public function testLogoutOtherDevicesWhileAnAttemptIsOpenRevokes(string $attempt, string $through, string $listener): void
    {
        $identity = $this->seedIdentity();
        $session  = $this->signIn();

        DB::table('integration_identities')->update(['password' => self::OUTDATED_HASH]);

        IntegrationIdentity::observe(RevokeSessionsOnPasswordChange::class);

        $listening = true;

        IntegrationIdentity::updated(function (IntegrationIdentity $saved) use ($listener, &$listening): void {

            if (!$listening) {
                return;
            }

            $listening = false;

            array_map(fn (string $step) => $this->interfere($step, $saved), explode(', ', $listener));
        });

        $logout = static function (IntegrationIdentity $validated) use ($identity, $through): bool {

            $guard = Auth::guard('console');

            self::assertInstanceOf(SessionGuard::class, $guard);

            $guard->setUser($through === 'validated' ? $validated : $identity->refresh());
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

        self::assertSame('password_changed', DB::table('authentication_sessions')->value('revoked_reason'));

        Auth::forgetGuards();

        $this->withHeaders(['Authorization' => 'Bearer ' . $session->tokens->accessToken->reveal()])->getJson('/me')->assertUnauthorized();

        self::assertNull(
            self::sessionsOf($this->freshGuard())->refresh(self::bodyToken($session->tokens), self::requestClient())->session,
        );
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

        IntegrationIdentity::observe(RevokeSessionsOnPasswordChange::class);

        try {
            DB::transaction(static function () use ($identity): never {
                $identity->forceFill(['password' => app(Hasher::class)->make('a new password')])->save();

                throw new \RuntimeException('roll back');
            });
        } catch (\RuntimeException) {
            self::assertSame(0, DB::table('authentication_sessions')->whereNotNull('revoked_at')->count());
        }

        DB::transaction(static function () use ($identity): void {

            $identity->forceFill(['password' => app(Hasher::class)->make('another password')])->save();

            self::assertSame(0, DB::table('authentication_sessions')->whereNotNull('revoked_at')->count());
        });

        self::assertSame(1, DB::table('authentication_sessions')->whereNotNull('revoked_at')->count());
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

        app(RevokeSessionsOnPasswordChange::class)->updated($model);

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
     * Do one thing a listener of a forced save may do before the sign-out's
     * event.
     *
     * @param  string  $step
     * @param  \Tests\Integration\Fixtures\IntegrationIdentity  $saved
     * @return void
     *
     * @throws \Throwable
     */
    private function interfere(string $step, IntegrationIdentity $saved): void
    {
        match ($step) {
            'attempt'  => self::assertFalse($this->webGuard()->attempt(['email' => 'ada@example.test', 'password' => 'wrong'])),
            'bind'     => $this->webGuard()->setUser($saved),
            'rollback' => self::rollBack(static function () use ($saved): void {
                IntegrationIdentity::query()->whereKey($saved->getKey())->firstOrFail()->forceFill(['password' => app(Hasher::class)->make('rolled back')])->save();
            }),
            'rehash' => app(Rehashing::class)->during($saved, self::PASSWORD, static function () use ($saved): void {
                IntegrationIdentity::query()->whereKey($saved->getKey())->firstOrFail()->forceFill(['password' => app(Hasher::class)->make(self::PASSWORD)])->save();
            }),
            default => null,
        };
    }

    /**
     * Run the callback in a transaction and roll it back.
     *
     * @param  \Closure(): void  $callback
     * @return void
     *
     * @throws \Throwable
     */
    private static function rollBack(\Closure $callback): void
    {
        DB::beginTransaction();

        try {
            $callback();
        } finally {
            DB::rollBack();
        }
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

        IntegrationIdentity::observe(RevokeSessionsOnPasswordChange::class);

        return $identity;
    }

    /**
     * Have the jwt guards sign in through Laravel's Eloquent user provider,
     * whose rehash saves the model with its events, in place of the package's.
     *
     * @return void
     */
    private function useEventedProvider(): void
    {
        Auth::provider('evented', static fn (Application $app): EloquentIdentityProvider => new EloquentIdentityProvider($app->make(Hasher::class), IntegrationIdentity::class));

        config()->set('auth.providers.identities.driver', 'evented');

        Auth::forgetGuards();
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
        $session = $this->sessions()->signIn('password', $credentials ?? self::credentials(), self::requestContext())->session;

        self::assertNotNull($session);

        return $session;
    }
}
