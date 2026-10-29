<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Auth\AuthManager as IlluminateAuthManager;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Contracts\Auth\UserProvider;
use Orchestra\Testbench\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\AuthenticationServiceProvider;
use SineMacula\Laravel\Authentication\AuthManager;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenService;
use Tests\Unit\Stubs\StubAuthenticatableModel;

/**
 * Feature tests for the package AuthManager subclass.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuthManager::class)]
final class AuthManagerTest extends TestCase
{
    /**
     * The `auth` container binding resolves to the package `AuthManager`
     * subclass after the service provider boots.
     *
     * @return void
     */
    public function testAuthBindingResolvesToPackageAuthManager(): void
    {
        self::assertInstanceOf(AuthManager::class, app('auth'));
    }

    /**
     * The package `AuthManager` is a subclass of Laravel's framework
     * `AuthManager`.
     *
     * @return void
     */
    public function testAuthManagerExtendsLaravelAuthManager(): void
    {
        self::assertInstanceOf(IlluminateAuthManager::class, app('auth'));
    }

    /**
     * The package `AuthManager` exposes a concrete `jwt()` instance method that
     * resolves a guard-scoped `JwtTokenService`.
     *
     * @return void
     */
    public function testAuthManagerExposesJwtMethod(): void
    {
        $this->configureJwtGuard();

        /** @var \SineMacula\Laravel\Authentication\AuthManager $manager */
        $manager = app('auth');

        self::assertInstanceOf(JwtTokenService::class, $manager->jwt('test_jwt'));
    }

    /**
     * `sessions()` hands out the named JWT guard's own session service, or the
     * default guard's when no name is given.
     *
     * @return void
     */
    public function testSessionsReturnsTheJwtGuardsSessionService(): void
    {
        $this->configureJwtGuard();

        config()->set('auth.defaults.guard', 'test_jwt');

        /** @var \SineMacula\Laravel\Authentication\AuthManager $manager */
        $manager = app('auth');
        $guard   = $manager->guard('test_jwt');

        self::assertInstanceOf(JwtGuard::class, $guard);
        self::assertSame($guard->sessions(), $manager->sessions('test_jwt'));
        self::assertSame($guard->sessions(), $manager->sessions());
    }

    /**
     * A guard that is not a JWT guard has no session service, and asking for
     * one names the guard.
     *
     * @return void
     */
    public function testSessionsRejectsAGuardThatIsNotAJwtGuard(): void
    {
        $this->configureJwtGuard();

        config()->set('auth.defaults.guard', 'web');

        /** @var \SineMacula\Laravel\Authentication\AuthManager $manager */
        $manager = app('auth');

        try {
            $manager->sessions();
            self::fail('Expected the session guard to be refused.');
        } catch (\InvalidArgumentException $exception) {
            self::assertSame('Auth guard [web] is not a jwt guard, so it has no session service.', $exception->getMessage());
        }

        config()->set('auth.defaults.guard', 'test_jwt');

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Auth guard [web] is not a jwt guard, so it has no session service.');

        $manager->sessions('web');
    }

    /**
     * `inheritDriversFrom()` copies the donor's custom guard and provider
     * driver maps onto the receiver so guards and providers registered before
     * the package boot survive the container swap. Verified observably: after
     * inheritance, the receiver resolves the donor's `inherited-guard` and
     * `inherited-provider` driver names to the donor-supplied factory closures.
     *
     * @return void
     */
    public function testInheritDriversFromCopiesCustomCreatorMaps(): void
    {
        $donor = new IlluminateAuthManager(app());

        $guardInstance    = \Mockery::mock(Guard::class);
        $providerInstance = \Mockery::mock(UserProvider::class);

        $donor->extend('inherited-guard', fn (): Guard => $guardInstance);
        $donor->provider('inherited-provider', fn (): UserProvider => $providerInstance);

        $receiver = new AuthManager(app());
        $receiver->inheritDriversFrom($donor);

        config()->set('auth.guards.inherited-guard-instance', [
            'driver'   => 'inherited-guard',
            'provider' => 'inherited-provider-instance',
        ]);
        config()->set('auth.providers.inherited-provider-instance', [
            'driver' => 'inherited-provider',
        ]);

        self::assertSame($guardInstance, $receiver->guard('inherited-guard-instance'));
        self::assertSame($providerInstance, $receiver->createUserProvider('inherited-provider-instance'));
    }

    /**
     * `jwt()` throws when the default guard resolves to an empty string. Pins
     * the `$guardName === ''` early-throw in `AuthManager::jwt()`.
     *
     * @return void
     */
    public function testJwtThrowsWhenDefaultGuardIsEmpty(): void
    {
        config()->set('auth.defaults.guard', '');

        /** @var \SineMacula\Laravel\Authentication\AuthManager $manager */
        $manager = app('auth');

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('No default auth guard is configured.');

        $manager->jwt();
    }

    /**
     * `inheritDriversFrom()` does not throw and leaves the receiver driver-less
     * when the donor has no custom creators registered. Pins the empty-array
     * short-circuit in `inheritDriversFrom()`: a freshly bound provider that
     * points at an unregistered custom driver still raises
     * `InvalidArgumentException`, proving the empty donor did not silently leak
     * driver registrations.
     *
     * @return void
     */
    public function testInheritDriversFromIsNoOpWhenDonorIsEmpty(): void
    {
        $emptyDonor = new IlluminateAuthManager(app());

        $receiver = new AuthManager(app());
        $receiver->inheritDriversFrom($emptyDonor);

        config()->set('auth.providers.unknown-after-empty-inherit', [
            'driver' => 'no-such-driver',
        ]);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('no-such-driver');

        $receiver->createUserProvider('unknown-after-empty-inherit');
    }

    /**
     * Register the package service provider against the Testbench application
     * so the `auth` binding is overridden by the package subclass during boot.
     *
     * @param  mixed  $app
     * @return array<int, class-string<\Illuminate\Support\ServiceProvider>>
     */
    #[\Override]
    protected function getPackageProviders(mixed $app): array
    {
        return [AuthenticationServiceProvider::class];
    }

    /**
     * Configure the `test_jwt` guard over the stub identity model.
     *
     * @return void
     */
    private function configureJwtGuard(): void
    {
        config()->set('auth.providers.identities', [
            'driver' => 'model',
            'model'  => StubAuthenticatableModel::class,
        ]);
        config()->set('auth.guards.test_jwt', [
            'driver'   => 'jwt',
            'provider' => 'identities',
        ]);
        config()->set('authentication.jwt.keys', ['default' => 'test-secret-key-with-at-least-32-bytes!']);
        config()->set('authentication.jwt.active_kid', 'default');
        config()->set('authentication.jwt.algorithm', 'HS256');
    }
}
