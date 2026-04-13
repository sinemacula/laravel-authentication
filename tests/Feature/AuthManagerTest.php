<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Auth\AuthManager as IlluminateAuthManager;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Contracts\Auth\UserProvider;
use Orchestra\Testbench\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\AuthManager;
use SineMacula\Laravel\Authentication\AuthServiceProvider;
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
     * The package `AuthManager` exposes a concrete `jwt()` instance method
     * that resolves a guard-scoped `JwtTokenService`.
     *
     * @return void
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAuthManagerExposesJwtMethod(): void
    {
        config()->set('auth.providers.identities', [
            'driver' => 'model',
            'model'  => StubAuthenticatableModel::class,
        ]);
        config()->set('auth.guards.test_jwt', [
            'driver'   => 'jwt',
            'provider' => 'identities',
        ]);
        config()->set('authentication.jwt.secret', 'test-secret-key-with-at-least-32-bytes!');

        /** @var \SineMacula\Laravel\Authentication\AuthManager $manager */
        $manager = app('auth');

        self::assertInstanceOf(JwtTokenService::class, $manager->jwt('test_jwt'));
    }

    /**
     * `inheritDriversFrom()` copies the donor's custom guard and provider
     * driver maps onto the receiver so guards and providers registered before
     * the package boot survive the container swap. Verified observably: after
     * inheritance, the receiver resolves the donor's `inherited-guard` and
     * `inherited-provider` driver names to the donor-supplied factory
     * closures.
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
     * `inheritDriversFrom()` does not throw and leaves the receiver driver-less
     * when the donor has no custom creators registered. Pins the empty-array
     * short-circuit in `inheritDriversFrom()`: a freshly bound provider that
     * points at an unregistered custom driver still raises
     * `InvalidArgumentException`, proving the empty donor did not silently
     * leak driver registrations.
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
        return [AuthServiceProvider::class];
    }
}
