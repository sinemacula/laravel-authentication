<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Auth\AuthManager as IlluminateAuthManager;
use Orchestra\Testbench\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\AuthManager;
use SineMacula\Laravel\Authentication\AuthServiceProvider;

/**
 * Unit tests for the package AuthManager subclass.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
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
        $reflection = new \ReflectionClass(AuthManager::class);

        self::assertTrue(
            $reflection->isSubclassOf(IlluminateAuthManager::class),
            'Package AuthManager must extend Illuminate\Auth\AuthManager.',
        );
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

        $guardInstance    = \Mockery::mock(\Illuminate\Contracts\Auth\Guard::class);
        $providerInstance = \Mockery::mock(\Illuminate\Contracts\Auth\UserProvider::class);

        $donor->extend('inherited-guard', fn (): \Illuminate\Contracts\Auth\Guard => $guardInstance);
        $donor->provider('inherited-provider', fn (): \Illuminate\Contracts\Auth\UserProvider => $providerInstance);

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
     * `inheritDriversFrom()` does not throw and leaves the receiver
     * driver-less when the donor has no custom creators registered. Pins the
     * empty-array short-circuit in `inheritDriversFrom()`: a freshly bound
     * provider that points at an unregistered custom driver still raises
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
    protected function getPackageProviders(mixed $app): array
    {
        return [AuthServiceProvider::class];
    }
}
