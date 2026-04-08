<?php

declare(strict_types = 1);

namespace Tests\Unit;

use Illuminate\Auth\AuthManager as IlluminateAuthManager;
use Orchestra\Testbench\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\AuthManager;
use SineMacula\Laravel\Authentication\AuthServiceProvider;
use SineMacula\Laravel\Authentication\Contracts\Factory;

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
     * The `auth` container binding resolves to the package
     * `AuthManager` subclass after the service provider boots.
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
     * The package `AuthManager` implements the package `Factory`
     * marker contract so consumers may type-hint the contract in
     * tests and IDE-friendly bindings.
     *
     * @return void
     */
    public function testAuthManagerImplementsPackageFactoryContract(): void
    {
        $reflection = new \ReflectionClass(AuthManager::class);

        self::assertTrue(
            $reflection->implementsInterface(Factory::class),
            'Package AuthManager must implement the package Factory contract.',
        );
    }

    /**
     * Register the package service provider against the Testbench
     * application so the `auth` binding is overridden by the package
     * subclass during boot.
     *
     * @param  mixed  $app
     * @return array<int, class-string<\Illuminate\Support\ServiceProvider>>
     */
    protected function getPackageProviders(mixed $app): array
    {
        return [AuthServiceProvider::class];
    }
}
