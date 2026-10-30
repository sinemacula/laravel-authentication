<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Auth\RequestGuard;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\Auth as IlluminateAuth;
use Orchestra\Testbench\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\AuthenticationServiceProvider;
use SineMacula\Laravel\Authentication\AuthManager;
use Tests\Fixtures\Auth\LaravelAuthManagerSubclass;
use Tests\Fixtures\Providers\BindsLaravelAuthManagerSubclass;

/**
 * Feature tests for another package's subclass of Laravel's auth manager bound
 * to `auth` in a `register()`: the package owns the binding, so the subclass is
 * replaced by the package's manager, which takes over the drivers registered on
 * it but not the subclass's own behaviour.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuthenticationServiceProvider::class)]
#[CoversClass(AuthManager::class)]
final class AuthManagerReplacementTest extends TestCase
{
    /**
     * `auth` and the facade resolve the package's manager, which builds the
     * guard driver the subclass registered, and answers its own default guard
     * rather than the subclass's.
     *
     * @return void
     */
    public function testASubclassOfLaravelsManagerIsReplacedByThePackages(): void
    {
        $manager = app('auth');

        self::assertSame(AuthManager::class, $manager::class);
        self::assertSame($manager, IlluminateAuth::getFacadeRoot());
        self::assertInstanceOf(RequestGuard::class, $manager->guard('subclassed'));
        self::assertSame('subclassed', $manager->getDefaultDriver());
        self::assertNotSame(LaravelAuthManagerSubclass::DEFAULT_GUARD, $manager->getDefaultDriver());
    }

    /**
     * Register the other package's provider, then the package's.
     *
     * @param  mixed  $app
     * @return array<int, class-string<\Illuminate\Support\ServiceProvider>>
     */
    #[\Override]
    protected function getPackageProviders(mixed $app): array
    {
        return [BindsLaravelAuthManagerSubclass::class, AuthenticationServiceProvider::class];
    }

    /**
     * Configure a guard of the subclass's driver as the default.
     *
     * @param  mixed  $app
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        assert($app instanceof Application);

        $config = $app->make(ConfigRepository::class);

        $config->set('auth.defaults.guard', 'subclassed');
        $config->set('auth.guards.subclassed', ['driver' => 'subclassed']);
    }
}
