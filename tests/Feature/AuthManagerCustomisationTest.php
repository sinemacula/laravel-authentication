<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\Auth as IlluminateAuth;
use Orchestra\Testbench\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\AuthenticationServiceProvider;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use Tests\Fixtures\Auth\CustomisedAuthManager;
use Tests\Fixtures\Providers\BindsCustomisedAuthManager;
use Tests\Unit\Stubs\StubAuthenticatableModel;

/**
 * Feature tests for an application's own auth manager, a subclass of the
 * package's bound to `auth` in a `register()`: the package keeps it, with its
 * own behaviour, and registers its drivers on it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuthenticationServiceProvider::class)]
final class AuthManagerCustomisationTest extends TestCase
{
    /**
     * The application's manager is the one `auth` and the facade resolve, with
     * its own method, and the package's guard driver is registered on it.
     *
     * @return void
     */
    public function testASubclassOfThePackagesManagerIsKept(): void
    {
        $manager = app('auth');

        self::assertInstanceOf(CustomisedAuthManager::class, $manager);
        self::assertSame(CustomisedAuthManager::ANSWER, $manager->customised());
        self::assertSame($manager, IlluminateAuth::getFacadeRoot());
        self::assertInstanceOf(JwtGuard::class, $manager->guard('api'));
    }

    /**
     * Register the package's provider, then the application's.
     *
     * @param  mixed  $app
     * @return array<int, class-string<\Illuminate\Support\ServiceProvider>>
     */
    #[\Override]
    protected function getPackageProviders(mixed $app): array
    {
        return [AuthenticationServiceProvider::class, BindsCustomisedAuthManager::class];
    }

    /**
     * Configure a JWT guard.
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

        $config->set('authentication.jwt.keys', ['default' => 'test-secret-key-with-at-least-32-bytes!']);
        $config->set('authentication.jwt.active_kid', 'default');
        $config->set('authentication.jwt.algorithm', 'HS256');
        $config->set('auth.providers.identities', ['driver' => 'model', 'model' => StubAuthenticatableModel::class]);
        $config->set('auth.guards.api', ['driver' => 'jwt', 'provider' => 'identities']);
    }
}
