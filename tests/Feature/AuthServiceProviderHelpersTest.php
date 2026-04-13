<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use Illuminate\Support\ServiceProvider;
use Orchestra\Testbench\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\AuthServiceProvider;

/**
 * Feature tests for the small provider-only behaviours on
 * `AuthServiceProvider`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuthServiceProvider::class)]
final class AuthServiceProviderHelpersTest extends TestCase
{
    /**
     * `registerPublishing()` short-circuits when the application is not
     * running in the console: invoking the protected method directly with
     * `runningInConsole()` returning false must NOT register a publish group.
     *
     * @return void
     *
     * @throws \ReflectionException
     */
    public function testRegisterPublishingShortCircuitsWhenNotRunningInConsole(): void
    {
        $app = \Mockery::mock(Application::class)->makePartial();
        $app->shouldReceive('runningInConsole')->andReturnFalse();

        $provider = new AuthServiceProvider($app);

        $previousGroups = ServiceProvider::publishableGroups();

        $reflection = new \ReflectionClass(AuthServiceProvider::class);
        $reflection->getMethod('registerPublishing')->invoke($provider);

        self::assertSame($previousGroups, ServiceProvider::publishableGroups());
    }

    /**
     * The `auth` binding is a singleton: resolving it twice returns the same
     * object instance so guards are not reconstructed mid-request.
     *
     * @return void
     */
    public function testAuthBindingIsSingleton(): void
    {
        $first  = app('auth');
        $second = app('auth');

        self::assertSame($first, $second);
    }

    /**
     * `mergeConfigFrom()` seeds the package defaults without clobbering values
     * the consumer has already set. The test confirms the consumer's secret
     * from `defineEnvironment` survives the provider's `mergeConfigFrom` call,
     * while a key the consumer did NOT set (`device.table`) takes the package
     * default.
     *
     * @return void
     */
    public function testMergeConfigDoesNotOverwriteConsumerValues(): void
    {
        self::assertSame(
            'test-secret-key-with-at-least-32-bytes!',
            config('authentication.jwt.secret'),
        );

        self::assertSame('devices', config('authentication.device.table'));
    }

    /**
     * `composer.json` `require` block contains zero `sinemacula/laravel-*` IAM
     * sibling packages. Standalone installability guard.
     *
     * @return void
     */
    public function testComposerJsonContainsNoIamSiblingDependencies(): void
    {
        $composerJson = json_decode(
            (string) file_get_contents(__DIR__ . '/../../composer.json'),
            true,
        );

        self::assertIsArray($composerJson);

        $require = $composerJson['require'] ?? [];

        $iamSiblings = array_filter(
            array_keys($require),
            static fn (string $name): bool => str_starts_with($name, 'sinemacula/laravel-')
                && $name !== 'sinemacula/laravel-authentication',
        );

        self::assertSame(
            [],
            $iamSiblings,
            'require must not list sinemacula/laravel-* IAM siblings.',
        );
    }

    /**
     * Register the package service provider against the Testbench application.
     *
     * @param  mixed  $app
     * @return array<int, class-string<\Illuminate\Support\ServiceProvider>>
     */
    #[\Override]
    protected function getPackageProviders(mixed $app): array
    {
        return [AuthServiceProvider::class];
    }

    /**
     * Define the Testbench environment with package config so the merge-config
     * test can verify consumer values survive.
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

        /** @var \Illuminate\Config\Repository $config */
        $config = $app->make(ConfigRepository::class);

        $config->set('authentication.jwt.secret', 'test-secret-key-with-at-least-32-bytes!');
    }
}
