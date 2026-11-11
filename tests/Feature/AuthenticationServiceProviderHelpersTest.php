<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use Illuminate\Support\ServiceProvider;
use Orchestra\Testbench\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\AuthenticationServiceProvider;

/**
 * Feature tests for the small provider-only behaviours on
 * `AuthenticationServiceProvider`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuthenticationServiceProvider::class)]
final class AuthenticationServiceProviderHelpersTest extends TestCase
{
    /**
     * `registerPublishing()` registers nothing outside the console.
     *
     * @return void
     *
     * @throws \ReflectionException
     */
    public function testRegisterPublishingShortCircuitsWhenNotRunningInConsole(): void
    {
        $app = \Mockery::mock(Application::class)->makePartial();
        $app->shouldReceive('runningInConsole')->andReturnFalse();

        $provider = new AuthenticationServiceProvider($app);

        [$publishes, $groups] = [ServiceProvider::$publishes, ServiceProvider::$publishGroups];

        ServiceProvider::$publishes     = [];
        ServiceProvider::$publishGroups = [];

        try {
            (new \ReflectionMethod(AuthenticationServiceProvider::class, 'registerPublishing'))->invoke($provider);

            self::assertSame([], ServiceProvider::$publishes);
            self::assertSame([], ServiceProvider::$publishGroups);
        } finally {
            [ServiceProvider::$publishes, ServiceProvider::$publishGroups] = [$publishes, $groups];
        }
    }

    /**
     * The `auth` binding is a singleton.
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
     * `mergeConfigFrom()` seeds the package defaults without overwriting values
     * the consumer has already set.
     *
     * @return void
     */
    public function testMergeConfigDoesNotOverwriteConsumerValues(): void
    {
        self::assertSame(
            ['default' => 'test-secret-key-with-at-least-32-bytes!'],
            config('authentication.jwt.keys'),
        );

        self::assertSame('authentication_sessions', config('authentication.session.table'));
    }

    /**
     * `composer.json` requires no `sinemacula/laravel-*` sibling package.
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

        self::assertIsArray($require);

        $iamSiblings = array_filter(
            array_keys($require),
            static fn (int|string $name): bool => is_string($name)
                && str_starts_with($name, 'sinemacula/laravel-')
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
        return [AuthenticationServiceProvider::class];
    }

    /**
     * Set consumer config values the merge must keep.
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

        $config->set('authentication.jwt.keys', ['default' => 'test-secret-key-with-at-least-32-bytes!']);
        $config->set('authentication.jwt.active_kid', 'default');
    }
}
