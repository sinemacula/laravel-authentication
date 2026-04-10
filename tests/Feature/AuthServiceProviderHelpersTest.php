<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Support\ServiceProvider;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use Orchestra\Testbench\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\AuthServiceProvider;

/**
 * Unit tests for the private static helpers on `AuthServiceProvider`
 * (`registerPublishing`, `resolveJwtInteger`, `resolveOptionalLogger`).
 *
 * Split out of `AuthServiceProviderTest` so each class stays focused on a
 * single behavioural slice.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 *
 * @internal
 */
#[CoversClass(AuthServiceProvider::class)]
final class AuthServiceProviderHelpersTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    /**
     * `registerPublishing()` short-circuits when the application is not
     * running in the console: invoking the protected method directly with
     * `runningInConsole()` returning false must NOT register a publish group.
     *
     * @return void
     */
    public function testRegisterPublishingShortCircuitsWhenNotRunningInConsole(): void
    {
        $app = \Mockery::mock(\Illuminate\Foundation\Application::class)->makePartial();
        $app->shouldReceive('runningInConsole')->andReturnFalse();

        $provider = new AuthServiceProvider($app);

        $previousGroups = ServiceProvider::publishableGroups();

        $reflection = new \ReflectionClass(AuthServiceProvider::class);
        $reflection->getMethod('registerPublishing')->invoke($provider);

        self::assertSame($previousGroups, ServiceProvider::publishableGroups());
    }

    /**
     * `resolveJwtInteger()` falls back to the package config when the
     * per-guard override is supplied as a non-int (e.g. a string from an env
     * var that the operator forgot to cast). Pins the
     * `is_int($guardJwtConfig[$key])` arm of the type guard.
     *
     * @return void
     */
    public function testResolveJwtIntegerFallsBackWhenGuardOverrideIsNonInteger(): void
    {
        config()->set('authentication.jwt.access_ttl_minutes', 25);

        $reflection = new \ReflectionClass(AuthServiceProvider::class);
        $method     = $reflection->getMethod('resolveJwtInteger');

        /** @var int $resolved */
        $resolved = $method->invoke(
            null,
            app(ConfigRepository::class),
            ['access_ttl_minutes' => 'not-an-integer'],
            'access_ttl_minutes',
            5,
        );

        self::assertSame(25, $resolved);
    }

    /**
     * `resolveJwtInteger()` honours an integer per-guard override.
     *
     * @return void
     */
    public function testResolveJwtIntegerHonoursIntegerOverride(): void
    {
        $reflection = new \ReflectionClass(AuthServiceProvider::class);
        $method     = $reflection->getMethod('resolveJwtInteger');

        /** @var int $resolved */
        $resolved = $method->invoke(
            null,
            app(ConfigRepository::class),
            ['access_ttl_minutes' => 99],
            'access_ttl_minutes',
            5,
        );

        self::assertSame(99, $resolved);
    }

    /**
     * `resolveOptionalLogger()` returns `null` when the container has no PSR-3
     * logger bound, so the JwtTokenService falls back to its `NullLogger`
     * default.
     *
     * @return void
     */
    public function testResolveOptionalLoggerReturnsNullWhenNotBound(): void
    {
        $app = \Mockery::mock(\Illuminate\Foundation\Application::class);
        $app->shouldReceive('bound')
            ->once()
            ->with(\Psr\Log\LoggerInterface::class)
            ->andReturnFalse();
        $app->shouldNotReceive('make');

        $reflection = new \ReflectionClass(AuthServiceProvider::class);

        /** @var ?\Psr\Log\LoggerInterface $logger */
        $logger = $reflection->getMethod('resolveOptionalLogger')->invoke(null, $app);

        self::assertNull($logger);
    }

    /**
     * `resolveOptionalLogger()` returns the bound logger when the container
     * has one. Mirrors the success branch alongside the `null` short-circuit
     * above.
     *
     * @return void
     */
    public function testResolveOptionalLoggerReturnsBoundLogger(): void
    {
        $logger = \Mockery::mock(\Psr\Log\LoggerInterface::class);

        $app = \Mockery::mock(\Illuminate\Foundation\Application::class);
        $app->shouldReceive('bound')
            ->once()
            ->with(\Psr\Log\LoggerInterface::class)
            ->andReturnTrue();
        $app->shouldReceive('make')
            ->once()
            ->with(\Psr\Log\LoggerInterface::class)
            ->andReturn($logger);

        $reflection = new \ReflectionClass(AuthServiceProvider::class);

        /** @var ?\Psr\Log\LoggerInterface $resolved */
        $resolved = $reflection->getMethod('resolveOptionalLogger')->invoke(null, $app);

        self::assertSame($logger, $resolved);
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
     */
    protected function defineEnvironment(mixed $app): void
    {
        assert($app instanceof \Illuminate\Foundation\Application);

        /** @var \Illuminate\Config\Repository $config */
        $config = $app->make(ConfigRepository::class);

        $config->set('authentication.jwt.secret', 'test-secret-key-with-at-least-32-bytes!');
    }
}
