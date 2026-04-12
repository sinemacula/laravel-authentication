<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Config\Repository;
use Illuminate\Foundation\Application;
use Orchestra\Testbench\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\AuthServiceProvider;
use SineMacula\Laravel\Authentication\Guards\BasicGuard;
use Tests\Unit\Stubs\StubAuthenticatableModel;

/**
 * Feature tests for the basic-guard config override layering on
 * `AuthServiceProvider`'s guard factory.
 *
 * Covers `auth.guards.<name>.identifier_field` for the basic driver - lookup
 * column layered over the package-wide
 * `authentication.credentials.identifier_field` default.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Ltd
 *
 * @internal
 */
#[CoversClass(AuthServiceProvider::class)]
final class AuthServiceProviderGuardConfigTest extends TestCase
{
    /**
     * A per-guard `identifier_field` override on the basic guard's config
     * block wins over the package-wide default, so consumers can register
     * multiple basic guards that look up credentials by different columns (e.g.
     * `email` for web users and `key_id` for tenant API keys).
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testBasicGuardAppliesPerGuardIdentifierFieldOverride(): void
    {
        config()->set('authentication.credentials.identifier_field', 'email');

        $guard = AuthServiceProvider::createBasicGuard($this->app, 'tenant_api', [
            'driver'           => 'basic',
            'provider'         => 'identities',
            'identifier_field' => 'key_id',
        ]);

        self::assertSame('key_id', $this->readGuardProperty($guard, 'identifierField'));
    }

    /**
     * With no per-guard `identifier_field` override, `createBasicGuard` falls
     * back to the package-wide `authentication.credentials.identifier_field`
     * default - backwards-compatible with single-guard consumers.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testBasicGuardFallsBackToPackageIdentifierField(): void
    {
        config()->set('authentication.credentials.identifier_field', 'email');

        $guard = AuthServiceProvider::createBasicGuard($this->app, 'cli', [
            'driver'   => 'basic',
            'provider' => 'identities',
        ]);

        self::assertSame('email', $this->readGuardProperty($guard, 'identifierField'));
    }

    /**
     * Register the package service provider against the Testbench application
     * so the container has the package config bindings.
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
     * Register a stub auth provider the basic-guard factory can resolve via
     * `IlluminateAuth::createUserProvider()` during the identifier-field
     * override tests.
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
        $config = $app->make(Repository::class);

        $config->set('auth.providers.identities', [
            'driver' => 'model',
            'model'  => StubAuthenticatableModel::class,
        ]);
    }

    /**
     * Read a private / readonly property off a `BasicGuard` instance via
     * reflection. Used by the identifier-field override tests to inspect the
     * resolved lookup column directly.
     *
     * @param  \SineMacula\Laravel\Authentication\Guards\BasicGuard  $guard
     * @param  string  $property
     * @return mixed
     *
     * @throws \ReflectionException
     *
     * @SuppressWarnings("php:S3011")
     */
    private function readGuardProperty(BasicGuard $guard, string $property): mixed
    {
        $reflectionProperty = (new \ReflectionClass($guard))->getProperty($property);

        return $reflectionProperty->getValue($guard);
    }
}
