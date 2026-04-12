<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Config\Repository;
use Illuminate\Foundation\Application;
use Orchestra\Testbench\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\AuthServiceProvider;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\PrincipalResolver;
use SineMacula\Laravel\Authentication\Guards\BasicGuard;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenExchange;
use Tests\Unit\Stubs\StubAuthenticatableModel;

/**
 * Feature tests for guard-local config override layering on
 * `AuthServiceProvider`'s guard factories.
 *
 * Covers the basic driver's `identifier_field` override plus the shared
 * `principal_resolver` selection path used by both shipped guards.
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
     * A per-guard `principal_resolver` override on the basic guard's config
     * block wins over the app-wide `PrincipalResolver::class` binding.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testBasicGuardAppliesPerGuardPrincipalResolverOverride(): void
    {
        $global = new AuthServiceProviderGuardConfigGlobalResolver;

        $this->app->instance(PrincipalResolver::class, $global);

        $guard = AuthServiceProvider::createBasicGuard($this->app, 'tenant_api', [
            'driver'             => 'basic',
            'provider'           => 'identities',
            'principal_resolver' => AuthServiceProviderGuardConfigBasicResolver::class,
        ]);

        $resolver = $this->readObjectProperty($guard, 'resolver');

        self::assertInstanceOf(AuthServiceProviderGuardConfigBasicResolver::class, $resolver);
        self::assertNotSame($global, $resolver);
    }

    /**
     * With no per-guard `principal_resolver` override, the basic guard falls
     * back to the app-wide `PrincipalResolver::class` binding.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testBasicGuardFallsBackToContainerPrincipalResolverBinding(): void
    {
        $global = new AuthServiceProviderGuardConfigGlobalResolver;

        $this->app->instance(PrincipalResolver::class, $global);

        $guard = AuthServiceProvider::createBasicGuard($this->app, 'cli', [
            'driver'   => 'basic',
            'provider' => 'identities',
        ]);

        self::assertSame($global, $this->readObjectProperty($guard, 'resolver'));
    }

    /**
     * A per-guard `principal_resolver` override on a JWT guard must be used by
     * both the guard and its refresh exchange so bearer and refresh flows stay
     * aligned.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testJwtGuardAppliesPerGuardPrincipalResolverOverrideAndSharesItWithRefreshExchange(): void
    {
        $global = new AuthServiceProviderGuardConfigGlobalResolver;

        $this->app->instance(PrincipalResolver::class, $global);

        config()->set('auth.guards.custom_jwt', [
            'driver'             => 'jwt',
            'provider'           => 'identities',
            'principal_resolver' => AuthServiceProviderGuardConfigJwtResolver::class,
        ]);

        $guard = AuthServiceProvider::createJwtGuard($this->app, 'custom_jwt', [
            'driver'             => 'jwt',
            'provider'           => 'identities',
            'principal_resolver' => AuthServiceProviderGuardConfigJwtResolver::class,
        ]);

        $resolver = $this->readObjectProperty($guard, 'resolver');

        self::assertInstanceOf(AuthServiceProviderGuardConfigJwtResolver::class, $resolver);
        self::assertNotSame($global, $resolver);

        $exchange = $this->readObjectProperty($guard, 'exchange');

        self::assertInstanceOf(RefreshTokenExchange::class, $exchange);
        self::assertSame($resolver, $this->readObjectProperty($exchange, 'resolver'));
    }

    /**
     * Guard-local resolver overrides must be non-empty strings so invalid
     * config fails loudly instead of silently falling back to the global
     * binding.
     *
     * @return void
     */
    public function testGuardPrincipalResolverRejectsEmptyStringOverride(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('principal_resolver must be a non-empty string');

        AuthServiceProvider::createBasicGuard($this->app, 'tenant_api', [
            'driver'             => 'basic',
            'provider'           => 'identities',
            'principal_resolver' => '',
        ]);
    }

    /**
     * Guard-local resolver overrides must be strings, not arbitrary config
     * payloads.
     *
     * @return void
     */
    public function testGuardPrincipalResolverRejectsNonStringOverride(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('principal_resolver must be a non-empty string');

        AuthServiceProvider::createBasicGuard($this->app, 'tenant_api', [
            'driver'             => 'basic',
            'provider'           => 'identities',
            'principal_resolver' => ['not-a-string'],
        ]);
    }

    /**
     * A configured guard-local resolver must resolve to the contract; any
     * other object type is a configuration error.
     *
     * @return void
     */
    public function testGuardPrincipalResolverRejectsResolvedNonResolverInstance(): void
    {
        $this->app->instance('not-a-resolver', new \stdClass);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('resolved to [stdClass]');

        AuthServiceProvider::createBasicGuard($this->app, 'tenant_api', [
            'driver'             => 'basic',
            'provider'           => 'identities',
            'principal_resolver' => 'not-a-resolver',
        ]);
    }

    /**
     * Missing container bindings for guard-local resolvers bubble up during
     * guard construction rather than silently falling back.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testGuardPrincipalResolverPropagatesUnresolvableContainerBinding(): void
    {
        config()->set('auth.guards.unresolvable_jwt', [
            'driver'             => 'jwt',
            'provider'           => 'identities',
            'principal_resolver' => 'missing-resolver-binding',
        ]);

        $this->expectException(\Illuminate\Contracts\Container\BindingResolutionException::class);

        AuthServiceProvider::createJwtGuard($this->app, 'unresolvable_jwt', [
            'driver'             => 'jwt',
            'provider'           => 'identities',
            'principal_resolver' => 'missing-resolver-binding',
        ]);
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

        $config->set('authentication.jwt.secret', 'guard-config-test-secret-with-at-least-32!');
        $config->set('authentication.jwt.algorithm', 'HS256');
        $config->set('authentication.jwt.access_ttl_minutes', 15);
        $config->set('authentication.jwt.refresh_ttl_minutes', 60 * 24 * 30);

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
     * @param  object  $target
     * @param  string  $property
     * @return mixed
     *
     * @throws \ReflectionException
     *
     * @SuppressWarnings("php:S3011")
     */
    private function readObjectProperty(object $target, string $property): mixed
    {
        $reflectionProperty = (new \ReflectionClass($target))->getProperty($property);

        return $reflectionProperty->getValue($target);
    }

    /**
     * Read a property off a `BasicGuard` instance via reflection.
     *
     * @param  \SineMacula\Laravel\Authentication\Guards\BasicGuard  $guard
     * @param  string  $property
     * @return mixed
     *
     * @throws \ReflectionException
     */
    private function readGuardProperty(BasicGuard $guard, string $property): mixed
    {
        return $this->readObjectProperty($guard, $property);
    }
}

/**
 * Stub basic-guard resolver for config override tests.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Ltd
 *
 * @internal
 */
final class AuthServiceProviderGuardConfigBasicResolver implements PrincipalResolver
{
    /**
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  mixed  $hint
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Principal
     */
    #[\Override]
    public function resolve(Identity $identity, mixed $hint = null): ?Principal
    {
        unset($identity, $hint);

        return null;
    }
}

/**
 * Stub JWT-guard resolver for config override tests.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Ltd
 *
 * @internal
 */
final class AuthServiceProviderGuardConfigJwtResolver implements PrincipalResolver
{
    /**
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  mixed  $hint
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Principal
     */
    #[\Override]
    public function resolve(Identity $identity, mixed $hint = null): ?Principal
    {
        unset($identity, $hint);

        return null;
    }
}

/**
 * Stub global resolver for config fallback tests.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Ltd
 *
 * @internal
 */
final class AuthServiceProviderGuardConfigGlobalResolver implements PrincipalResolver
{
    /**
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  mixed  $hint
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Principal
     */
    #[\Override]
    public function resolve(Identity $identity, mixed $hint = null): ?Principal
    {
        unset($identity, $hint);

        return null;
    }
}
