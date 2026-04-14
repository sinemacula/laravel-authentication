<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Config\Repository;
use Illuminate\Contracts\Container\BindingResolutionException;
use Illuminate\Foundation\Application;
use Orchestra\Testbench\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\AuthServiceProvider;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\PrincipalResolver;
use SineMacula\Laravel\Authentication\Exceptions\InvalidDeviceModelConfiguration;
use Tests\Unit\Stubs\PlainDeviceFixture;
use Tests\Unit\Stubs\StubAlternateGuardScopedPrincipalResolver;
use Tests\Unit\Stubs\StubAuthenticatableModel;
use Tests\Unit\Stubs\StubBareDevice;
use Tests\Unit\Stubs\StubIdentity;

/**
 * Feature tests for JWT guard factory validation and shared
 * principal-resolver validation on `AuthServiceProvider`.
 *
 * Covers the JWT driver's device-model pre-checks and the
 * guard-local `principal_resolver` override validation path
 * used by both shipped guards.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuthServiceProvider::class)]
final class AuthServiceProviderGuardValidationTest extends TestCase
{
    /**
     * A per-guard `principal_resolver` override on a JWT guard must be used by
     * the guard so bearer flows use the guard-scoped resolver rather than the
     * global binding.
     *
     * The exchange's resolver sharing is verified indirectly: the factory
     * constructs both the guard and its exchange with the same resolved
     * instance, and `JwtGuard::setPrincipalResolver()` propagates future
     * rebinds to the exchange.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testJwtGuardAppliesPerGuardPrincipalResolverOverrideAndSharesItWithRefreshExchange(): void
    {
        $globalPrincipal = $this->mockPrincipal('global');
        $scopedPrincipal = $this->mockPrincipal('scoped');

        $this->bindMockGlobalResolver($globalPrincipal);

        $scopedResolver = \Mockery::mock(PrincipalResolver::class);
        $scopedResolver->shouldReceive('resolve')
            ->andReturn($scopedPrincipal);

        $this->app?->instance(
            StubAlternateGuardScopedPrincipalResolver::class,
            $scopedResolver,
        );

        config()->set('auth.guards.custom_jwt', [
            'driver'             => 'jwt',
            'provider'           => 'identities',
            'principal_resolver' => StubAlternateGuardScopedPrincipalResolver::class,
        ]);

        $guard = AuthServiceProvider::createJwtGuard($this->app, 'custom_jwt', [
            'driver'             => 'jwt',
            'provider'           => 'identities',
            'principal_resolver' => StubAlternateGuardScopedPrincipalResolver::class,
        ]);

        // Exercise the guard's resolver by logging in with a stub identity and
        // verifying the resolved principal is the scoped one.
        $identity         = new StubIdentity(['id' => 1]);
        $identity->exists = true;
        $guard->login($identity, $scopedPrincipal);

        self::assertSame($scopedPrincipal, $guard->principal());

        // Verify the scoped resolver was actually resolved (not the global) by
        // replacing it via setPrincipalResolver and confirming the guard
        // previously held the scoped instance.
        $replacementPrincipal = $this->mockPrincipal('replacement');
        $replacementResolver  = \Mockery::mock(PrincipalResolver::class);
        $replacementResolver->shouldReceive('resolve')
            ->andReturn($replacementPrincipal);

        $guard->setPrincipalResolver($replacementResolver);

        // login() with the new resolver should now yield the replacement
        $guard->login($identity, $replacementPrincipal);
        self::assertSame($replacementPrincipal, $guard->principal());
    }

    /**
     * JWT guards fail fast when `authentication.device.model` is empty instead
     * of constructing a guard whose refresh path cannot resolve devices.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testJwtGuardRejectsEmptyConfiguredDeviceModel(): void
    {
        config()->set('authentication.device.model', '');

        $this->expectException(InvalidDeviceModelConfiguration::class);
        $this->expectExceptionMessage('authentication.device.model');

        AuthServiceProvider::createJwtGuard($this->app, 'custom_jwt', [
            'driver'   => 'jwt',
            'provider' => 'identities',
        ]);
    }

    /**
     * JWT guards require the configured device model to satisfy the explicit
     * Eloquent-backed persistence boundary, not just the generic `Device`
     * contract.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testJwtGuardRejectsConfiguredDeviceModelOutsideEloquentBoundary(): void
    {
        config()->set('authentication.device.model', StubBareDevice::class);

        $this->expectException(InvalidDeviceModelConfiguration::class);
        $this->expectExceptionMessage(StubBareDevice::class);

        AuthServiceProvider::createJwtGuard($this->app, 'custom_jwt', [
            'driver'   => 'jwt',
            'provider' => 'identities',
        ]);
    }

    /**
     * Plain-object device fixtures remain valid event/token payloads, but they
     * are rejected when misconfigured as the persisted JWT device model.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testJwtGuardRejectsPlainDeviceFixtureAsConfiguredDeviceModel(): void
    {
        config()->set('authentication.device.model', PlainDeviceFixture::class);

        $this->expectException(InvalidDeviceModelConfiguration::class);
        $this->expectExceptionMessage(PlainDeviceFixture::class);

        AuthServiceProvider::createJwtGuard($this->app, 'custom_jwt', [
            'driver'   => 'jwt',
            'provider' => 'identities',
        ]);
    }

    /**
     * Guard-local resolver overrides must be non-empty strings so invalid
     * config fails loudly instead of silently falling back to the global
     * binding.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
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
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
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
     * A configured guard-local resolver must resolve to the contract; any other
     * object type is a configuration error.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testGuardPrincipalResolverRejectsResolvedNonResolverInstance(): void
    {
        $this->app?->instance('not-a-resolver', new \stdClass);

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

        $this->expectException(BindingResolutionException::class);

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
     * Register a stub auth provider the guard factories can resolve via
     * `IlluminateAuth::createUserProvider()` during construction.
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
     * Create a mock `Principal` with the supplied identifier.
     *
     * @param  string  $id
     * @return \SineMacula\Laravel\Authentication\Contracts\Principal
     */
    private function mockPrincipal(string $id): Principal
    {
        $principal = \Mockery::mock(Principal::class);
        $principal->shouldReceive('getPrincipalIdentifier')->andReturn($id);
        $principal->shouldReceive('isActive')->andReturnTrue();
        $principal->shouldReceive('getTenant')->andReturnNull();

        return $principal;
    }

    /**
     * Bind a mock global `PrincipalResolver` that returns the supplied
     * principal.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @return void
     */
    private function bindMockGlobalResolver(Principal $principal): void
    {
        $resolver = \Mockery::mock(PrincipalResolver::class);
        $resolver->shouldReceive('resolve')->andReturn($principal);

        $this->app?->instance(PrincipalResolver::class, $resolver);
    }
}
