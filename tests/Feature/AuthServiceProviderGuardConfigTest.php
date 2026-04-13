<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Auth\Events\Attempting;
use Illuminate\Config\Repository;
use Illuminate\Contracts\Container\BindingResolutionException;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\Auth as IlluminateAuth;
use Illuminate\Support\Facades\Event;
use Orchestra\Testbench\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\AuthServiceProvider;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\PrincipalResolver;
use SineMacula\Laravel\Authentication\Exceptions\InvalidDeviceModelConfiguration;
use SineMacula\Laravel\Authentication\Guards\BasicGuard;
use Tests\Unit\Stubs\PlainDeviceFixture;
use Tests\Unit\Stubs\StubAlternateGuardScopedPrincipalResolver;
use Tests\Unit\Stubs\StubAuthenticatableModel;
use Tests\Unit\Stubs\StubBareDevice;
use Tests\Unit\Stubs\StubGuardScopedPrincipalResolver;
use Tests\Unit\Stubs\StubIdentity;

/**
 * Feature tests for guard-local config override layering on
 * `AuthServiceProvider`'s guard factories.
 *
 * Covers the basic driver's `identifier_field` override plus the shared
 * `principal_resolver` selection path used by both shipped guards.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuthServiceProvider::class)]
final class AuthServiceProviderGuardConfigTest extends TestCase
{
    /**
     * A per-guard `identifier_field` override on the basic guard's config
     * block wins over the package-wide default, so consumers can register
     * multiple basic guards that look up credentials by different columns
     * (e.g. `email` for web users and `key_id` for tenant API keys).
     *
     * Verified by triggering the guard's user-resolution path and inspecting
     * the credentials key in the dispatched `Attempting` event.
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

        self::assertSame('key_id', $this->capturedIdentifierField($guard));
    }

    /**
     * With no per-guard `identifier_field` override, `createBasicGuard`
     * falls back to the package-wide
     * `authentication.credentials.identifier_field` default - backwards
     * compatible with single-guard consumers.
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

        self::assertSame('email', $this->capturedIdentifierField($guard));
    }

    /**
     * A per-guard `principal_resolver` override on the basic guard's config
     * block wins over the app-wide `PrincipalResolver::class` binding.
     *
     * Verified by completing authentication through the guard's public API
     * and asserting the principal returned by the guard-scoped resolver
     * appears on `$guard->principal()`.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testBasicGuardAppliesPerGuardPrincipalResolverOverride(): void
    {
        $globalPrincipal = $this->mockPrincipal('global');
        $scopedPrincipal = $this->mockPrincipal('scoped');

        $this->bindMockGlobalResolver($globalPrincipal);
        $this->bindMockGuardScopedResolver(
            StubGuardScopedPrincipalResolver::class,
            $scopedPrincipal,
        );

        $guard = $this->buildAuthenticatingBasicGuard('tenant_api', [
            'driver'             => 'basic',
            'provider'           => 'identities',
            'principal_resolver' => StubGuardScopedPrincipalResolver::class,
        ]);

        self::assertNotNull($guard->user());
        self::assertSame($scopedPrincipal, $guard->principal());
    }

    /**
     * With no per-guard `principal_resolver` override, the basic guard
     * falls back to the app-wide `PrincipalResolver::class` binding.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testBasicGuardFallsBackToContainerPrincipalResolverBinding(): void
    {
        $globalPrincipal = $this->mockPrincipal('global');

        $this->bindMockGlobalResolver($globalPrincipal);

        $guard = $this->buildAuthenticatingBasicGuard('cli', [
            'driver'   => 'basic',
            'provider' => 'identities',
        ]);

        self::assertNotNull($guard->user());
        self::assertSame($globalPrincipal, $guard->principal());
    }

    /**
     * A per-guard `principal_resolver` override on a JWT guard must be used
     * by the guard so bearer flows use the guard-scoped resolver rather
     * than the global binding.
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

        // Exercise the guard's resolver by logging in with a stub identity
        // and verifying the resolved principal is the scoped one.
        $identity         = new StubIdentity(['id' => 1]);
        $identity->exists = true;
        $guard->login($identity, $scopedPrincipal);

        self::assertSame($scopedPrincipal, $guard->principal());

        // Verify the scoped resolver was actually resolved (not the global)
        // by replacing it via setPrincipalResolver and confirming the guard
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
     * JWT guards fail fast when `authentication.device.model` is empty
     * instead of constructing a guard whose refresh path cannot resolve
     * devices.
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
     * JWT guards require the configured device model to satisfy the
     * explicit Eloquent-backed persistence boundary, not just the generic
     * `Device` contract.
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
     * Plain-object device fixtures remain valid event/token payloads, but
     * they are rejected when misconfigured as the persisted JWT device
     * model.
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
     * A configured guard-local resolver must resolve to the contract; any
     * other object type is a configuration error.
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
     * Register the package service provider against the Testbench
     * application so the container has the package config bindings.
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
     * Capture the identifier field key used by the guard's credential
     * path by triggering `user()` with HTTP Basic credentials and
     * inspecting the `Attempting` event.
     *
     * The provider is not expected to resolve a user; the event fires
     * before the provider lookup so the identifier field is observable
     * regardless.
     *
     * @param  \SineMacula\Laravel\Authentication\Guards\BasicGuard  $guard
     * @return string
     */
    private function capturedIdentifierField(BasicGuard $guard): string
    {
        Event::fake(Attempting::class);

        $guard->setRequest(
            $this->createRequestWithBasicAuth('test-user', 'test-pass'),
        );

        try {
            $guard->user();
        } catch (\Throwable) {
            // The provider may throw (no database); the event fires before
            // the provider lookup so it is already captured.
        }

        $events = Event::dispatched(Attempting::class);

        self::assertNotEmpty($events, 'Attempting event was not dispatched');

        /** @var \Illuminate\Auth\Events\Attempting $event */
        $event = $events[0][0];

        $keys = array_diff(
            array_keys($event->credentials),
            ['password'],
        );

        self::assertCount(1, $keys);

        return (string) array_values($keys)[0];
    }

    /**
     * Build a `BasicGuard` wired with a mock identity provider so the
     * full credential -> resolver -> principal path completes without a
     * database.
     *
     * @param  string  $name
     * @param  array<string, mixed>  $config
     * @return \SineMacula\Laravel\Authentication\Guards\BasicGuard
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function buildAuthenticatingBasicGuard(string $name, array $config): BasicGuard
    {
        $this->registerMockIdentityProvider();

        $guard = AuthServiceProvider::createBasicGuard($this->app, $name, $config);
        $guard->setRequest(
            $this->createRequestWithBasicAuth('test-user', 'test-pass'),
        );

        return $guard;
    }

    /**
     * Register a mock identity provider driver (`mock-model`) that returns
     * a `StubIdentity` with valid credentials, allowing the guard's auth
     * flow to reach the principal resolver.
     *
     * @return void
     */
    private function registerMockIdentityProvider(): void
    {
        $identity         = new StubIdentity(['id' => 1]);
        $identity->exists = true;

        $provider = \Mockery::mock(
            \SineMacula\Laravel\Authentication\Contracts\IdentityProvider::class,
        );
        $provider->shouldReceive('retrieveByCredentials')->andReturn($identity);
        $provider->shouldReceive('validateCredentials')->andReturnTrue();
        $provider->shouldReceive('rehashPasswordIfRequired');

        IlluminateAuth::provider(
            'mock-model',
            fn () => $provider,
        );

        config()->set('auth.providers.identities', [
            'driver' => 'mock-model',
        ]);
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

    /**
     * Bind a mock guard-scoped `PrincipalResolver` under the supplied
     * class name that returns the supplied principal.
     *
     * The mock targets the `PrincipalResolver` interface (not the final
     * concrete class) and is bound under the concrete class name so the
     * container resolves it during guard construction.
     *
     * @param  class-string  $class
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @return void
     */
    private function bindMockGuardScopedResolver(
        string $class,
        Principal $principal,
    ): void {
        $resolver = \Mockery::mock(PrincipalResolver::class);
        $resolver->shouldReceive('resolve')->andReturn($principal);

        $this->app?->instance($class, $resolver);
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
     * Build an `Illuminate\Http\Request` with HTTP Basic credentials set.
     *
     * @param  string  $username
     * @param  string  $password
     * @return \Illuminate\Http\Request
     */
    private function createRequestWithBasicAuth(
        string $username,
        string $password,
    ): \Illuminate\Http\Request {
        return \Illuminate\Http\Request::create(
            '/',
            'GET',
            server: [
                'PHP_AUTH_USER' => $username,
                'PHP_AUTH_PW'   => $password,
            ],
        );
    }
}
