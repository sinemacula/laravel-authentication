<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Config\Repository;
use Illuminate\Contracts\Container\BindingResolutionException;
use Illuminate\Foundation\Application;
use Orchestra\Testbench\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\AuthenticationServiceProvider;
use SineMacula\Laravel\Authentication\Contracts\CanBeActive;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\PrincipalResolver;
use SineMacula\Laravel\Authentication\Exceptions\InvalidSessionModelConfigurationException;
use Tests\Integration\Fixtures\SeparateConnectionSession;
use Tests\Unit\Stubs\PlainSessionFixture;
use Tests\Unit\Stubs\StubAlternateGuardScopedPrincipalResolver;
use Tests\Unit\Stubs\StubAuthenticatableModel;
use Tests\Unit\Stubs\StubBareSession;
use Tests\Unit\Stubs\StubIdentity;

/**
 * Feature tests for JWT guard factory validation and shared principal-resolver
 * validation on `AuthenticationServiceProvider`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuthenticationServiceProvider::class)]
final class AuthenticationServiceProviderGuardValidationTest extends TestCase
{
    /**
     * A JWT guard uses its own `principal_resolver` over the global binding.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testJwtGuardUsesItsOwnPrincipalResolver(): void
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

        $guard = AuthenticationServiceProvider::createJwtGuard($this->application(), 'custom_jwt', [
            'driver'             => 'jwt',
            'provider'           => 'identities',
            'principal_resolver' => StubAlternateGuardScopedPrincipalResolver::class,
        ]);

        $identity         = new StubIdentity(['id' => 1]);
        $identity->exists = true;
        $guard->login($identity, $scopedPrincipal);

        self::assertSame($scopedPrincipal, $guard->principal());

        $replacementPrincipal = $this->mockPrincipal('replacement');
        $replacementResolver  = \Mockery::mock(PrincipalResolver::class);
        $replacementResolver->shouldReceive('resolve')
            ->andReturn($replacementPrincipal);

        $guard->setPrincipalResolver($replacementResolver);

        $guard->login($identity, $replacementPrincipal);
        self::assertSame($replacementPrincipal, $guard->principal());
    }

    /**
     * JWT guards fail fast when `authentication.session.model` is empty.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testJwtGuardRejectsEmptyConfiguredSessionModel(): void
    {
        config()->set('authentication.session.model', '');

        $this->expectException(InvalidSessionModelConfigurationException::class);
        $this->expectExceptionMessage('authentication.session.model');

        AuthenticationServiceProvider::createJwtGuard($this->application(), 'custom_jwt', [
            'driver'   => 'jwt',
            'provider' => 'identities',
        ]);
    }

    /**
     * JWT guards require the configured session model to be Eloquent-backed.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testJwtGuardRejectsConfiguredSessionModelOutsideEloquentBoundary(): void
    {
        config()->set('authentication.session.model', StubBareSession::class);

        $this->expectException(InvalidSessionModelConfigurationException::class);
        $this->expectExceptionMessage(StubBareSession::class);

        AuthenticationServiceProvider::createJwtGuard($this->application(), 'custom_jwt', [
            'driver'   => 'jwt',
            'provider' => 'identities',
        ]);
    }

    /**
     * A plain-object session is rejected as the JWT session model.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testJwtGuardRejectsPlainSessionFixtureAsConfiguredSessionModel(): void
    {
        config()->set('authentication.session.model', PlainSessionFixture::class);

        $this->expectException(InvalidSessionModelConfigurationException::class);
        $this->expectExceptionMessage(PlainSessionFixture::class);

        AuthenticationServiceProvider::createJwtGuard($this->application(), 'custom_jwt', [
            'driver'   => 'jwt',
            'provider' => 'identities',
        ]);
    }

    /**
     * JWT guards fail fast when the session model names a connection other than
     * the storage connection.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testJwtGuardRejectsASessionModelOffTheStorageConnection(): void
    {
        config()->set('auth.guards.custom_jwt', ['driver' => 'jwt', 'provider' => 'identities']);
        config()->set('authentication.session.model', SeparateConnectionSession::class);

        try {
            AuthenticationServiceProvider::createJwtGuard($this->application(), 'custom_jwt', ['driver' => 'jwt', 'provider' => 'identities']);

            self::fail('Expected the session model to be refused.');
        } catch (InvalidSessionModelConfigurationException $exception) {
            $expected = 'the session model is on [session_store], the storage connection is [' . config()->string('database.default') . '].';

            self::assertStringContainsString($expected, $exception->getMessage());
        }

        config()->set('authentication.storage.connection', SeparateConnectionSession::CONNECTION);

        $guard = AuthenticationServiceProvider::createJwtGuard($this->application(), 'custom_jwt', ['driver' => 'jwt', 'provider' => 'identities']);

        self::assertSame('custom_jwt', $guard->getName());
    }

    /**
     * Guard-local resolver overrides must be non-empty strings.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testGuardPrincipalResolverRejectsEmptyStringOverride(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('principal_resolver must be a non-empty string');

        AuthenticationServiceProvider::createJwtGuard($this->application(), 'tenant_api', [
            'driver'             => 'jwt',
            'provider'           => 'identities',
            'principal_resolver' => '',
        ]);
    }

    /**
     * Guard-local resolver overrides must be strings.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testGuardPrincipalResolverRejectsNonStringOverride(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('principal_resolver must be a non-empty string');

        AuthenticationServiceProvider::createJwtGuard($this->application(), 'tenant_api', [
            'driver'             => 'jwt',
            'provider'           => 'identities',
            'principal_resolver' => ['not-a-string'],
        ]);
    }

    /**
     * A configured guard-local resolver must resolve to the contract.
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

        AuthenticationServiceProvider::createJwtGuard($this->application(), 'tenant_api', [
            'driver'             => 'jwt',
            'provider'           => 'identities',
            'principal_resolver' => 'not-a-resolver',
        ]);
    }

    /**
     * A missing binding for a guard-local resolver fails guard construction.
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

        AuthenticationServiceProvider::createJwtGuard($this->application(), 'unresolvable_jwt', [
            'driver'             => 'jwt',
            'provider'           => 'identities',
            'principal_resolver' => 'missing-resolver-binding',
        ]);
    }

    /**
     * Register the package service provider.
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
     * Register a stub auth provider the guard factories can resolve.
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

        $config->set('authentication.jwt.keys', ['default' => 'guard-config-test-secret-with-at-least-32!']);
        $config->set('authentication.jwt.active_kid', 'default');
        $config->set('authentication.jwt.algorithm', 'HS256');
        $config->set('authentication.jwt.issuer', 'https://issuer.example.test');
        $config->set('authentication.jwt.audience', 'https://api.example.test');
        $config->set('authentication.jwt.access_ttl_minutes', 15);
        $config->set('authentication.jwt.refresh_idle_ttl_minutes', 60 * 24 * 30);

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
        $principal = \Mockery::mock(Principal::class, CanBeActive::class);
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

    /**
     * The application the test runs.
     *
     * @return \Illuminate\Foundation\Application
     */
    private function application(): Application
    {
        self::assertNotNull($this->app);

        return $this->app;
    }
}
