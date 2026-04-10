<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Orchestra\Testbench\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\AuthServiceProvider;
use SineMacula\Laravel\Authentication\Guards\BasicGuard;
use SineMacula\Laravel\Authentication\Jwt\JwtKeyring;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenService;

/**
 * Unit tests for the per-guard config override layering on
 * `AuthServiceProvider`'s guard factories.
 *
 * Covers two override surfaces:
 *
 * - `auth.guards.<name>.jwt.*` for the jwt driver - secret, keys,
 *   audience, issuer, TTLs, etc. layered over the package-wide
 *   `authentication.jwt.*` defaults.
 * - `auth.guards.<name>.identifier_field` for the basic driver -
 *   lookup column layered over the package-wide
 *   `authentication.credentials.identifier_field` default.
 *
 * Together these let consumers register multiple guards with distinct trust
 * boundaries in a single `config/auth.php`.
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
final class AuthServiceProviderGuardConfigTest extends TestCase
{
    /** @var string Shared package-default secret used across the override test cases. */
    private const string PACKAGE_SECRET = 'package-default-secret-with-32-bytes!';

    /** @var string Kid used by the current-generation key in kid-mode override tests. */
    private const string KID_NEW = '2026-04';

    /** @var string Kid used by the previous-generation key in kid-mode override tests. */
    private const string KID_OLD = '2026-03';

    /**
     * A per-guard `jwt` override block with a distinct `audience` produces a
     * `JwtTokenService` whose audience differs from the package default, so
     * two guards can verify different audiences without sharing a global
     * configuration.
     *
     * @return void
     */
    public function testAppliesGuardAudienceOverride(): void
    {
        config()->set('authentication.jwt.secret', self::PACKAGE_SECRET);
        config()->set('authentication.jwt.audience', 'package-default-audience');

        $service = $this->invokeBuildJwtTokenService(['audience' => 'staff-api']);

        self::assertSame('staff-api', $this->readServiceProperty($service, 'audience'));
    }

    /**
     * A per-guard `jwt.secret` override wins over the package default - the
     * resulting keyring's active key holds the guard-specific signing
     * material, not the package secret.
     *
     * @return void
     */
    public function testAppliesGuardSecretOverride(): void
    {
        config()->set('authentication.jwt.secret', self::PACKAGE_SECRET);

        $guardSecret = 'guard-only-secret-with-at-least-32-bytes!';

        $service = $this->invokeBuildJwtTokenService(['secret' => $guardSecret]);

        $keyring = $this->readServiceProperty($service, 'keyring');

        self::assertInstanceOf(JwtKeyring::class, $keyring);
        self::assertSame($guardSecret, $keyring->activeKey()->getKeyMaterial());
    }

    /**
     * A per-guard `jwt.keys` + `active_kid` override activates kid mode for
     * that guard even when the package default is single-secret mode, so one
     * guard can rotate keys independently of the package-wide configuration.
     *
     * @return void
     */
    public function testAppliesGuardKidKeysOverride(): void
    {
        config()->set('authentication.jwt.secret', self::PACKAGE_SECRET);

        $service = $this->invokeBuildJwtTokenService([
            'keys' => [
                self::KID_NEW => 'kid-new-secret-material-32-bytes!!',
                self::KID_OLD => 'kid-old-secret-material-32-bytes!!',
            ],
            'active_kid' => self::KID_NEW,
        ]);

        $keyring = $this->readServiceProperty($service, 'keyring');

        self::assertInstanceOf(JwtKeyring::class, $keyring);
        self::assertSame(self::KID_NEW, $keyring->activeKid());

        $verificationKeys = $keyring->verificationKeys();

        self::assertIsArray($verificationKeys);
        self::assertArrayHasKey(self::KID_NEW, $verificationKeys);
        self::assertArrayHasKey(self::KID_OLD, $verificationKeys);
    }

    /**
     * With no per-guard `jwt` block, the builder falls back to the
     * package-wide `authentication.jwt.*` defaults unchanged -
     * backwards-compatible with single-guard consumers.
     *
     * @return void
     */
    public function testFallsBackToPackageDefaultsWithEmptyGuardBlock(): void
    {
        config()->set('authentication.jwt.secret', self::PACKAGE_SECRET);
        config()->set('authentication.jwt.audience', 'package-default-audience');
        config()->set('authentication.jwt.access_ttl_minutes', 45);

        $service = $this->invokeBuildJwtTokenService([]);

        $keyring = $this->readServiceProperty($service, 'keyring');

        self::assertInstanceOf(JwtKeyring::class, $keyring);
        self::assertSame(self::PACKAGE_SECRET, $keyring->activeKey()->getKeyMaterial());
        self::assertSame('package-default-audience', $this->readServiceProperty($service, 'audience'));
        self::assertSame(45, $this->readServiceProperty($service, 'accessTtlMinutes'));
    }

    /**
     * A per-guard `identifier_field` override on the basic guard's config
     * block wins over the package-wide default, so consumers can register
     * multiple basic guards that look up credentials by different columns
     * (e.g. `email` for web users and `key_id` for tenant API keys).
     *
     * @return void
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
     */
    protected function defineEnvironment(mixed $app): void
    {
        assert($app instanceof \Illuminate\Foundation\Application);

        /** @var \Illuminate\Config\Repository $config */
        $config = $app->make(\Illuminate\Config\Repository::class);

        $config->set('auth.providers.identities', [
            'driver' => 'model',
            'model'  => \Tests\Unit\Stubs\StubAuthenticatableModel::class,
        ]);
    }

    /**
     * Invoke the private `buildJwtTokenService` factory via reflection with
     * the supplied per-guard override block.
     *
     * @param  array<string, mixed>  $guardJwtConfig
     * @return \SineMacula\Laravel\Authentication\Jwt\JwtTokenService
     */
    private function invokeBuildJwtTokenService(array $guardJwtConfig): JwtTokenService
    {
        $service = (new \ReflectionClass(AuthServiceProvider::class))
            ->getMethod('buildJwtTokenService')
            ->invoke(null, $this->app, $guardJwtConfig);    // NOSONAR

        assert($service instanceof JwtTokenService);

        return $service;
    }

    /**
     * Read a private property off a `JwtTokenService` instance via reflection
     * so the override tests can inspect the merged field values directly
     * without leaking getters to production.
     *
     * @param  \SineMacula\Laravel\Authentication\Jwt\JwtTokenService  $service
     * @param  string  $property
     * @return mixed
     */
    private function readServiceProperty(JwtTokenService $service, string $property): mixed
    {
        $reflectionProperty = (new \ReflectionClass($service))->getProperty($property);

        return $reflectionProperty->getValue($service);    // NOSONAR
    }

    /**
     * Read a private / readonly property off a `BasicGuard` instance via
     * reflection. Used by the identifier-field override tests to inspect the
     * resolved lookup column directly.
     *
     * @param  \SineMacula\Laravel\Authentication\Guards\BasicGuard  $guard
     * @param  string  $property
     * @return mixed
     */
    private function readGuardProperty(BasicGuard $guard, string $property): mixed
    {
        $reflectionProperty = (new \ReflectionClass($guard))->getProperty($property);

        return $reflectionProperty->getValue($guard);    // NOSONAR
    }
}
