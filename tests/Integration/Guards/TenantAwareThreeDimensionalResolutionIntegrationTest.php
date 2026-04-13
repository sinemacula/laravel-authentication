<?php

declare(strict_types = 1);

namespace Tests\Integration\Guards;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Facades\Auth as PackageAuth;
use SineMacula\Laravel\Authentication\Guards\BasicGuard;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Resolvers\DefaultPrincipalResolver;
use Tests\Integration\Fixtures\TenantAware3dIdentity;
use Tests\Integration\Fixtures\TenantAware3dPrincipal;
use Tests\Integration\Fixtures\TenantAware3dTenant;
use Tests\TestCase;
use Tests\Unit\Stubs\StubPrincipal;

/**
 * Integration tests for tenant-aware 3D principal resolution.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(BasicGuard::class)]
#[CoversClass(JwtGuard::class)]
#[CoversClass(DefaultPrincipalResolver::class)]
final class TenantAwareThreeDimensionalResolutionIntegrationTest extends TestCase
{
    private const TEST_PASSWORD = 'correct horse battery staple';

    /** @var string JWT guard name for 3D bearer tests. */
    private const string JWT_GUARD = 'api_3d';

    /** @var string Basic guard name for 3D credential tests. */
    private const string BASIC_THREE_D_GUARD = 'cli_3d';

    /** @var string Basic guard name for 2D credential tests. */
    private const string BASIC_TWO_D_GUARD = 'cli_2d';

    /**
     * Provision the tenant-aware 3D and 2D identity tables used by the suite.
     *
     * @return void
     */
    protected function setUp(): void
    {
        parent::setUp();

        Schema::create('tenant_aware_3d_identities', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('email')->unique();
            $blueprint->string('password');
            $blueprint->boolean('is_active')->default(true);
            $blueprint->timestamps();
        });

        Schema::create('tenant_aware_3d_tenants', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('name');
            $blueprint->string('type');
            $blueprint->timestamps();
        });

        Schema::create('tenant_aware_3d_principals', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->unsignedInteger('identity_id');
            $blueprint->unsignedInteger('tenant_id');
            $blueprint->string('name');
            $blueprint->boolean('is_active')->default(true);
            $blueprint->timestamps();
        });

        Schema::create('stub_principals', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('email')->unique();
            $blueprint->string('password');
            $blueprint->boolean('is_active')->default(true);
            $blueprint->timestamps();
        });
    }

    /**
     * Drop the in-memory schema.
     *
     * @return void
     */
    protected function tearDown(): void
    {
        Schema::dropIfExists('stub_principals');
        Schema::dropIfExists('tenant_aware_3d_principals');
        Schema::dropIfExists('tenant_aware_3d_tenants');
        Schema::dropIfExists('tenant_aware_3d_identities');

        parent::tearDown();
    }

    /**
     * A hinted JWT principal can be resolved with tenant context pre-attached
     * while preserving the exact principal and inverse identity mapping.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Random\RandomException
     */
    public function testJwtBearerHintedResolutionKeepsPrincipalTenantAndTypeStable(): void
    {
        [$identity, $principal, $tenant] = $this->seedTenantAwareThreeDimensionalFixtures();

        $jwt = PackageAuth::jwt(self::JWT_GUARD);
        assert($jwt !== null);

        $token = $jwt->issueAccessToken($identity, $principal, null);
        $guard = $this->jwtGuardForBearer($token);

        self::assertTrue($guard->check());
        $resolvedIdentity  = $guard->identity();
        $resolvedPrincipal = $guard->principal();
        $resolvedTenant    = $guard->tenant();

        self::assertInstanceOf(TenantAware3dIdentity::class, $resolvedIdentity);
        self::assertInstanceOf(TenantAware3dPrincipal::class, $resolvedPrincipal);
        self::assertNotNull($resolvedTenant);
        self::assertSame($resolvedIdentity, $resolvedPrincipal->getIdentity());
        self::assertSame($principal->getPrincipalIdentifier(), $resolvedPrincipal->getPrincipalIdentifier());
        self::assertSame($tenant->getTenantIdentifier(), $resolvedTenant->getTenantIdentifier());
        self::assertSame('staff', $guard->type());
    }

    /**
     * The 3D BasicGuard credential path still authenticates normally while the
     * identity's default principal lookup can return tenant-aware context.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testBasicGuardThreeDimensionalDefaultResolutionKeepsTenantAndTypeStable(): void
    {
        [$identity, $principal, $tenant] = $this->seedTenantAwareThreeDimensionalFixtures('basic-3d@example.test');

        $guard = $this->basicGuardForCredentials(
            self::BASIC_THREE_D_GUARD,
            $identity->email,
            self::TEST_PASSWORD,
        );

        self::assertNotNull($guard->user());

        $resolvedIdentity  = $guard->identity();
        $resolvedPrincipal = $guard->principal();
        $resolvedTenant    = $guard->tenant();

        self::assertInstanceOf(TenantAware3dIdentity::class, $resolvedIdentity);
        self::assertInstanceOf(TenantAware3dPrincipal::class, $resolvedPrincipal);
        self::assertNotNull($resolvedTenant);
        self::assertSame($resolvedIdentity, $resolvedPrincipal->getIdentity());
        self::assertSame($principal->getPrincipalIdentifier(), $resolvedPrincipal->getPrincipalIdentifier());
        self::assertSame($tenant->getTenantIdentifier(), $resolvedTenant->getTenantIdentifier());
        self::assertSame('staff', $guard->type());
    }

    /**
     * The 2D BasicGuard control path still returns the identity itself as the
     * acting principal.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testBasicGuardTwoDimensionalControlStillReturnsIdentityAsPrincipal(): void
    {
        $identity = $this->seedTwoDimensionalIdentity();

        $guard = $this->basicGuardForCredentials(
            self::BASIC_TWO_D_GUARD,
            $identity->email,
            self::TEST_PASSWORD,
        );

        self::assertNotNull($guard->user());

        $resolved = $guard->identity();

        self::assertInstanceOf(StubPrincipal::class, $resolved);
        self::assertSame($resolved, $guard->principal());
        self::assertNull($guard->tenant());
        self::assertNull($guard->type());
    }

    /**
     * Configure the JWT and Basic guards used by the suite.
     *
     * @param  mixed  $app
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        assert($app instanceof Application);

        /** @var \Illuminate\Config\Repository $config */
        $config = $app->make(ConfigRepository::class);

        $config->set('auth.defaults.guard', self::JWT_GUARD);

        $config->set('auth.guards.' . self::JWT_GUARD, [
            'driver'   => 'jwt',
            'provider' => 'tenant_aware_identities',
        ]);

        $config->set('auth.guards.' . self::BASIC_THREE_D_GUARD, [
            'driver'   => 'basic',
            'provider' => 'tenant_aware_identities',
        ]);

        $config->set('auth.guards.' . self::BASIC_TWO_D_GUARD, [
            'driver'   => 'basic',
            'provider' => 'two_d_identities',
        ]);

        $config->set('auth.providers.tenant_aware_identities', [
            'driver' => 'model',
            'model'  => TenantAware3dIdentity::class,
        ]);

        $config->set('auth.providers.two_d_identities', [
            'driver' => 'model',
            'model'  => StubPrincipal::class,
        ]);
    }

    /**
     * Persist and return one tenant-aware 3D identity plus its active scoped
     * principal and tenant.
     *
     * @formatter:off
     *
     * @param  string  $email
     * @return array{0: \Tests\Integration\Fixtures\TenantAware3dIdentity,
     *               1: \Tests\Integration\Fixtures\TenantAware3dPrincipal,
     *               2: \Tests\Integration\Fixtures\TenantAware3dTenant}
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     *
     * @formatter:on
     */
    private function seedTenantAwareThreeDimensionalFixtures(string $email = 'tenant-aware-3d@example.test'): array
    {
        $hasher = app(Hasher::class);

        $identity            = new TenantAware3dIdentity;
        $identity->email     = $email;
        $identity->password  = $hasher->make(self::TEST_PASSWORD);
        $identity->is_active = true;
        $identity->save();

        $tenant       = new TenantAware3dTenant;
        $tenant->name = 'Acme Staff';
        $tenant->type = 'staff';
        $tenant->save();

        $principal              = new TenantAware3dPrincipal;
        $principal->identity_id = $identity->getKey(); // @phpstan-ignore assign.propertyType
        $principal->tenant_id   = $tenant->getKey(); // @phpstan-ignore assign.propertyType
        $principal->name        = 'staff-actor';
        $principal->is_active   = true;
        $principal->save();

        return [$identity, $principal, $tenant];
    }

    /**
     * Resolve a fresh JWT guard against a request carrying the supplied bearer
     * token.
     *
     * @param  string  $token
     * @return \SineMacula\Laravel\Authentication\Guards\JwtGuard
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function jwtGuardForBearer(#[\SensitiveParameter] string $token): JwtGuard
    {
        app()->instance('request', Request::create('/tenant-aware-3d', 'GET', [], [], [], [
            'HTTP_AUTHORIZATION' => 'Bearer ' . $token,
        ]));

        $manager = PackageAuth::manager();
        $manager->forgetGuards();

        $guard = $manager->guard(self::JWT_GUARD);

        self::assertInstanceOf(JwtGuard::class, $guard);

        return $guard;
    }

    /**
     * Resolve a fresh BasicGuard against HTTP Basic credentials.
     *
     * @param  string  $guardName
     * @param  string  $username
     * @param  string  $password
     * @return \SineMacula\Laravel\Authentication\Guards\BasicGuard
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function basicGuardForCredentials(string $guardName, string $username, string $password): BasicGuard
    {
        app()->instance('request', Request::create('/tenant-aware-basic', 'GET', [], [], [], [
            'PHP_AUTH_USER' => $username,
            'PHP_AUTH_PW'   => $password,
        ]));

        $manager = PackageAuth::manager();
        $manager->forgetGuards();

        $guard = $manager->guard($guardName);

        self::assertInstanceOf(BasicGuard::class, $guard);

        return $guard;
    }

    /**
     * Persist and return an active 2D identity.
     *
     * @return \Tests\Unit\Stubs\StubPrincipal
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function seedTwoDimensionalIdentity(): StubPrincipal
    {
        $hasher = app(Hasher::class);

        $identity            = new StubPrincipal;
        $identity->email     = 'basic-2d@example.test';
        $identity->password  = $hasher->make(self::TEST_PASSWORD);
        $identity->is_active = true;
        $identity->save();

        return $identity;
    }
}
