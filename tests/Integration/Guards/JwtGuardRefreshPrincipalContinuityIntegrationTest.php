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
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Facades\Auth as PackageAuth;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Jwt\Enums\Claims;
use SineMacula\Laravel\Authentication\Jwt\Enums\TokenType;
use SineMacula\Laravel\Authentication\Jwt\RefreshResult;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenHasher;
use SineMacula\Laravel\Authentication\Models\Device;
use Tests\TestCase;
use Tests\Unit\Stubs\PlainPrincipalFixture;
use Tests\Unit\Stubs\StubMappedPrincipalResolver;
use Tests\Unit\Stubs\StubPrincipal;
use Tests\Unit\Stubs\StubTenant;

/**
 * Integration test for refresh principal continuity in multi-scope deployments.
 *
 * Verifies that a refresh token carrying the originally active principal id
 * keeps the refreshed bearer session on that same principal and therefore the
 * same tenant/type, even when the resolver's default principal differs.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(JwtGuard::class)]
final class JwtGuardRefreshPrincipalContinuityIntegrationTest extends TestCase
{
    /** @var string Guard name used by all refresh continuity tests. */
    private const string GUARD = 'api';

    /** @var string Container alias for the fixed principal resolver. */
    private const string RESOLVER = 'refresh-principal-continuity-resolver';

    /**
     * Provision the shared identity table used by the test.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        Schema::create('stub_principals', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('email')->unique();
            $blueprint->string('password');
            $blueprint->boolean('is_active')->default(true);
            $blueprint->timestamps();
        });
    }

    /**
     * Release the in-memory schema.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Schema::dropIfExists('stub_principals');

        parent::tearDown();
    }

    /**
     * A refresh token issued for a non-default scoped principal refreshes back
     * into that same scope instead of downgrading to the resolver's default.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testRefreshPreservesOriginalPrincipalTenantAndTypeWhenDefaultDiffers(): void
    {
        $identity = $this->seedIdentity();

        $customerTenant    = $this->makeTenant(202, 'customer');
        $staffTenant       = $this->makeTenant(101, 'staff');
        $customerPrincipal = new PlainPrincipalFixture('customer-actor', $identity, $customerTenant);
        $staffPrincipal    = new PlainPrincipalFixture('staff-actor', $identity, $staffTenant);

        $resolver = new StubMappedPrincipalResolver(
            $customerPrincipal,
            [
                'customer-actor' => $customerPrincipal,
                'staff-actor'    => $staffPrincipal,
            ],
        );

        assert($this->app !== null);

        $this->app->instance(self::RESOLVER, $resolver);

        self::assertSame('customer-actor', $resolver->resolve($identity)?->getPrincipalIdentifier());

        $plainRotationId = 'stored-rotation-id';

        $device = new Device;
        $device->forceFill([
            'authenticatable_type' => StubPrincipal::class,
            'authenticatable_id'   => (string) $identity->getKey(), // @phpstan-ignore cast.string
            'os'                   => 'ios',
            'refresh_key'          => RefreshTokenHasher::hash($plainRotationId),
        ])->save();

        $jwt = PackageAuth::jwt(self::GUARD);
        assert($jwt !== null);

        $guard  = $this->freshGuard();
        $result = $guard->refresh(
            $jwt->issueRefreshToken($device, $plainRotationId, $staffPrincipal),
        );

        self::assertInstanceOf(RefreshResult::class, $result);
        self::assertSame('staff-actor', $guard->principal()?->getPrincipalIdentifier());
        self::assertSame($staffTenant, $guard->tenant());
        self::assertSame('staff', $guard->type());

        $parseJwt = PackageAuth::jwt(self::GUARD);
        assert($parseJwt !== null);

        $refreshClaims = $parseJwt->parse($result->refreshToken, TokenType::REFRESH);

        self::assertIsArray($refreshClaims);
        self::assertSame('staff-actor', $refreshClaims[Claims::PRINCIPAL_ID->value]);

        $refreshedGuard = $this->guardForBearer($result->accessToken);

        self::assertTrue($refreshedGuard->check());
        self::assertSame('staff-actor', $refreshedGuard->principal()?->getPrincipalIdentifier());
        self::assertSame($staffTenant, $refreshedGuard->tenant());
        self::assertSame('staff', $refreshedGuard->type());
    }

    /**
     * Configure the JWT guard and provider used by this test.
     *
     * @param  mixed  $app
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        assert($app instanceof Application);

        /** @var \Illuminate\Config\Repository $config */
        $config = $app->make(ConfigRepository::class);

        $config->set('auth.defaults.guard', self::GUARD);

        $config->set('auth.guards.' . self::GUARD, [
            'driver'             => 'jwt',
            'provider'           => 'identities',
            'principal_resolver' => self::RESOLVER,
        ]);

        $config->set('auth.providers.identities', [
            'driver' => 'model',
            'model'  => StubPrincipal::class,
        ]);
    }

    /**
     * Persist and return an active identity row.
     *
     * @return \Tests\Unit\Stubs\StubPrincipal
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function seedIdentity(): StubPrincipal
    {
        $hasher = app(Hasher::class);

        $identity            = new StubPrincipal;
        $identity->email     = 'refresh-continuity@example.test';
        $identity->password  = $hasher->make('correct horse battery staple');
        $identity->is_active = true;
        $identity->save();

        return $identity;
    }

    /**
     * Build an unsaved tenant object with an identifier and type.
     *
     * @param  int  $id
     * @param  string  $type
     * @return \Tests\Unit\Stubs\StubTenant
     */
    private function makeTenant(int $id, string $type): StubTenant
    {
        $tenant = new StubTenant;
        $tenant->forceFill([
            'id'   => $id,
            'type' => $type,
        ]);

        return $tenant;
    }

    /**
     * Resolve a fresh guard for the current request.
     *
     * @return \SineMacula\Laravel\Authentication\Guards\JwtGuard
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function freshGuard(): JwtGuard
    {
        $manager = PackageAuth::manager();
        $manager->forgetGuards();

        $guard = $manager->guard(self::GUARD);

        self::assertInstanceOf(JwtGuard::class, $guard);

        return $guard;
    }

    /**
     * Resolve a fresh guard against a request carrying the supplied bearer
     * token.
     *
     * @param  string  $token
     * @return \SineMacula\Laravel\Authentication\Guards\JwtGuard
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function guardForBearer(#[\SensitiveParameter] string $token): JwtGuard
    {
        app()->instance('request', Request::create('/refresh-continuity', 'GET', [], [], [], [
            'HTTP_AUTHORIZATION' => 'Bearer ' . $token,
        ]));

        return $this->freshGuard();
    }
}
