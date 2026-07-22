<?php

declare(strict_types = 1);

namespace Tests\Integration\Guards;

use Firebase\JWT\JWT;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Cache\ResolutionCacheInvalidator;
use SineMacula\Laravel\Authentication\Contracts\ResolutionCache;
use SineMacula\Laravel\Authentication\Facades\Auth as PackageAuth;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Jwt\Enums\Claims;
use SineMacula\Laravel\Authentication\Jwt\Enums\TokenType;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenHasher;
use SineMacula\Laravel\Authentication\Models\Device;
use Tests\TestCase;
use Tests\Unit\Stubs\PlainPrincipalFixture;
use Tests\Unit\Stubs\StubActiveAwarePrincipal;
use Tests\Unit\Stubs\StubMutablePrincipalResolver;

/**
 * Integration tests for cross-request freshness on the JWT bearer/refresh paths
 * when bearer identity caching is enabled.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(JwtGuard::class)]
final class JwtGuardResolutionFreshnessIntegrationTest extends TestCase
{
    /** @var string Guard name used by all freshness tests. */
    private const string GUARD = 'api';

    /** @var string Container alias for the fixed principal resolver. */
    private const string RESOLVER = 'freshness-resolver';

    /** @var string HS256 signing secret for freshness test tokens. */
    private const string JWT_SECRET = 'freshness-secret-with-at-least-32-bytes!';

    /**
     * Provision the identity table and register the mutable principal resolver.
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

        assert($this->app !== null);

        $this->app->instance(self::RESOLVER, new StubMutablePrincipalResolver);
    }

    /**
     * Drop the shared identity table.
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
     * Bearer auth must reject the next request once the identity becomes
     * inactive and the shared identity cache entry is explicitly invalidated.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Random\RandomException
     */
    public function testBearerRejectsPreviouslyIssuedTokenWhenIdentityBecomesInactiveBetweenRequests(): void
    {
        $identity  = $this->seedIdentity();
        $principal = new PlainPrincipalFixture('principal-live', $identity);

        $this->resolver()->setHintedPrincipal('principal-live', $principal);

        $jwt = PackageAuth::jwt(self::GUARD);
        assert($jwt !== null);

        $token = $jwt->issueAccessToken($identity, $principal, null);

        self::assertTrue($this->guardForBearer($token)->check());

        $identity->is_active = false;
        $identity->save();

        app(ResolutionCacheInvalidator::class)->forgetIdentity($identity);

        self::assertFalse($this->guardForBearer($token)->check());
    }

    /**
     * Principals stay live-resolved on every bearer request even when the
     * identity itself comes from the shared cache.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Random\RandomException
     */
    public function testBearerRejectsPreviouslyIssuedTokenWhenResolvedPrincipalBecomesInactiveBetweenRequests(): void
    {
        $identity = $this->seedIdentity('principal-change@example.test');

        $activePrincipal   = new PlainPrincipalFixture('principal-live', $identity, null, true);
        $inactivePrincipal = new PlainPrincipalFixture('principal-live', $identity, null, false);

        $this->resolver()->setHintedPrincipal('principal-live', $activePrincipal);

        $jwt = PackageAuth::jwt(self::GUARD);
        assert($jwt !== null);

        $token = $jwt->issueAccessToken($identity, $activePrincipal, null);

        self::assertTrue($this->guardForBearer($token)->check());

        $this->resolver()->setHintedPrincipal('principal-live', $inactivePrincipal);

        self::assertFalse($this->guardForBearer($token)->check());
    }

    /**
     * Bearer device resolution remains live-only, so deleting the device row
     * causes the next request with that `did` claim to fail closed.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Random\RandomException
     */
    public function testBearerRejectsPreviouslyIssuedTokenWhenHintedDeviceIsDeletedBetweenRequests(): void
    {
        $identity = $this->seedIdentity('device-delete@example.test');
        $device   = $this->seedDevice($identity);

        $this->resolver()->setHintedPrincipal((string) $identity->getKey(), $identity); // @phpstan-ignore cast.string

        $jwt = PackageAuth::jwt(self::GUARD);
        assert($jwt !== null);

        $token = $jwt->issueAccessToken($identity, $identity, $device);

        self::assertTrue($this->guardForBearer($token)->check());

        $device->delete();

        self::assertFalse($this->guardForBearer($token)->check());
    }

    /**
     * Refresh must re-check the live identity row on every exchange.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testRefreshRejectsTokenWhenIdentityBecomesInactiveAfterIssuance(): void
    {
        $identity = $this->seedIdentity('refresh-identity@example.test');
        $device   = $this->seedDevice($identity, 'stored-rotation-id');

        $jwt = PackageAuth::jwt(self::GUARD);
        assert($jwt !== null);

        $token = $jwt->issueRefreshToken($device, 'stored-rotation-id', $identity);

        $identity->is_active = false;
        $identity->save();

        self::assertNull($this->freshGuard()->refresh($token));
    }

    /**
     * Refresh must re-check the live principal result on every exchange.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testRefreshRejectsTokenWhenPrincipalBecomesInactiveAfterIssuance(): void
    {
        $identity = $this->seedIdentity('refresh-principal@example.test');
        $device   = $this->seedDevice($identity, 'refresh-principal-rotation');

        $activePrincipal   = new PlainPrincipalFixture('principal-refresh', $identity, null, true);
        $inactivePrincipal = new PlainPrincipalFixture('principal-refresh', $identity, null, false);

        $jwt = PackageAuth::jwt(self::GUARD);
        assert($jwt !== null);

        $token = $jwt->issueRefreshToken($device, 'refresh-principal-rotation', $activePrincipal);

        $this->resolver()->setHintedPrincipal('principal-refresh', $inactivePrincipal);

        self::assertNull($this->freshGuard()->refresh($token));
    }

    /**
     * Refresh remains device-row-backed and must fail immediately when the
     * referenced device has been deleted.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testRefreshRejectsTokenWhenDeviceIsDeletedAfterIssuance(): void
    {
        $identity = $this->seedIdentity('refresh-device-delete@example.test');
        $device   = $this->seedDevice($identity, 'refresh-device-delete');

        $jwt = PackageAuth::jwt(self::GUARD);
        assert($jwt !== null);

        $token = $jwt->issueRefreshToken($device, 'refresh-device-delete', $identity);

        $device->delete();

        self::assertNull($this->freshGuard()->refresh($token));
    }

    /**
     * The bearer path must resolve principals against the current resolver
     * policy on a fresh request even when the identity hits the shared cache.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testBearerSeesChangedResolverMappingOnFreshRequest(): void
    {
        $identity = $this->seedIdentity('resolver-change@example.test');

        $this->resolver()->setDefaultPrincipal(new PlainPrincipalFixture('staff-actor', $identity));

        $token = $this->encodeAccessToken([
            'sub' => (string) $identity->getKey(), // @phpstan-ignore cast.string
            'iat' => time(),
            'exp' => time() + 600,
        ]);

        $firstGuard = $this->guardForBearer($token);

        self::assertTrue($firstGuard->check());
        self::assertSame('staff-actor', $firstGuard->principal()?->getPrincipalIdentifier());

        $this->resolver()->setDefaultPrincipal(new PlainPrincipalFixture('customer-actor', $identity));

        $secondGuard = $this->guardForBearer($token);

        self::assertTrue($secondGuard->check());
        self::assertSame('customer-actor', $secondGuard->principal()?->getPrincipalIdentifier());
    }

    /**
     * Refresh must not consult the shared bearer identity cache at all.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testRefreshPathNeverUsesResolutionCache(): void
    {
        $identity = $this->seedIdentity('refresh-cache-bypass@example.test');
        $device   = $this->seedDevice($identity, 'refresh-cache-bypass');

        $this->resolver()->setHintedPrincipal((string) $identity->getKey(), $identity); // @phpstan-ignore cast.string

        assert($this->app !== null);

        $this->app->instance(
            ResolutionCache::class,
            new class implements ResolutionCache {
                /**
                 * @param  string  $guardName
                 * @param  string  $providerModelClass
                 * @param  mixed  $identifier
                 * @param  callable(): ?\Illuminate\Contracts\Auth\Authenticatable  $resolver
                 * @return never
                 *
                 * @throws \LogicException
                 */
                #[\Override]
                public function rememberJwtIdentity(string $guardName, string $providerModelClass, mixed $identifier, callable $resolver): ?Authenticatable
                {
                    unset($guardName, $providerModelClass, $identifier, $resolver);

                    throw new \LogicException('Refresh must not use the shared resolution cache.');
                }

                /**
                 * @param  string  $guardName
                 * @param  string  $providerModelClass
                 * @param  mixed  $identifier
                 * @return void
                 *
                 * @throws \LogicException
                 */
                #[\Override]
                public function forgetJwtIdentity(string $guardName, string $providerModelClass, mixed $identifier): void
                {
                    unset($guardName, $providerModelClass, $identifier);

                    throw new \LogicException('Refresh must not invalidate the shared resolution cache.');
                }
            },
        );

        $jwt = PackageAuth::jwt(self::GUARD);
        assert($jwt !== null);

        $token = $jwt->issueRefreshToken($device, 'refresh-cache-bypass', $identity);

        self::assertNotNull($this->freshGuard()->refresh($token));
    }

    /**
     * Configure the single JWT guard used by this suite.
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

        $config->set('cache.default', 'array');
        $config->set('auth.defaults.guard', self::GUARD);

        $config->set('auth.guards.' . self::GUARD, [
            'driver'             => 'jwt',
            'provider'           => 'identities',
            'principal_resolver' => self::RESOLVER,
        ]);

        $config->set('auth.providers.identities', [
            'driver' => 'model',
            'model'  => StubActiveAwarePrincipal::class,
        ]);

        $config->set('authentication.jwt.secret', self::JWT_SECRET);
        $config->set('authentication.jwt.algorithm', 'HS256');
        $config->set('authentication.resolution_cache.jwt.identity_ttl_seconds', 15);
    }

    /**
     * Persist and return an active identity row.
     *
     * @param  string  $email
     * @return \Tests\Unit\Stubs\StubActiveAwarePrincipal
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function seedIdentity(string $email = 'freshness@example.test'): StubActiveAwarePrincipal
    {
        $hasher = app(Hasher::class);

        $identity            = new StubActiveAwarePrincipal;
        $identity->email     = $email;
        $identity->password  = $hasher->make('correct horse battery staple');
        $identity->is_active = true;
        $identity->save();

        return $identity;
    }

    /**
     * Return the mutable principal resolver bound for the suite.
     *
     * @return \Tests\Unit\Stubs\StubMutablePrincipalResolver
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function resolver(): StubMutablePrincipalResolver
    {
        assert($this->app !== null);

        $resolver = $this->app->make(self::RESOLVER);

        assert($resolver instanceof StubMutablePrincipalResolver);

        return $resolver;
    }

    /**
     * Resolve a fresh guard against a bearer-authenticated request.
     *
     * @param  string  $token
     * @return \SineMacula\Laravel\Authentication\Guards\JwtGuard
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function guardForBearer(#[\SensitiveParameter] string $token): JwtGuard
    {
        app()->instance('request', Request::create('/freshness', 'GET', [], [], [], [
            'HTTP_AUTHORIZATION' => 'Bearer ' . $token,
        ]));

        return $this->freshGuard();
    }

    /**
     * Resolve a fresh guard against the current request binding.
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
     * Persist and return a device row for the supplied identity.
     *
     * @param  \Tests\Unit\Stubs\StubActiveAwarePrincipal  $identity
     * @param  ?string  $rotationId
     * @return \SineMacula\Laravel\Authentication\Models\Device
     */
    private function seedDevice(StubActiveAwarePrincipal $identity, ?string $rotationId = null): Device
    {
        $device = new Device;
        $device->forceFill([
            'authenticatable_type' => StubActiveAwarePrincipal::class,
            'authenticatable_id'   => (string) $identity->getKey(), // @phpstan-ignore cast.string
            'os'                   => 'ios',
            'refresh_key'          => $rotationId === null ? null : RefreshTokenHasher::hash($rotationId),
        ])->save();

        return $device;
    }

    /**
     * Encode an access token with only the claims needed by the bearer tests.
     *
     * @param  array<string, mixed>  $claims
     * @return string
     */
    private function encodeAccessToken(array $claims): string
    {
        return JWT::encode(
            array_merge($claims, [Claims::TYPE->value => TokenType::ACCESS->value]),
            self::JWT_SECRET,
            'HS256',
        );
    }
}
