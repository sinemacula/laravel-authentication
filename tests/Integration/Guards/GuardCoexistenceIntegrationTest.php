<?php

declare(strict_types = 1);

namespace Tests\Integration\Guards;

use Carbon\Carbon;
use Firebase\JWT\JWT;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\AuthManager;
use SineMacula\Laravel\Authentication\AuthServiceProvider;
use SineMacula\Laravel\Authentication\Contracts\ContextualGuard;
use SineMacula\Laravel\Authentication\Facades\Auth as PackageAuth;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Resolvers\DefaultPrincipalResolver;
use Tests\Integration\Fixtures\Coexist2dIdentity;
use Tests\Integration\Fixtures\Coexist3dIdentity;
use Tests\Integration\Fixtures\Coexist3dPrincipal;
use Tests\TestCase;

/**
 * Integration test proving that two package guards - one in 2D mode
 * (identity-is-principal) and one in 3D mode (identity → distinct principal
 * via `HasPrincipals`) - can coexist in the same Laravel application without
 * cross-contamination.
 *
 * Both guards run through the real `JwtGuard::user()` bearer-token resolution
 * path using tokens issued through the guard-scoped `Auth::jwt(...)` surface,
 * so the test exercises the full identity → provider → resolver → principal
 * wiring end-to-end.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Ltd
 *
 * @internal
 */
#[CoversClass(JwtGuard::class)]
#[CoversClass(AuthManager::class)]
#[CoversClass(AuthServiceProvider::class)]
#[CoversClass(DefaultPrincipalResolver::class)]
final class GuardCoexistenceIntegrationTest extends TestCase
{
    /** @var string */
    private const string GUARD_2D = 'api_2d';

    /** @var string */
    private const string GUARD_3D = 'api_3d';

    /** @var \Carbon\Carbon */
    private Carbon $now;

    /**
     * Freeze the Carbon + JWT clocks and create the three fixture tables used
     * by the 2D and 3D guards (the base TestCase already creates the shipped
     * `devices` table via `defineDatabaseMigrations()`, which these guards do
     * not need but is harmless to leave in place).
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->now = Carbon::createStrict(2026, 4, 6, 12, 0, 0);

        Carbon::setTestNow($this->now);

        JWT::$timestamp = $this->now->getTimestamp();

        Schema::create('coexist_2d_identities', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('email')->unique();
            $blueprint->string('password');
            $blueprint->boolean('is_active')->default(true);
            $blueprint->timestamps();
        });

        Schema::create('coexist_3d_identities', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('email')->unique();
            $blueprint->string('password');
            $blueprint->boolean('is_active')->default(true);
            $blueprint->timestamps();
        });

        Schema::create('coexist_3d_principals', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->unsignedInteger('identity_id');
            $blueprint->string('name');
            $blueprint->boolean('is_active')->default(true);
            $blueprint->timestamps();
        });
    }

    /**
     * Drop the three fixture tables and release the frozen clocks.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Schema::dropIfExists('coexist_3d_principals');
        Schema::dropIfExists('coexist_3d_identities');
        Schema::dropIfExists('coexist_2d_identities');

        Carbon::setTestNow();

        JWT::$timestamp = null;

        parent::tearDown();
    }

    /**
     * End-to-end coexistence assertion.
     *
     * Seeds a 2D identity and a 3D identity + principal, issues a real JWT
     * access token for each via the guard-scoped `Auth::jwt(...)` surface,
     * hands each token to the respective guard through a real Illuminate
     * Request's `Bearer` header, and asserts:
     *
     * 1. the 2D guard's `identity()` and `principal()` return the
     *    exact same model instance (2D adoption mode),
     * 2. the 3D guard's `identity()` and `principal()` return
     *    distinct model instances of distinct classes (3D mode),
     * 3. after binding the 3D guard, the 2D guard still exposes
     *    its own 2D identity - i.e. no cross-contamination,
     * 4. and `Auth::id()` on each guard returns that guard's
     *    identity key, not the other's.
     *
     * @return void
     */
    public function testBothGuardsAuthenticateInSameRunWithoutCrossContamination(): void
    {
        [$twoD, $threeDIdentity, $threeDPrincipal] = $this->seedFixtures();

        $twoDToken = PackageAuth::jwt(self::GUARD_2D)->issueAccessToken($twoD, $twoD, null);
        $threeDToken = PackageAuth::jwt(self::GUARD_3D)->issueAccessToken($threeDIdentity, $threeDPrincipal, null);

        $guard2d = $this->resolve2dGuard($twoDToken, $twoD);
        $guard3d = $this->resolve3dGuard($threeDToken, $threeDIdentity, $threeDPrincipal, $guard2d);

        $this->assertNoCrossContamination($guard2d, $guard3d);

        self::assertSame($twoD->getKey(), $guard2d->id());
        self::assertSame($threeDIdentity->getKey(), $guard3d->id());
    }

    /**
     * Flip `auth.defaults.guard` between `api_2d` and `api_3d` and assert that
     * the default-guard-dispatched `Auth::principal()` accessor routes to the
     * correct guard each time, exposing the matching adoption mode's
     * contextual triple.
     *
     * @return void
     */
    public function testSwitchingDefaultGuardTo2dExposesCorrectContext(): void
    {
        [$twoD] = $this->seedFixtures();

        $twoDToken = PackageAuth::jwt(self::GUARD_2D)->issueAccessToken($twoD, $twoD, null);

        $this->switchDefaultGuard(self::GUARD_2D);
        $this->bindRequestWithBearer($twoDToken);

        $guard = PackageAuth::guard();

        self::assertInstanceOf(ContextualGuard::class, $guard);
        self::assertNotNull($guard->user());

        $identity  = PackageAuth::identity();
        $principal = PackageAuth::principal();

        self::assertInstanceOf(Coexist2dIdentity::class, $identity);
        self::assertInstanceOf(Coexist2dIdentity::class, $principal);
        self::assertSame($identity, $principal);
    }

    /**
     * Flip `auth.defaults.guard` to `api_3d` and assert that the
     * default-guard-dispatched `Auth::principal()` accessor routes to the
     * 3D guard, exposing distinct identity and principal instances.
     *
     * @return void
     */
    public function testSwitchingDefaultGuardTo3dExposesCorrectContext(): void
    {
        [, $threeDIdentity, $threeDPrincipal] = $this->seedFixtures();

        $threeDToken = PackageAuth::jwt(self::GUARD_3D)->issueAccessToken($threeDIdentity, $threeDPrincipal, null);

        $this->switchDefaultGuard(self::GUARD_3D);
        $this->bindRequestWithBearer($threeDToken);

        $guard = PackageAuth::guard();

        self::assertInstanceOf(ContextualGuard::class, $guard);
        self::assertNotNull($guard->user());

        $identity  = PackageAuth::identity();
        $principal = PackageAuth::principal();

        self::assertInstanceOf(Coexist3dIdentity::class, $identity);
        self::assertInstanceOf(Coexist3dPrincipal::class, $principal);
        self::assertNotSame($identity, $principal);
    }

    /**
     * Configure the two providers and two jwt guards the tests run against,
     * plus the JWT secret and the default `api_2d` guard.
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

        $config->set('auth.defaults.guard', self::GUARD_2D);

        $config->set('auth.guards.' . self::GUARD_2D, [
            'driver'   => 'jwt',
            'provider' => 'identities_2d',
        ]);

        $config->set('auth.guards.' . self::GUARD_3D, [
            'driver'   => 'jwt',
            'provider' => 'identities_3d',
        ]);

        $config->set('auth.providers.identities_2d', [
            'driver' => 'model',
            'model'  => Coexist2dIdentity::class,
        ]);

        $config->set('auth.providers.identities_3d', [
            'driver' => 'model',
            'model'  => Coexist3dIdentity::class,
        ]);
    }

    /**
     * Resolve the 2D guard under a request carrying the supplied bearer token
     * and assert the identity and principal are the same model instance.
     *
     * @param  string  $token
     * @param  \Tests\Integration\Fixtures\Coexist2dIdentity  $expected
     * @return \SineMacula\Laravel\Authentication\Contracts\ContextualGuard
     */
    private function resolve2dGuard(string $token, Coexist2dIdentity $expected): ContextualGuard
    {
        $this->bindRequestWithBearer($token);

        $guard = PackageAuth::guard(self::GUARD_2D);

        self::assertInstanceOf(ContextualGuard::class, $guard);
        self::assertNotNull($guard->user());

        $resolved = $guard->identity();

        self::assertInstanceOf(Coexist2dIdentity::class, $resolved);
        self::assertSame($expected->getKey(), $resolved->getKey());
        self::assertSame($resolved, $guard->principal(), 'In 2D mode the identity and principal must be the same model instance.');

        return $guard;
    }

    /**
     * Resolve the 3D guard under a request carrying the supplied bearer token
     * and assert the identity and principal are distinct model instances.
     *
     * @param  string  $token
     * @param  \Tests\Integration\Fixtures\Coexist3dIdentity  $expectedIdentity
     * @param  \Tests\Integration\Fixtures\Coexist3dPrincipal  $expectedPrincipal
     * @param  \SineMacula\Laravel\Authentication\Contracts\ContextualGuard  $guard2d
     * @return \SineMacula\Laravel\Authentication\Contracts\ContextualGuard
     */
    private function resolve3dGuard(
        string $token,
        Coexist3dIdentity $expectedIdentity,
        Coexist3dPrincipal $expectedPrincipal,
        ContextualGuard $guard2d,
    ): ContextualGuard {

        $this->bindRequestWithBearer($token);

        $guard = PackageAuth::guard(self::GUARD_3D);

        self::assertInstanceOf(ContextualGuard::class, $guard);
        self::assertNotSame($guard2d, $guard, 'The two guards must be distinct instances cached independently by the AuthManager.');
        self::assertNotNull($guard->user());

        $resolved = $guard->identity();

        self::assertInstanceOf(Coexist3dIdentity::class, $resolved);
        self::assertSame($expectedIdentity->getKey(), $resolved->getKey());

        $principal = $guard->principal();

        self::assertInstanceOf(Coexist3dPrincipal::class, $principal);
        self::assertNotSame($guard->identity(), $principal, 'In 3D mode the identity and principal must be distinct instances.');
        self::assertNotInstanceOf(Coexist3dIdentity::class, $principal, 'The 3D principal must NOT be an instance of the identity model class.');
        self::assertSame($expectedPrincipal->getKey(), $principal->getPrincipalIdentifier());

        return $guard;
    }

    /**
     * Assert that the two guards do not leak model instances across
     * guard boundaries.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\ContextualGuard  $guard2d
     * @param  \SineMacula\Laravel\Authentication\Contracts\ContextualGuard  $guard3d
     * @return void
     */
    private function assertNoCrossContamination(ContextualGuard $guard2d, ContextualGuard $guard3d): void
    {
        self::assertInstanceOf(Coexist2dIdentity::class, $guard2d->identity());
        self::assertInstanceOf(Coexist2dIdentity::class, $guard2d->principal());
        self::assertNotInstanceOf(Coexist3dIdentity::class, $guard2d->identity());
        self::assertNotInstanceOf(Coexist3dPrincipal::class, $guard2d->principal());

        self::assertNotInstanceOf(Coexist2dIdentity::class, $guard3d->identity());
        self::assertNotInstanceOf(Coexist2dIdentity::class, $guard3d->principal());
    }

    /**
     * Insert one 2D identity row, one 3D identity row, and one matching active
     * principal row, returning the three hydrated models.
     *
     * @formatter:off
     *
     * @return array{0: \Tests\Integration\Fixtures\Coexist2dIdentity, 1: \Tests\Integration\Fixtures\Coexist3dIdentity, 2: \Tests\Integration\Fixtures\Coexist3dPrincipal}
     *
     * @formatter:on
     */
    private function seedFixtures(): array
    {
        $twoD            = new Coexist2dIdentity;
        $twoD->email     = '2d@example.test';
        $twoD->password  = 'hashed-irrelevant';
        $twoD->is_active = true;
        $twoD->save();

        $threeDIdentity            = new Coexist3dIdentity;
        $threeDIdentity->email     = '3d@example.test';
        $threeDIdentity->password  = 'hashed-irrelevant';
        $threeDIdentity->is_active = true;
        $threeDIdentity->save();

        $threeDPrincipal              = new Coexist3dPrincipal;
        $threeDPrincipal->identity_id = $threeDIdentity->id;
        $threeDPrincipal->name        = 'Acting on behalf of 3d@example.test';
        $threeDPrincipal->is_active   = true;
        $threeDPrincipal->save();

        return [$twoD, $threeDIdentity, $threeDPrincipal];
    }

    /**
     * Bind a fresh Illuminate Request carrying the supplied JWT as a `Bearer`
     * token onto the container's `request` binding. The service provider's
     * `refresh('request', ...)` wiring propagates the new request onto every
     * previously-constructed guard, so already-resolved guards pick up the
     * swap automatically.
     *
     * @param  string  $token
     * @return void
     */
    private function bindRequestWithBearer(#[\SensitiveParameter] string $token): void
    {
        $app = $this->app;

        assert($app !== null);

        $request = Request::create('/coexist', 'GET', [], [], [], [
            'HTTP_AUTHORIZATION' => 'Bearer ' . $token,
        ]);

        $app->instance('request', $request);
    }

    /**
     * Swap the default guard config key and forget any cached guards so the
     * next `Auth::guard()` call builds the newly-defaulted guard against the
     * current request binding.
     *
     * @param  string  $name
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function switchDefaultGuard(string $name): void
    {
        config()->set('auth.defaults.guard', $name);

        PackageAuth::manager()->forgetGuards();
    }
}
