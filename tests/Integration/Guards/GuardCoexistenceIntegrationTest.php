<?php

declare(strict_types = 1);

namespace Tests\Integration\Guards;

use Carbon\Carbon;
use Firebase\JWT\JWT;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\AuthManager;
use SineMacula\Laravel\Authentication\AuthServiceProvider;
use SineMacula\Laravel\Authentication\Contracts\ContextualGuard;
use SineMacula\Laravel\Authentication\Facades\Auth as PackageAuth;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenService;
use SineMacula\Laravel\Authentication\Resolvers\DefaultPrincipalResolver;
use Tests\Integration\Fixtures\Coexist2dIdentity;
use Tests\Integration\Fixtures\Coexist3dIdentity;
use Tests\Integration\Fixtures\Coexist3dPrincipal;
use Tests\TestCase;

/**
 * Integration test proving that two package guards — one in 2D mode
 * (identity-is-principal) and one in 3D mode (identity → distinct
 * principal via `HasPrincipals`) — can coexist in the same Laravel
 * application without cross-contamination.
 *
 * Satisfies the PRD P0 acceptance criterion: "A test application
 * configures one route protected by a 2D guard and another protected
 * by a 3D guard. Authenticating against the 2D route exposes identity
 * and principal as the same model; authenticating against the 3D
 * route exposes a principal and organization distinct from the
 * identity. Both routes return correct results in the same test run."
 *
 * Both guards run through the real `JwtGuard::user()` bearer-token
 * resolution path using tokens issued by the real `JwtTokenService`
 * resolved from the container, so the test exercises the full
 * identity → provider → resolver → principal wiring end-to-end.
 *
 * @author    Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright 2026 Sine Macula Limited.
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
     * Freeze the Carbon + JWT clocks and create the three fixture
     * tables used by the 2D and 3D guards (the base TestCase already
     * creates the shipped `devices` table via
     * `defineDatabaseMigrations()`, which these guards do not need but
     * is harmless to leave in place).
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
     * Seeds a 2D identity and a 3D identity + principal, issues a
     * real JWT access token for each via the container's
     * `JwtTokenService`, hands each token to the respective guard
     * through a real Illuminate Request's `Bearer` header, and
     * asserts:
     *
     *   1. the 2D guard's `identity()` and `principal()` return the
     *      exact same model instance (2D adoption mode),
     *   2. the 3D guard's `identity()` and `principal()` return
     *      distinct model instances of distinct classes (3D mode),
     *   3. after binding the 3D guard, the 2D guard still exposes
     *      its own 2D identity — i.e. no cross-contamination,
     *   4. and `Auth::id()` on each guard returns that guard's
     *      identity key, not the other's.
     *
     * @return void
     */
    public function testBothGuardsAuthenticateInSameRunWithoutCrossContamination(): void
    {
        [$twoD, $threeDIdentity, $threeDPrincipal] = $this->seedFixtures();

        $tokens = $this->tokenService();

        $twoDToken   = $tokens->issueAccessToken($twoD, $twoD, null);
        $threeDToken = $tokens->issueAccessToken($threeDIdentity, $threeDPrincipal, null);

        // Resolve the 2D guard first under a request carrying the 2D
        // bearer token. Assertions: the identity and principal are the
        // exact same model instance (2D mode), and Auth::id() returns
        // the 2D identity's key.
        $this->bindRequestWithBearer($twoDToken);

        $guard2d = PackageAuth::guard(self::GUARD_2D);

        self::assertInstanceOf(ContextualGuard::class, $guard2d);

        // Trigger bearer-token resolution via `user()` — the resolved
        // identity is asserted via the contextual `identity()`
        // accessor below because larastan narrows Laravel's
        // `Guard::user()` return type to the framework default
        // `Illuminate\Foundation\Auth\User`, which phpstan cannot
        // reconcile with our package-specific `Identity`
        // implementations.
        self::assertNotNull($guard2d->user());

        $resolved2d = $guard2d->identity();

        self::assertInstanceOf(Coexist2dIdentity::class, $resolved2d);
        self::assertSame($twoD->getKey(), $resolved2d->getKey());
        self::assertSame($resolved2d, $guard2d->principal(), 'In 2D mode the identity and principal must be the same model instance.');

        // Resolve the 3D guard under a request carrying the 3D bearer
        // token. Assertions: identity and principal are distinct
        // instances of distinct classes, and the principal's owning
        // identity matches the resolved identity.
        $this->bindRequestWithBearer($threeDToken);

        $guard3d = PackageAuth::guard(self::GUARD_3D);

        self::assertInstanceOf(ContextualGuard::class, $guard3d);
        self::assertNotSame($guard2d, $guard3d, 'The two guards must be distinct instances cached independently by the AuthManager.');

        self::assertNotNull($guard3d->user());

        $resolved3d = $guard3d->identity();

        self::assertInstanceOf(Coexist3dIdentity::class, $resolved3d);
        self::assertSame($threeDIdentity->getKey(), $resolved3d->getKey());

        $principal3d = $guard3d->principal();

        self::assertInstanceOf(Coexist3dPrincipal::class, $principal3d);
        self::assertNotSame($guard3d->identity(), $principal3d, 'In 3D mode the identity and principal must be distinct instances.');
        self::assertNotInstanceOf(Coexist3dIdentity::class, $principal3d, 'The 3D principal must NOT be an instance of the identity model class.');
        self::assertSame($threeDPrincipal->getKey(), $principal3d->getPrincipalIdentifier());

        // Cross-contamination checks. The previously-bound 2D guard
        // must still expose its own 2D identity + principal, and the
        // 3D guard must never expose the 2D model classes.
        self::assertInstanceOf(Coexist2dIdentity::class, $guard2d->identity());
        self::assertInstanceOf(Coexist2dIdentity::class, $guard2d->principal());
        self::assertNotInstanceOf(Coexist3dIdentity::class, $guard2d->identity());
        self::assertNotInstanceOf(Coexist3dPrincipal::class, $guard2d->principal());

        self::assertNotInstanceOf(Coexist2dIdentity::class, $guard3d->identity());
        self::assertNotInstanceOf(Coexist2dIdentity::class, $guard3d->principal());

        // Per-guard id() must reflect each guard's own identity key,
        // not the other guard's.
        self::assertSame($twoD->getKey(), $guard2d->id());
        self::assertSame($threeDIdentity->getKey(), $guard3d->id());
    }

    /**
     * Flip `auth.defaults.guard` between `api_2d` and `api_3d` and
     * assert that the default-guard-dispatched `Auth::principal()`
     * accessor routes to the correct guard each time, exposing the
     * matching adoption mode's contextual triple.
     *
     * @return void
     */
    public function testSwitchingDefaultGuardBetween2dAnd3dExposesCorrectContext(): void
    {
        [$twoD, $threeDIdentity, $threeDPrincipal] = $this->seedFixtures();

        $tokens = $this->tokenService();

        $twoDToken   = $tokens->issueAccessToken($twoD, $twoD, null);
        $threeDToken = $tokens->issueAccessToken($threeDIdentity, $threeDPrincipal, null);

        // Default guard → api_2d: a call to Auth::principal() via the
        // package manager must return the 2D identity itself.
        $this->switchDefaultGuard(self::GUARD_2D);
        $this->bindRequestWithBearer($twoDToken);

        $guard2d = PackageAuth::guard();

        self::assertInstanceOf(ContextualGuard::class, $guard2d);

        // Trigger resolution of the bearer token before reading the
        // manager's contextual accessors — `Auth::identity()` returns
        // the guard's already-bound identity rather than eagerly
        // resolving the token itself.
        self::assertNotNull($guard2d->user());

        $identity2d  = PackageAuth::identity();
        $principal2d = PackageAuth::principal();

        self::assertInstanceOf(Coexist2dIdentity::class, $identity2d);
        self::assertInstanceOf(Coexist2dIdentity::class, $principal2d);
        self::assertSame($identity2d, $principal2d);

        // Default guard → api_3d: the same accessor pair must now
        // route to the 3D guard and return a distinct principal.
        $this->switchDefaultGuard(self::GUARD_3D);
        $this->bindRequestWithBearer($threeDToken);

        $guard3d = PackageAuth::guard();

        self::assertInstanceOf(ContextualGuard::class, $guard3d);
        self::assertNotSame($guard2d, $guard3d);

        self::assertNotNull($guard3d->user());

        $identity3d  = PackageAuth::identity();
        $principal3d = PackageAuth::principal();

        self::assertInstanceOf(Coexist3dIdentity::class, $identity3d);
        self::assertInstanceOf(Coexist3dPrincipal::class, $principal3d);
        self::assertNotSame($identity3d, $principal3d);
    }

    /**
     * Configure the two providers and two jwt guards the tests run
     * against, plus the JWT secret and the default `api_2d` guard.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        assert($app instanceof \Illuminate\Foundation\Application);

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
     * Insert one 2D identity row, one 3D identity row, and one
     * matching active principal row, returning the three hydrated
     * models.
     *
     * @return array{0: \Tests\Integration\Fixtures\Coexist2dIdentity, 1: \Tests\Integration\Fixtures\Coexist3dIdentity, 2: \Tests\Integration\Fixtures\Coexist3dPrincipal}
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
     * Resolve the container's JwtTokenService. Centralised so each
     * test reads the container-built instance rather than constructing
     * a parallel service (which would miss the service provider's
     * keyring and TTL wiring).
     *
     * @return \SineMacula\Laravel\Authentication\Jwt\JwtTokenService
     */
    private function tokenService(): JwtTokenService
    {
        $app = $this->app;

        assert($app !== null);

        return $app->make(JwtTokenService::class);
    }

    /**
     * Bind a fresh Illuminate Request carrying the supplied JWT as a
     * `Bearer` token onto the container's `request` binding. The
     * service provider's `refresh('request', ...)` wiring propagates
     * the new request onto every previously-constructed guard, so
     * already-resolved guards pick up the swap automatically.
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
     * Swap the default guard config key and forget any cached guards
     * so the next `Auth::guard()` call builds the newly-defaulted
     * guard against the current request binding.
     *
     * @param  string  $name
     * @return void
     */
    private function switchDefaultGuard(string $name): void
    {
        config()->set('auth.defaults.guard', $name);

        PackageAuth::manager()->forgetGuards();
    }
}
