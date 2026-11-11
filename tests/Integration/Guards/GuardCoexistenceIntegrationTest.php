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
use SineMacula\Laravel\Authentication\AuthenticationServiceProvider;
use SineMacula\Laravel\Authentication\AuthManager;
use SineMacula\Laravel\Authentication\Contracts\ContextualGuard;
use SineMacula\Laravel\Authentication\Facades\Auth as PackageAuth;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Resolvers\DefaultPrincipalResolver;
use Tests\Integration\Fixtures\Coexist2dIdentity;
use Tests\Integration\Fixtures\Coexist3dIdentity;
use Tests\Integration\Fixtures\Coexist3dPrincipal;
use Tests\TestCase;

/**
 * A 2D guard and a 3D guard coexist in one application without sharing state.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(JwtGuard::class)]
#[CoversClass(AuthManager::class)]
#[CoversClass(AuthenticationServiceProvider::class)]
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
     * Freeze the clocks and create the fixture tables for both guards.
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
     * Drop the fixture tables and release the frozen clocks.
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
     * Each guard resolves its own token in its own mode without leaking state.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testBothGuardsAuthenticateInSameRunWithoutCrossContamination(): void
    {
        [$twoD, $threeDIdentity, $threeDPrincipal] = $this->seedFixtures();

        $twoDJwt   = PackageAuth::jwt(self::GUARD_2D);
        $threeDJwt = PackageAuth::jwt(self::GUARD_3D);

        $twoDToken   = $twoDJwt->issueAccessToken($twoD, $twoD, null, null)->reveal();
        $threeDToken = $threeDJwt->issueAccessToken($threeDIdentity, $threeDPrincipal, null, null)->reveal();

        $this->bindRequestWithBearer($twoDToken);

        $guard2d = PackageAuth::guard(self::GUARD_2D);

        self::assertInstanceOf(ContextualGuard::class, $guard2d);
        self::assertNotNull($guard2d->user());

        $resolved2d = $guard2d->identity();

        self::assertInstanceOf(Coexist2dIdentity::class, $resolved2d);
        self::assertSame($twoD->getKey(), $resolved2d->getKey());
        self::assertSame($resolved2d, $guard2d->principal(), 'In 2D mode the identity and principal must be the same model instance.');

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

        // `hasUser()` reads the bound state without resolving the new request.
        self::assertFalse($guard2d->hasUser());

        self::assertNotInstanceOf(Coexist2dIdentity::class, $guard3d->identity());
        self::assertNotInstanceOf(Coexist2dIdentity::class, $guard3d->principal());

        // Both guards share a signing key and the identifiers collide.
        self::assertNull($guard2d->identity());
        self::assertNull($guard2d->principal());

        self::assertNull($guard2d->id());
        self::assertSame($threeDIdentity->getKey(), $guard3d->id());
    }

    /**
     * `Auth::principal()` follows the default guard as it flips between modes.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testSwitchingDefaultGuardTo2dExposesCorrectContext(): void
    {
        [$twoD] = $this->seedFixtures();

        $jwtService = PackageAuth::jwt(self::GUARD_2D);

        $twoDToken = $jwtService->issueAccessToken($twoD, $twoD, null, null)->reveal();

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
     * `Auth::principal()` on a 3D default guard returns a distinct principal.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testSwitchingDefaultGuardTo3dExposesCorrectContext(): void
    {
        [, $threeDIdentity, $threeDPrincipal] = $this->seedFixtures();

        $jwtService = PackageAuth::jwt(self::GUARD_3D);

        $threeDToken = $jwtService->issueAccessToken($threeDIdentity, $threeDPrincipal, null, null)->reveal();

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
     * Configure the 2D and 3D guards with `api_2d` as the default.
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
     * Persist a 2D identity, a 3D identity and its active principal.
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
     * Bind a fresh request carrying the bearer token for resolved guards.
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
     * Switch the default guard and forget the cached guards.
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
