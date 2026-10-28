<?php

declare(strict_types = 1);

namespace Tests\Integration\Guards;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Authentication\AuthManager;
use SineMacula\Laravel\Authentication\Concerns\ActsAsPrincipal;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Guards\ActivationPolicy;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use Tests\Integration\Fixtures\PlainTeam;
use Tests\Integration\Fixtures\PlainTeamUser;
use Tests\Integration\Fixtures\TenantAware3dTenant;
use Tests\Integration\Fixtures\UncheckedTenantUser;
use Tests\TestCase;

/**
 * Tenant checks are opt-in: only a tenant whose model implements both `Tenant`
 * and `CanBeActive` is checked. A user whose `tenant` relation points at an
 * ordinary model, or at a `Tenant` that does not opt in, signs in and
 * authenticates bearer requests whether or not that row still exists.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ActivationPolicy::class)]
#[CoversTrait(ActsAsPrincipal::class)]
final class TenantOptInIntegrationTest extends TestCase
{
    /** @var string Plaintext password of the seeded users. */
    private const string PASSWORD = 'correct horse battery staple';

    /**
     * Create the team, tenant, and user tables.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        Schema::create('plain_teams', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('name');
            $blueprint->timestamps();
        });

        Schema::create('plain_team_users', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('email')->unique();
            $blueprint->string('password');
            $blueprint->unsignedInteger('team_id');
            $blueprint->timestamps();
        });

        Schema::create('tenant_aware_3d_tenants', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('name');
            $blueprint->string('type');
            $blueprint->timestamps();
        });

        Schema::create('unchecked_tenant_users', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('email')->unique();
            $blueprint->string('password');
            $blueprint->unsignedInteger('tenant_id');
            $blueprint->timestamps();
        });
    }

    /**
     * Drop the fixture tables.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Schema::dropIfExists('unchecked_tenant_users');
        Schema::dropIfExists('tenant_aware_3d_tenants');
        Schema::dropIfExists('plain_team_users');
        Schema::dropIfExists('plain_teams');

        parent::tearDown();
    }

    /**
     * A user whose `tenant` relation returns an ordinary team acts within no
     * tenant: it signs in, its bearer token authenticates, and the guard
     * reports no tenant.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testUserWhoseTenantRelationIsNotATenantActsWithinNoTenant(): void
    {
        $team = new PlainTeam;
        $team->forceFill(['name' => 'Team'])->save();

        $user = $this->seedUser(new PlainTeamUser, ['team_id' => $team->getKey()]);

        $this->assertSignsInAndAuthenticates('teams', $user);
    }

    /**
     * A user whose team has been deleted still signs in and authenticates: an
     * ordinary model is never checked.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testUserWhoseTeamIsDeletedStillSignsIn(): void
    {
        $team = new PlainTeam;
        $team->forceFill(['name' => 'Team'])->save();

        $user = $this->seedUser(new PlainTeamUser, ['team_id' => $team->getKey()]);

        $team->delete();

        $this->assertSignsInAndAuthenticates('teams', $user);
    }

    /**
     * A user whose tenant does not implement `CanBeActive` still signs in and
     * authenticates after that tenant is deleted: only a tenant that opts in is
     * checked.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testUserWhoseNonActivatableTenantIsDeletedStillSignsIn(): void
    {
        $tenant = new TenantAware3dTenant;
        $tenant->forceFill(['name' => 'Tenant', 'type' => 'staff'])->save();

        $user = $this->seedUser(new UncheckedTenantUser, ['tenant_id' => $tenant->getKey()]);

        $tenant->delete();

        $this->assertSignsInAndAuthenticates('unchecked', $user);
    }

    /**
     * Configure one JWT guard per user model.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        /** @var \Illuminate\Config\Repository $config */
        $config = app(ConfigRepository::class);

        $config->set('auth.guards.teams', ['driver' => 'jwt', 'provider' => 'teams']);
        $config->set('auth.providers.teams', ['driver' => 'model', 'model' => PlainTeamUser::class]);

        $config->set('auth.guards.unchecked', ['driver' => 'jwt', 'provider' => 'unchecked']);
        $config->set('auth.providers.unchecked', ['driver' => 'model', 'model' => UncheckedTenantUser::class]);

        // Failed attempts wait out the timebox; keep it short.
        $config->set('authentication.timebox.credentials_microseconds', 1);
    }

    /**
     * Persist the user with a hashed password and the supplied attributes.
     *
     * @template TUser of \Tests\Integration\Fixtures\PlainTeamUser|\Tests\Integration\Fixtures\UncheckedTenantUser
     *
     * @param  TUser  $user
     * @param  array<string, mixed>  $attributes
     * @return TUser
     */
    private function seedUser(Model $user, array $attributes): Model
    {
        $user->forceFill([
            'email'    => 'user@example.test',
            'password' => app(Hasher::class)->make(self::PASSWORD),
            ...$attributes,
        ])->save();

        return $user;
    }

    /**
     * Assert the user signs in on the guard with no tenant bound, and that an
     * access token issued to it authenticates a bearer request.
     *
     * @param  string  $guardName
     * @param  \Tests\Integration\Fixtures\PlainTeamUser|\Tests\Integration\Fixtures\UncheckedTenantUser  $user
     * @return void
     *
     * @throws \Throwable
     */
    private function assertSignsInAndAuthenticates(string $guardName, PlainTeamUser|UncheckedTenantUser $user): void
    {
        $guard = $this->guardForRequest(Request::create('/sign-in', 'POST'), $guardName);

        self::assertTrue($guard->attempt(['email' => 'user@example.test', 'password' => self::PASSWORD]));
        self::assertNull($guard->tenant());

        $token = $this->authManager()->jwt($guardName)->issueAccessToken($user, $user, null);
        $guard = $this->guardForRequest(Request::create('/me', 'GET', server: ['HTTP_AUTHORIZATION' => 'Bearer ' . $token]), $guardName);

        self::assertInstanceOf(Identity::class, $guard->user());
        self::assertTrue($user->is($guard->user()));
    }

    /**
     * Resolve the package auth manager with no cached guards.
     *
     * @return \SineMacula\Laravel\Authentication\AuthManager
     */
    private function authManager(): AuthManager
    {
        $manager = app('auth');

        assert($manager instanceof AuthManager);

        $manager->forgetGuards();

        return $manager;
    }

    /**
     * Resolve a fresh JWT guard bound to the supplied request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  string  $name
     * @return \SineMacula\Laravel\Authentication\Guards\JwtGuard
     */
    private function guardForRequest(Request $request, string $name): JwtGuard
    {
        app()->instance('request', $request);

        $guard = $this->authManager()->guard($name);

        assert($guard instanceof JwtGuard);

        return $guard;
    }
}
