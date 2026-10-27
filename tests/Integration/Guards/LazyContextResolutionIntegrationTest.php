<?php

declare(strict_types = 1);

namespace Tests\Integration\Guards;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\AuthManager;
use SineMacula\Laravel\Authentication\Guards\AbstractGuard;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Models\Device;
use Tests\Integration\Fixtures\ActivatableTenant;
use Tests\Integration\Fixtures\ActivatableTenantMember;
use Tests\Integration\Fixtures\ActivatableTenantMembership;
use Tests\TestCase;

/**
 * On a route without authentication middleware, the first call to `Auth::id()`
 * or to any contextual accessor resolves the bearer token, as Laravel's own
 * guards do, instead of returning `null` until something calls `user()`. A
 * principal or device pinned before that first access stays pinned.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AbstractGuard::class)]
#[CoversClass(JwtGuard::class)]
final class LazyContextResolutionIntegrationTest extends TestCase
{
    /**
     * Create the tenant, member, and membership tables.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        Schema::create('activatable_tenants', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('name');
            $blueprint->boolean('is_active')->default(true);
            $blueprint->timestamps();
        });

        Schema::create('activatable_tenant_members', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('email')->unique();
            $blueprint->string('password');
            $blueprint->timestamps();
        });

        Schema::create('activatable_tenant_memberships', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->unsignedInteger('identity_id');
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
        Schema::dropIfExists('activatable_tenant_memberships');
        Schema::dropIfExists('activatable_tenant_members');
        Schema::dropIfExists('activatable_tenants');

        parent::tearDown();
    }

    /**
     * Data provider of each accessor called first on the request.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideAccessors(): iterable
    {
        yield from [
            'id'        => ['id'],
            'identity'  => ['identity'],
            'principal' => ['principal'],
            'device'    => ['device'],
            'tenant'    => ['tenant'],
        ];
    }

    /**
     * The accessor, called first on a route without `auth` middleware, returns
     * the value carried by the bearer token.
     *
     * @param  string  $accessor
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[DataProvider('provideAccessors')]
    public function testAccessorResolvesBearerTokenWhenCalledFirst(string $accessor): void
    {
        [$member, $membership, $tenant, $device] = $this->seedContext();

        $manager = app('auth');

        assert($manager instanceof AuthManager);

        $token = $manager->jwt('api')->issueAccessToken($member, $membership, $device);

        Route::get('/first-call', static function () use ($accessor): array {

            $manager = app('auth');

            assert($manager instanceof AuthManager);

            return ['value' => match ($accessor) {
                'id'        => $manager->id(),
                'identity'  => $manager->identity()?->getAuthIdentifier(),
                'principal' => $manager->principal()?->getPrincipalIdentifier(),
                'device'    => $manager->device()?->getDeviceIdentifier(),
                default     => $manager->tenant()?->getTenantIdentifier(),
            }];
        });

        $expected = [
            'id'        => $member->getKey(),
            'identity'  => $member->getKey(),
            'principal' => $membership->getKey(),
            'device'    => $device->getKey(),
            'tenant'    => $tenant->getKey(),
        ];

        $this->withHeaders(['Authorization' => 'Bearer ' . $token])->getJson('/first-call')
            ->assertOk()
            ->assertExactJson(['value' => $expected[$accessor]]);
    }

    /**
     * A principal and device pinned on a route without `auth` middleware,
     * before anything resolved the request, stay pinned: the bearer token is
     * resolved first and the pins replace its principal and device.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testPinsSetBeforeFirstAccessAreNotReplacedByTheBearerToken(): void
    {
        [$member, $membership, $tenant, $device] = $this->seedContext();

        $otherMembership = new ActivatableTenantMembership;
        $otherMembership->forceFill(['identity_id' => $member->getKey(), 'tenant_id' => $tenant->getKey()])->save();

        $otherDevice = $device->replicate();
        $otherDevice->save();

        $manager = app('auth');

        assert($manager instanceof AuthManager);

        $token = $manager->jwt('api')->issueAccessToken($member, $membership, $device);

        Route::get('/pin-first', static function () use ($otherMembership, $otherDevice): array {

            $guard = app('auth')->guard('api');

            assert($guard instanceof JwtGuard);

            $guard->setPrincipal($otherMembership)->setDevice($otherDevice);

            return [
                'identity'  => $guard->identity()?->getAuthIdentifier(),
                'principal' => $guard->principal()?->getPrincipalIdentifier(),
                'device'    => $guard->device()?->getDeviceIdentifier(),
            ];
        });

        $this->withHeaders(['Authorization' => 'Bearer ' . $token])->getJson('/pin-first')
            ->assertOk()
            ->assertExactJson([
                'identity'  => $member->getKey(),
                'principal' => $otherMembership->getKey(),
                'device'    => $otherDevice->getKey(),
            ]);
    }

    /**
     * Configure the JWT guard against the member provider.
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

        $config->set('auth.defaults.guard', 'api');

        $config->set('auth.guards.api', [
            'driver'   => 'jwt',
            'provider' => 'members',
        ]);

        $config->set('auth.providers.members', [
            'driver' => 'model',
            'model'  => ActivatableTenantMember::class,
        ]);
    }

    /**
     * Persist a member with a membership in a tenant and a device.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @return array{0: \Tests\Integration\Fixtures\ActivatableTenantMember, 1: \Tests\Integration\Fixtures\ActivatableTenantMembership, 2: \Tests\Integration\Fixtures\ActivatableTenant, 3: \SineMacula\Laravel\Authentication\Models\Device}
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    private function seedContext(): array
    {
        $tenant = new ActivatableTenant;
        $tenant->forceFill(['name' => 'Tenant', 'is_active' => true])->save();

        $member = new ActivatableTenantMember;
        $member->forceFill(['email' => 'member@example.test', 'password' => 'irrelevant'])->save();

        $membership = new ActivatableTenantMembership;
        $membership->forceFill(['identity_id' => $member->getKey(), 'tenant_id' => $tenant->getKey()])->save();

        $device = new Device;
        $device->forceFill([
            'authenticatable_type' => ActivatableTenantMember::class,
            'authenticatable_id'   => (string) $member->getKey(), // @phpstan-ignore cast.string
            'os'                   => 'ios',
        ])->save();

        return [$member, $membership, $tenant, $device];
    }
}
