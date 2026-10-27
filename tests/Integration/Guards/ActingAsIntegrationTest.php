<?php

declare(strict_types = 1);

namespace Tests\Integration\Guards;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Guards\AbstractGuard;
use Tests\Integration\Fixtures\ActivatableTenant;
use Tests\Integration\Fixtures\ActivatableTenantMember;
use Tests\Integration\Fixtures\ActivatableTenantMembership;
use Tests\TestCase;

/**
 * Laravel's `actingAs()` binds through `setUser()`, so it yields the acting
 * identity's default principal, and switching to another identity replaces the
 * principal instead of keeping the previous identity's.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AbstractGuard::class)]
final class ActingAsIntegrationTest extends TestCase
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
     * Acting as one member and then another binds each member's own default
     * membership and tenant.
     *
     * @return void
     */
    public function testActingAsBindsEachIdentitysDefaultPrincipal(): void
    {
        [$first, $firstMembership]   = $this->seedMember('first@example.test');
        [$second, $secondMembership] = $this->seedMember('second@example.test');

        $this->actingAs($first, 'api');

        self::assertSame($first->getKey(), Auth::identity()?->getAuthIdentifier());
        self::assertSame($firstMembership->getKey(), Auth::principal()?->getPrincipalIdentifier());
        self::assertSame($firstMembership->tenant_id, $this->actingTenantIdentifier());

        $this->actingAs($second, 'api');

        self::assertSame($second->getKey(), Auth::identity()?->getAuthIdentifier());
        self::assertSame($secondMembership->getKey(), Auth::principal()?->getPrincipalIdentifier());
        self::assertSame($secondMembership->tenant_id, $this->actingTenantIdentifier());
        self::assertNull(Auth::device());
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
     * Return the identifier of the tenant the acting principal acts within.
     *
     * @return mixed
     */
    private function actingTenantIdentifier(): mixed
    {
        return Auth::tenant()?->getTenantIdentifier();
    }

    /**
     * Persist a member with one membership in its own tenant.
     *
     * @param  string  $email
     * @return array{0: \Tests\Integration\Fixtures\ActivatableTenantMember, 1: \Tests\Integration\Fixtures\ActivatableTenantMembership}
     */
    private function seedMember(string $email): array
    {
        $tenant = new ActivatableTenant;
        $tenant->forceFill(['name' => $email, 'is_active' => true])->save();

        $member = new ActivatableTenantMember;
        $member->forceFill(['email' => $email, 'password' => 'irrelevant'])->save();

        $membership = new ActivatableTenantMembership;
        $membership->forceFill(['identity_id' => $member->getKey(), 'tenant_id' => $tenant->getKey()])->save();

        return [$member, $membership];
    }
}
