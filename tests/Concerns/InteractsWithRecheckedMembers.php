<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use Tests\Integration\Fixtures\ActivatableTenant;
use Tests\Integration\Fixtures\RecheckedMember;
use Tests\Integration\Fixtures\RecheckedMembership;

/**
 * A 3D guard (`rechecked`) over `RecheckedMember`, whose identities and
 * memberships can each be deactivated, soft-deleted and restored and record a
 * "tokens valid after" cutoff, acting within activatable tenants: the tables
 * behind it and seeded members. For tests that sign in through the session
 * service alongside `InteractsWithSessions`, which creates the tenants' table.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait InteractsWithRecheckedMembers
{
    /**
     * Register the `rechecked` guard and its provider.
     *
     * @param  \Illuminate\Config\Repository  $config
     * @return void
     */
    protected static function configureRecheckedGuard(ConfigRepository $config): void
    {
        $config->set('auth.providers.rechecked', ['driver' => 'model', 'model' => RecheckedMember::class]);
        $config->set('auth.guards.rechecked', ['driver' => 'jwt', 'provider' => 'rechecked', 'application' => ['methods' => ['password', 'sso']]]);
    }

    /**
     * Create the members' and memberships' tables.
     *
     * @return void
     */
    protected function createRecheckedTables(): void
    {
        Schema::create('rechecked_members', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('email')->unique();
            $blueprint->string('password');
            $blueprint->boolean('is_active')->default(true);
            $blueprint->dateTime('tokens_valid_after', 0)->nullable();
            $blueprint->timestamps();
            $blueprint->softDeletes();
        });

        Schema::create('rechecked_memberships', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->unsignedInteger('identity_id');
            $blueprint->unsignedInteger('tenant_id');
            $blueprint->boolean('is_active')->default(true);
            $blueprint->dateTime('tokens_valid_after', 0)->nullable();
            $blueprint->timestamps();
            $blueprint->softDeletes();
        });
    }

    /**
     * Drop the members' and memberships' tables.
     *
     * @return void
     */
    protected function dropRecheckedTables(): void
    {
        Schema::dropIfExists('rechecked_memberships');
        Schema::dropIfExists('rechecked_members');
    }

    /**
     * Persist an active member with one active membership in an active tenant.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  string  $email
     * @param  ?\Tests\Integration\Fixtures\ActivatableTenant  $tenant
     * @return array{0: \Tests\Integration\Fixtures\RecheckedMember, 1: \Tests\Integration\Fixtures\RecheckedMembership, 2: \Tests\Integration\Fixtures\ActivatableTenant}
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    protected function seedRechecked(string $email = 'rechecked@example.test', ?ActivatableTenant $tenant = null): array
    {
        $tenant ??= ActivatableTenant::query()->create(['name' => 'Tenant', 'is_active' => true]);

        $member = RecheckedMember::query()->create(['email' => $email, 'password' => app(Hasher::class)->make(self::PASSWORD), 'is_active' => true]);

        $membership = RecheckedMembership::query()->create(['identity_id' => $member->getKey(), 'tenant_id' => $tenant->getKey(), 'is_active' => true]);

        return [$member, $membership, $tenant];
    }
}
