<?php

declare(strict_types = 1);

namespace Benchmarks\Support;

use Illuminate\Database\Schema\Blueprint;

/**
 * Shared benchmark schema builder.
 *
 * Creates the tables the benchmark harnesses rely on, keyed by fixture shape,
 * skipping any table that already exists so repeated harness boots stay
 * idempotent.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class BenchSchema
{
    /**
     * Create an auto-incrementing identity table with credential columns.
     *
     * @param  string  $table
     * @return void
     */
    public static function ensureIdentityTable(string $table): void
    {
        self::ensureTable($table, static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('email')->unique();
            $blueprint->string('password');
            $blueprint->boolean('is_active')->default(true);
            $blueprint->timestamps();
        });
    }

    /**
     * Create the big-increments access-only identity table.
     *
     * @return void
     */
    public static function ensureAccessOnlyIdentityTable(): void
    {
        self::ensureTable('access_only_identities', static function (Blueprint $blueprint): void {
            $blueprint->id();
            $blueprint->string('email')->unique();
            $blueprint->string('password');
            $blueprint->timestamps();
        });
    }

    /**
     * Create the coexistence 3D principal table.
     *
     * @return void
     */
    public static function ensureCoexistPrincipalTable(): void
    {
        self::ensureTable('coexist_3d_principals', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->unsignedInteger('identity_id');
            $blueprint->string('name');
            $blueprint->boolean('is_active')->default(true);
            $blueprint->timestamps();
        });
    }

    /**
     * Create the tenant and tenant-scoped principal tables.
     *
     * @return void
     */
    public static function ensureTenantTables(): void
    {
        self::ensureTable('tenant_aware_3d_tenants', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('name');
            $blueprint->string('type');
            $blueprint->timestamps();
        });

        self::ensureTable('tenant_aware_3d_principals', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->unsignedInteger('identity_id');
            $blueprint->unsignedInteger('tenant_id');
            $blueprint->string('name');
            $blueprint->boolean('is_active')->default(true);
            $blueprint->timestamps();
        });
    }

    /**
     * Create the devices table.
     *
     * @return void
     */
    public static function ensureDeviceTable(): void
    {
        self::ensureTable('devices', static function (Blueprint $blueprint): void {
            $blueprint->uuid('id')->primary();
            $blueprint->string('authenticatable_type');
            $blueprint->string('authenticatable_id');
            $blueprint->index(['authenticatable_type', 'authenticatable_id']);
            $blueprint->string('os');
            $blueprint->string('refresh_key', 64)->nullable()->index();
            $blueprint->timestamp('revoked_at')->nullable();
            $blueprint->timestamp('last_logged_in_at')->nullable();
            $blueprint->timestamp('last_mfa_verified_at')->nullable();
            $blueprint->timestamps();
        });
    }

    /**
     * Create a table from its blueprint definition unless it already exists.
     *
     * @param  string  $table
     * @param  \Closure(\Illuminate\Database\Schema\Blueprint): void  $definition
     * @return void
     */
    private static function ensureTable(string $table, \Closure $definition): void
    {
        $schema = BenchDatabase::schema();

        if ($schema->hasTable($table)) {
            return;
        }

        $schema->create($table, $definition);
    }
}
