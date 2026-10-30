<?php

declare(strict_types = 1);

namespace Benchmarks\Support;

use Carbon\Carbon;
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
            self::defineDeviceColumns($blueprint);
        });
    }

    /**
     * Define the columns and indexes of the shipped devices migration.
     *
     * @param  \Illuminate\Database\Schema\Blueprint  $blueprint
     * @return void
     */
    public static function defineDeviceColumns(Blueprint $blueprint): void
    {
        $blueprint->uuid('id')->primary();
        $blueprint->string('authenticatable_type')->nullable();
        $blueprint->string('authenticatable_id')->nullable();
        $blueprint->string('principal_type')->nullable();
        $blueprint->string('principal_id')->nullable();
        $blueprint->dateTime('principal_switched_at', 0)->nullable();
        $blueprint->string('guard')->nullable();
        $blueprint->string('sign_in_method')->nullable();
        $blueprint->string('sign_in_identifier_type')->nullable();
        $blueprint->string('client_name')->nullable();
        $blueprint->string('platform')->nullable();
        $blueprint->string('created_ip', 45)->nullable();
        $blueprint->string('created_user_agent', 512)->nullable();
        $blueprint->dateTime('last_used_at', 0)->nullable();
        $blueprint->string('last_used_ip', 45)->nullable();
        $blueprint->string('last_used_user_agent', 512)->nullable();
        $blueprint->string('refresh_key', 64)->nullable();
        $blueprint->string('previous_refresh_key', 64)->nullable();
        $blueprint->dateTime('refresh_rotated_at', 0)->nullable();
        $blueprint->dateTime('signed_in_at', 0);
        $blueprint->dateTime('idle_expires_at', 0);
        $blueprint->dateTime('absolute_expires_at', 0);
        $blueprint->dateTime('revoked_at', 0)->nullable();
        $blueprint->string('revoked_reason', 64)->nullable();
        $blueprint->datetimes(0);
        $blueprint->index(['authenticatable_type', 'authenticatable_id']);
        $blueprint->index(['principal_type', 'principal_id']);
        $blueprint->index('guard');
        $blueprint->index('idle_expires_at');
        $blueprint->index('absolute_expires_at');
        $blueprint->index('revoked_at');
    }

    /**
     * Create the machine client table: a non-human identity that acts as its
     * own principal.
     *
     * @return void
     */
    public static function ensureMachineClientTable(): void
    {
        self::ensureTable('machine_clients', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('email')->unique();
            $blueprint->string('password')->nullable();
            $blueprint->boolean('is_active')->default(true);
            $blueprint->timestamps();
        });
    }

    /**
     * Create the table of identities that sign in by a one-time code sent to
     * their phone number or email address.
     *
     * @return void
     */
    public static function ensureCodeIdentityTable(): void
    {
        self::ensureTable('code_identities', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('phone')->nullable()->unique();
            $blueprint->dateTime('phone_verified_at', 0)->nullable();
            $blueprint->string('email')->nullable()->unique();
            $blueprint->dateTime('email_verified_at', 0)->nullable();
            $blueprint->string('password')->nullable();
            $blueprint->boolean('is_active')->default(true);
            $blueprint->datetimes(0);
        });
    }

    /**
     * Create the API keys table, as the shipped migration does.
     *
     * @return void
     */
    public static function ensureApiKeyTable(): void
    {
        self::ensureTable('api_keys', static function (Blueprint $blueprint): void {
            $blueprint->uuid('id')->primary();
            $blueprint->string('public_id', 64)->unique();
            $blueprint->char('secret_hash', 64);
            $blueprint->string('guard');
            $blueprint->string('name')->nullable();
            $blueprint->string('authenticatable_type');
            $blueprint->string('authenticatable_id');
            $blueprint->string('principal_type');
            $blueprint->string('principal_id');
            $blueprint->string('tenant_type')->nullable();
            $blueprint->string('tenant_id')->nullable();
            $blueprint->text('scopes');
            $blueprint->dateTime('expires_at', 0)->nullable();
            $blueprint->dateTime('last_used_at', 0)->nullable();
            $blueprint->dateTime('rotated_at', 0)->nullable();
            $blueprint->uuid('replaced_by')->nullable();
            $blueprint->dateTime('revoked_at', 0)->nullable();
            $blueprint->datetimes(0);
            $blueprint->index(['authenticatable_type', 'authenticatable_id']);
            $blueprint->index(['principal_type', 'principal_id']);
        });
    }

    /**
     * Create the attempt limiter's counters table, as the shipped migration
     * does.
     *
     * @return void
     */
    public static function ensureRateLimitTable(): void
    {
        self::ensureTable('rate_limits', static function (Blueprint $blueprint): void {
            $blueprint->char('key', 64)->primary();
            $blueprint->unsignedInteger('hits');
            $blueprint->dateTime('window_ends_at', 0)->index();
        });
    }

    /**
     * Create the one-time codes table, as the shipped migration does.
     *
     * @return void
     */
    public static function ensureOneTimeCodeTable(): void
    {
        self::ensureTable('one_time_codes', static function (Blueprint $blueprint): void {
            $blueprint->char('id', 64)->primary();
            $blueprint->string('purpose', 32);
            $blueprint->string('guard');
            $blueprint->uuid('issue_id');
            $blueprint->char('code_hash', 64);
            $blueprint->unsignedSmallInteger('attempts');
            $blueprint->dateTime('issued_at', 0);
            $blueprint->dateTime('expires_at', 0)->index();
            $blueprint->dateTime('consumed_at', 0)->nullable();
        });
    }

    /**
     * The start and deadlines of a session that starts now, with the package's
     * default lifetimes.
     *
     * @return array{signed_in_at: \Carbon\CarbonInterface, idle_expires_at: \Carbon\CarbonInterface, absolute_expires_at: \Carbon\CarbonInterface}
     */
    public static function liveSession(): array
    {
        return [
            'signed_in_at'        => Carbon::now(),
            'idle_expires_at'     => Carbon::now()->addDays(90),
            'absolute_expires_at' => Carbon::now()->addDays(180),
        ];
    }

    /**
     * A session the guard's password sign-in started now: the guard and method
     * a device records, which refresh and the bearer path check, with the
     * deadlines of `liveSession()`.
     *
     * @param  string  $guard
     * @return array{idle_expires_at: \Carbon\CarbonInterface, absolute_expires_at: \Carbon\CarbonInterface, guard: string, sign_in_method: string}
     */
    public static function signedIn(string $guard): array
    {
        return [...self::liveSession(), 'guard' => $guard, 'sign_in_method' => 'password'];
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
