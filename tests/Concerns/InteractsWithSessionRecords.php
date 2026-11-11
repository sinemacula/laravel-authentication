<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use Carbon\CarbonInterface;
use Illuminate\Database\DatabaseManager;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Schema;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Exceptions\TenantUnavailableException;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use SineMacula\Laravel\Authentication\Support\PrincipalReference;
use Tests\Fixtures\Database\ShippedMigrations;

/**
 * Shared session helpers for test cases that create session tables and rows.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait InteractsWithSessionRecords
{
    /**
     * A session of the guard that starts now with the default lifetimes, acting
     * as the principal when one is given.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  string  $guard
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @return array<string, mixed>
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    protected static function liveSession(string $guard = 'api', ?Principal $principal = null): array
    {
        $session = self::sessionEndingAt(Carbon::now()->addDays(90), Carbon::now()->addDays(180), $guard);

        return $principal === null ? $session : [...$session, ...self::recordedPrincipal($principal)];
    }

    /**
     * The session columns that record the principal a session acts as, as the
     * session service writes them at sign-in.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @return array{principal_type: string, principal_id: ?string, tenant_id: ?string, switched_at: null}
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    protected static function recordedPrincipal(Principal $principal): array
    {
        try {
            $tenant = $principal->getTenant();
        } catch (TenantUnavailableException) {
            $tenant = null;
        }

        return [
            'principal_type' => PrincipalReference::type($principal),
            'principal_id'   => PrincipalReference::id($principal),
            'tenant_id'      => IdentifierCoercion::stringify($tenant?->getTenantIdentifier()),
            'switched_at'    => null,
        ];
    }

    /**
     * An active session of the guard, signed in with a password now, acting in
     * no tenant, never switched, that ends at the given times.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  \Carbon\CarbonInterface  $idle
     * @param  \Carbon\CarbonInterface  $absolute
     * @param  string  $guard
     * @return array{guard: string, sign_in_method: string, status: string, tenant_id: null, switched_at: null, signed_in_at: \Carbon\CarbonInterface, idle_expires_at: \Carbon\CarbonInterface, absolute_expires_at: \Carbon\CarbonInterface}
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    protected static function sessionEndingAt(CarbonInterface $idle, CarbonInterface $absolute, string $guard = 'api'): array
    {
        return [
            'guard'               => $guard,
            'sign_in_method'      => 'password',
            'status'              => 'active',
            'tenant_id'           => null,
            'switched_at'         => null,
            'signed_in_at'        => Carbon::now(),
            'idle_expires_at'     => $idle,
            'absolute_expires_at' => $absolute,
        ];
    }

    /**
     * Create the one-time codes table on the connection with the shipped
     * migration.
     *
     * @param  string  $connection
     * @return void
     */
    protected static function createCodeTableOn(string $connection): void
    {
        $manager = app(DatabaseManager::class);
        $default = $manager->getDefaultConnection();

        $manager->setDefaultConnection($connection);

        try {
            ShippedMigrations::up('2026_04_06_000003_create_one_time_codes_table.php');
        } finally {
            $manager->setDefaultConnection($default);
        }
    }

    /**
     * Create a session table with every column of the shipped migration, the
     * owner and deadlines nullable.
     *
     * @param  string  $table
     * @param  string  $key
     * @param  ?string  $connection
     * @param  bool  $incrementing
     * @param  bool  $stringKey
     * @return void
     */
    protected static function createSessionRecordTable(string $table, string $key = 'id', ?string $connection = null, bool $incrementing = false, bool $stringKey = false): void
    {
        Schema::connection($connection)->create($table, static function (Blueprint $blueprint) use ($key, $incrementing, $stringKey): void {
            if ($incrementing) {
                $blueprint->increments($key);
            } elseif ($stringKey) {
                $blueprint->string($key)->primary();
            } else {
                $blueprint->uuid($key)->primary();
            }

            $blueprint->uuid('generation')->nullable();
            $blueprint->string('authenticatable_type')->nullable();
            $blueprint->string('authenticatable_id')->nullable();
            $blueprint->string('principal_type')->nullable();
            $blueprint->string('principal_id')->nullable();
            $blueprint->string('status', 16)->default('active');
            $blueprint->string('requires', 64)->nullable();
            $blueprint->string('pending_key', 64)->nullable();
            $blueprint->string('supersedes_session_id')->nullable();
            $blueprint->string('supersedes_refresh_key', 64)->nullable();
            $blueprint->text('attempt_windows')->nullable();
            $blueprint->string('tenant_id')->nullable();
            $blueprint->string('tenant_policy_version', 64)->nullable();
            $blueprint->dateTime('switched_at', 0)->nullable();
            $blueprint->unsignedBigInteger('issuance_sequence')->default(0);
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
            $blueprint->dateTime('signed_in_at', 0)->nullable();
            $blueprint->dateTime('idle_expires_at', 0)->nullable();
            $blueprint->dateTime('absolute_expires_at', 0)->nullable();
            $blueprint->dateTime('revoked_at', 0)->nullable();
            $blueprint->string('revoked_reason', 64)->nullable();
            $blueprint->datetimes(0);
        });
    }
}
