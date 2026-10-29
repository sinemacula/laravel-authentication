<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use Carbon\CarbonInterface;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Schema;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Sessions\PrincipalReference;

/**
 * Shared device helpers for test cases that create device tables and rows.
 *
 * A trait rather than a base-class method because the device tests extend
 * different base cases (plain Testbench and the package `TestCase`).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait InteractsWithDevices
{
    /**
     * A session of the guard that starts now, signed in with a password, with
     * the package's default lifetimes (90 days idle, 180 days absolute), acting
     * as the principal when one is given (a bearer token naming the device is
     * accepted only for the principal the device records).
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
     * The device columns that record the principal a session acts as, as the
     * session service writes them at sign-in: the principal, and no switch.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @return array{principal_type: string, principal_id: ?string, principal_switched_at: null}
     */
    protected static function recordedPrincipal(Principal $principal): array
    {
        return ['principal_type' => PrincipalReference::type($principal), 'principal_id' => PrincipalReference::id($principal), 'principal_switched_at' => null];
    }

    /**
     * A session of the guard, signed in with a password now, that ends at the
     * given times.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  \Carbon\CarbonInterface  $idle
     * @param  \Carbon\CarbonInterface  $absolute
     * @param  string  $guard
     * @return array{guard: string, sign_in_method: string, signed_in_at: \Carbon\CarbonInterface, idle_expires_at: \Carbon\CarbonInterface, absolute_expires_at: \Carbon\CarbonInterface}
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
            'signed_in_at'        => Carbon::now(),
            'idle_expires_at'     => $idle,
            'absolute_expires_at' => $absolute,
        ];
    }

    /**
     * Create a device table with every column of the shipped migration. The
     * owner and both deadlines are nullable, unlike the shipped table, so tests
     * can store a device without an owner or a session. The table is created on
     * the given connection, or the default one.
     *
     * @param  string  $table
     * @param  string  $key
     * @param  ?string  $connection
     * @return void
     */
    protected static function createDeviceTable(string $table, string $key = 'id', ?string $connection = null): void
    {
        Schema::connection($connection)->create($table, static function (Blueprint $blueprint) use ($key): void {
            $blueprint->uuid($key)->primary();
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
            $blueprint->dateTime('signed_in_at', 0)->nullable();
            $blueprint->dateTime('idle_expires_at', 0)->nullable();
            $blueprint->dateTime('absolute_expires_at', 0)->nullable();
            $blueprint->dateTime('revoked_at', 0)->nullable();
            $blueprint->string('revoked_reason', 64)->nullable();
            $blueprint->datetimes(0);
        });
    }
}
