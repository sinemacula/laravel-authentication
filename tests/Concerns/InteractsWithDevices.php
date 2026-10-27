<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use Carbon\CarbonInterface;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Schema;

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
     * The deadlines of a session that starts now, with the package's default
     * lifetimes (90 days idle, 180 days absolute).
     *
     * @return array{idle_expires_at: \Carbon\CarbonInterface, absolute_expires_at: \Carbon\CarbonInterface}
     */
    protected static function liveSession(): array
    {
        return self::sessionEndingAt(Carbon::now()->addDays(90), Carbon::now()->addDays(180));
    }

    /**
     * The deadlines of a session that ends at the given times.
     *
     * @param  \Carbon\CarbonInterface  $idle
     * @param  \Carbon\CarbonInterface  $absolute
     * @return array{idle_expires_at: \Carbon\CarbonInterface, absolute_expires_at: \Carbon\CarbonInterface}
     */
    protected static function sessionEndingAt(CarbonInterface $idle, CarbonInterface $absolute): array
    {
        return [
            'idle_expires_at'     => $idle,
            'absolute_expires_at' => $absolute,
        ];
    }

    /**
     * Create a device table with every column of the shipped migration. The
     * owner and both deadlines are nullable, unlike the shipped table, so tests
     * can store a device without an owner or a session.
     *
     * @param  string  $table
     * @param  string  $key
     * @return void
     */
    protected static function createDeviceTable(string $table, string $key = 'id'): void
    {
        Schema::create($table, static function (Blueprint $blueprint) use ($key): void {
            $blueprint->uuid($key)->primary();
            $blueprint->string('authenticatable_type')->nullable();
            $blueprint->string('authenticatable_id')->nullable();
            $blueprint->string('principal_type')->nullable();
            $blueprint->string('principal_id')->nullable();
            $blueprint->string('guard')->nullable();
            $blueprint->string('sign_in_method')->nullable();
            $blueprint->string('client_name')->nullable();
            $blueprint->string('platform')->nullable();
            $blueprint->string('created_ip', 45)->nullable();
            $blueprint->string('created_user_agent', 512)->nullable();
            $blueprint->timestamp('last_used_at', 0)->nullable();
            $blueprint->string('last_used_ip', 45)->nullable();
            $blueprint->string('last_used_user_agent', 512)->nullable();
            $blueprint->string('refresh_key', 64)->nullable();
            $blueprint->string('previous_refresh_key', 64)->nullable();
            $blueprint->timestamp('refresh_rotated_at', 0)->nullable();
            $blueprint->timestamp('idle_expires_at', 0)->nullable();
            $blueprint->timestamp('absolute_expires_at', 0)->nullable();
            $blueprint->timestamp('revoked_at', 0)->nullable();
            $blueprint->string('revoked_reason', 64)->nullable();
            $blueprint->timestamps(0);
        });
    }
}
