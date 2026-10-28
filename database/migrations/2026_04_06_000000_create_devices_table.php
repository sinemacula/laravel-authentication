<?php

declare(strict_types = 1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Schema;
use SineMacula\Laravel\Authentication\Database\MigrationCollisionGuard;

/**
 * Create the devices table.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */

return new class extends Migration {
    /**
     * Run the migrations.
     *
     * @return void
     *
     * @throws \RuntimeException
     */
    public function up(): void
    {
        $table = Config::string('authentication.device.table', 'devices');

        $schema = Schema::getConnection()->getSchemaBuilder();

        (new MigrationCollisionGuard($schema))->ensureNotExists($table, 'device.table');

        Schema::create($table, static function (Blueprint $blueprint): void {
            $blueprint->uuid('id')->primary();

            // Plain string polymorphic columns so the table works against
            // integer, UUID, or ULID keys. `morphs()` would pin the id to
            // unsignedBigInteger and break non-integer keys.
            $blueprint->string('authenticatable_type');
            $blueprint->string('authenticatable_id');
            $blueprint->string('principal_type')->nullable();
            $blueprint->string('principal_id')->nullable();

            // When the session last switched the principal it acts as: access
            // tokens issued before it are rejected, so a switch back to an
            // earlier principal does not revive that principal's old tokens.
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

            // SHA-256 hex digests of the current and the immediately previous
            // refresh rotation ids. Not indexed: a device is always found by
            // its primary key and its digest compared in constant time.
            $blueprint->string('refresh_key', 64)->nullable();
            $blueprint->string('previous_refresh_key', 64)->nullable();

            // Every time is a whole-second `dateTime`. Whole seconds because
            // the refresh rotation compares the stored deadlines by equality,
            // which a fractional part the application never wrote would
            // break; `dateTime` because MySQL's `timestamp` ends in January
            // 2038, before the longest session lifetime the package accepts.
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

            // Separate single-column indexes so each condition of a pruning
            // query that matches either deadline or the revocation time can use
            // its own index.
            $blueprint->index('idle_expires_at');
            $blueprint->index('absolute_expires_at');
            $blueprint->index('revoked_at');
        });
    }

    /**
     * Reverse the migrations.
     *
     * @return void
     */
    public function down(): void
    {
        $table = Config::string('authentication.device.table', 'devices');

        Schema::dropIfExists($table);
    }
};
