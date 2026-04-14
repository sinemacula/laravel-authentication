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
        $table            = Config::string('authentication.device.table', 'devices');
        $refreshKeyColumn = Config::string('authentication.device.refresh_key_column', 'refresh_key');

        $schema = Schema::getConnection()->getSchemaBuilder();

        (new MigrationCollisionGuard($schema))->ensureNotExists($table);

        Schema::create($table, static function (Blueprint $blueprint) use ($refreshKeyColumn): void {
            $blueprint->uuid('id')->primary();

            // Plain string polymorphic columns so the table works against
            // integer, UUID, or ULID identity keys. `morphs()` would pin the id
            // to unsignedBigInteger and break non-integer keys.
            $blueprint->string('authenticatable_type');
            $blueprint->string('authenticatable_id');
            $blueprint->index(['authenticatable_type', 'authenticatable_id']);

            $blueprint->string('os');

            // SHA-256 hex digest of the refresh token's `jti` claim for the
            // package's default Eloquent device adapter. Nullable so a device
            // can exist pre-issuance or post-revocation. Indexed but not
            // unique: revocation sets a family to one sentinel.
            $blueprint->string($refreshKeyColumn, 64)->nullable()->index();

            // Revocation marker. Set by the reuse-detection CAS path and
            // consumer-initiated logout-everywhere flows; non-null rejects any
            // refresh with reason `device_revoked`.
            $blueprint->timestamp('revoked_at')->nullable();

            $blueprint->timestamp('last_logged_in_at')->nullable();
            $blueprint->timestamp('last_mfa_verified_at')->nullable();
            $blueprint->timestamps();
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
