<?php

declare(strict_types = 1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Schema;
use SineMacula\Laravel\Authentication\Database\MigrationCollisionGuard;

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
        $table            = Config::string('laravel-authentication.device.table', 'devices');
        $refreshKeyColumn = Config::string('laravel-authentication.device.refresh_key_column', 'refresh_key');

        $schema = Schema::getConnection()->getSchemaBuilder();

        (new MigrationCollisionGuard($schema))->ensureNotExists($table);

        Schema::create($table, static function (Blueprint $blueprint) use ($refreshKeyColumn): void {
            $blueprint->ulid('id')->primary();

            // Polymorphic relation columns + composite index. `morphs()` is
            // deliberate: it picks the right id column width for string/int
            // identity keys and indexes (type, id) in one step, which is the
            // query shape the guard issues.
            $blueprint->morphs('authenticatable');

            $blueprint->string('os');
            // SHA-256 hex digest (64 characters) of the plaintext rotation
            // identifier embedded in the refresh token's `jti` claim. Nullable
            // so a device row can exist before the first refresh credential is
            // issued and so a revoked device can have its credential cleared
            // without colliding on the old unique index. Indexed but NOT unique
            // — revoking a family of devices to the same sentinel would
            // otherwise fail the uniqueness check, and a SHA-256 collision is
            // not a realistic concern for the `did → device` primary-key lookup
            // path.
            $blueprint->string($refreshKeyColumn, 64)->nullable()->index();

            // Revocation marker. When set, the refresh exchange rejects any
            // refresh attempt against this device with reason `device_revoked`.
            // Used by the reuse-detection CAS path (a refresh token that
            // verifies against the stored digest but loses the CAS race is
            // treated as a replay and revokes the entire device family) and by
            // consumer-initiated logout-everywhere flows.
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
        $table = Config::string('laravel-authentication.device.table', 'devices');

        Schema::dropIfExists($table);
    }
};
