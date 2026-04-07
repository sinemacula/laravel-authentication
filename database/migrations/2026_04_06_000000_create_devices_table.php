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

            // Polymorphic relation columns + composite index. `morphs()`
            // is deliberate: it picks the right id column width for
            // string/int identity keys and indexes (type, id) in one
            // step, which is the query shape the guard issues.
            $blueprint->morphs('authenticatable');

            $blueprint->string('os');
            // SHA-256 hex digest (64 characters) of the plaintext
            // rotation identifier embedded in the refresh token's `jti`
            // claim. Unique so two devices cannot share a rotation id;
            // fixed-length for index efficiency.
            $blueprint->string($refreshKeyColumn, 64)->unique();

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
