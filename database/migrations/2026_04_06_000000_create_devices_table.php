<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use SineMacula\Laravel\Authentication\Database\MigrationCollisionGuard;

return new class extends Migration {

    /**
     * Run the migrations.
     *
     * @return void
     *
     * @throws \RuntimeException When the configured devices table already exists.
     */
    public function up(): void
    {
        $table            = (string) config('laravel-authentication.device.table', 'devices');
        $refreshKeyColumn = (string) config('laravel-authentication.device.refresh_key_column', 'refresh_key');

        (new MigrationCollisionGuard(Schema::getConnection()->getSchemaBuilder()))
            ->ensureNotExists($table);

        Schema::create($table, static function (Blueprint $blueprint) use ($refreshKeyColumn): void {

            $blueprint->ulid('id')->primary();
            $blueprint->string('authenticatable_type');
            $blueprint->string('authenticatable_id');
            $blueprint->string('os');
            $blueprint->string($refreshKeyColumn);
            $blueprint->timestamp('last_logged_in_at')->nullable();
            $blueprint->timestamp('last_mfa_verified_at')->nullable();
            $blueprint->timestamps();

            $blueprint->index(['authenticatable_type', 'authenticatable_id']);
            $blueprint->index($refreshKeyColumn);
        });
    }

    /**
     * Reverse the migrations.
     *
     * @return void
     */
    public function down(): void
    {
        $table = (string) config('laravel-authentication.device.table', 'devices');

        Schema::dropIfExists($table);
    }
};
