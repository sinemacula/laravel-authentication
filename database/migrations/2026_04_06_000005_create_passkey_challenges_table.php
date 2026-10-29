<?php

declare(strict_types = 1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Schema;
use SineMacula\Laravel\Authentication\Database\MigrationCollisionGuard;

/**
 * Create the passkey challenges table: the single-use, short-lived challenges
 * of passkey registration, sign-in and factor ceremonies.
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
        $table  = $this->table();
        $schema = Schema::getConnection()->getSchemaBuilder();

        (new MigrationCollisionGuard($schema))->ensureNotExists($table, 'passkeys.challenges_table');

        Schema::create($table, static function (Blueprint $blueprint): void {
            $blueprint->uuid('id')->primary();
            $blueprint->string('purpose', 16);
            $blueprint->string('guard');
            $blueprint->string('rp_id');

            // The identity a registration or factor ceremony is for; a sign-in
            // ceremony is usernameless and records none.
            $blueprint->string('authenticatable_type')->nullable();
            $blueprint->string('authenticatable_id')->nullable();

            // The ceremony options as sent, challenge included, which the
            // response is verified against. Long text: a registration or a
            // factor lists every passkey the identity has, which can outgrow
            // MySQL's 64 KiB text.
            $blueprint->longText('options');

            $blueprint->dateTime('expires_at', 0);
            $blueprint->dateTime('created_at', 0)->nullable();

            $blueprint->index('expires_at');
        });
    }

    /**
     * Reverse the migrations.
     *
     * @return void
     */
    public function down(): void
    {
        Schema::dropIfExists($this->table());
    }

    /**
     * The configured table name.
     *
     * @return string
     */
    private function table(): string
    {
        return Config::string('authentication.passkeys.challenges_table', 'passkey_challenges');
    }
};
