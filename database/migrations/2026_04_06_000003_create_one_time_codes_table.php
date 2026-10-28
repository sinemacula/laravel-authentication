<?php

declare(strict_types = 1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Schema;
use SineMacula\Laravel\Authentication\Database\MigrationCollisionGuard;

/**
 * Create the one-time codes table: the live code of each binding.
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
        $table = Config::string('authentication.codes.table', 'one_time_codes');

        (new MigrationCollisionGuard(Schema::getConnection()->getSchemaBuilder()))->ensureNotExists($table, 'codes.table');

        Schema::create($table, static function (Blueprint $blueprint): void {
            // HMAC-SHA256 hex digest of the binding (purpose, guard, identifier
            // type and normal form, and the identity a verification is for), so
            // there is one live code per binding and the table holds no
            // identifier.
            $blueprint->char('id', 64)->primary();
            $blueprint->string('purpose', 32);
            $blueprint->string('guard');

            // Random per issuance, and hashed with the code: every check, use
            // and delivery is bound to it, since a resend can draw the same
            // digits as the code it replaces.
            $blueprint->uuid('issue_id');
            $blueprint->char('code_hash', 64);
            $blueprint->unsignedSmallInteger('attempts');

            $blueprint->dateTime('issued_at', 0);
            $blueprint->dateTime('expires_at', 0)->index();
            $blueprint->dateTime('consumed_at', 0)->nullable();
        });
    }

    /**
     * Reverse the migrations.
     *
     * @return void
     */
    public function down(): void
    {
        Schema::dropIfExists(Config::string('authentication.codes.table', 'one_time_codes'));
    }
};
