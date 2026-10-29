<?php

declare(strict_types = 1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Schema;
use SineMacula\Laravel\Authentication\Database\MigrationCollisionGuard;

/**
 * Create the identifier changes table: the pending change of each identity's
 * identifier of each type.
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
        $table = Config::string('authentication.identifier_changes.table', 'identifier_changes');

        (new MigrationCollisionGuard(Schema::getConnection()->getSchemaBuilder()))->ensureNotExists($table, 'identifier_changes.table');

        Schema::create($table, static function (Blueprint $blueprint): void {
            // SHA-256 hex digest of the identity's row and the identifier type,
            // so an identity has one pending change per type and a new request
            // replaces the one before.
            $blueprint->char('id', 64)->primary();
            $blueprint->string('guard');
            $blueprint->string('type', 64);

            // `previous` exactly as stored, not normalised; `previous_verified`
            // lets the notice to it tell a proven owner from an address that
            // may be a stranger's.
            $blueprint->string('previous')->nullable();
            $blueprint->boolean('previous_verified')->default(false);
            $blueprint->string('identifier');

            // Random per request: the code and the link that confirm a change
            // are bound to it, so a newer request outdates both.
            $blueprint->uuid('request_id')->unique();

            $blueprint->dateTime('requested_at', 0);
            $blueprint->dateTime('expires_at', 0)->index();
        });
    }

    /**
     * Reverse the migrations.
     *
     * @return void
     */
    public function down(): void
    {
        Schema::dropIfExists(Config::string('authentication.identifier_changes.table', 'identifier_changes'));
    }
};
