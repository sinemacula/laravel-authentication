<?php

declare(strict_types = 1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Schema;
use SineMacula\Laravel\Authentication\Database\MigrationCollisionGuard;
use SineMacula\Laravel\Authentication\Database\StorageConnection;

/**
 * Create the identifier changes table.
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

        $schema = Schema::connection($this->getConnection());

        (new MigrationCollisionGuard($schema))->ensureNotExists($table, 'identifier_changes.table');

        $schema->create($table, static function (Blueprint $blueprint): void {
            // Digest of the identity and identifier type: one pending change
            // per type.
            $blueprint->char('id', 64)->primary();
            $blueprint->string('guard');
            $blueprint->string('type', 64);

            // `previous_verified` lets the notice tell a proven owner from an
            // address that may be a stranger's.
            $blueprint->string('previous')->nullable();
            $blueprint->boolean('previous_verified')->default(false);
            $blueprint->string('identifier');

            // Binds the confirming code and link, so a newer request outdates
            // both.
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
        Schema::connection($this->getConnection())->dropIfExists(Config::string('authentication.identifier_changes.table', 'identifier_changes'));
    }

    /**
     * The connection the package's tables live on.
     *
     * @return ?string
     *
     * @throws \InvalidArgumentException
     */
    #[Override]
    public function getConnection(): ?string
    {
        return StorageConnection::name();
    }
};
