<?php

declare(strict_types = 1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Schema;
use SineMacula\Laravel\Authentication\Database\MigrationCollisionGuard;
use SineMacula\Laravel\Authentication\Database\StorageConnection;

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

        $schema = Schema::connection($this->getConnection());

        (new MigrationCollisionGuard($schema))->ensureNotExists($table, 'codes.table');

        $schema->create($table, static function (Blueprint $blueprint): void {
            // HMAC-SHA256 hex digest of the delivery key (purpose, guard,
            // identifier type or channel kind, destination in normal form, and
            // the owner where the purpose has one), so there is one challenge
            // per key, the delivery cap and the cooldown are counted on it, and
            // the table holds no identifier.
            $blueprint->char('id', 64)->primary();

            // The challenge's public id: kept across resends, new for each new
            // challenge. A check finds the row by its key and compares this, so
            // it needs no index.
            $blueprint->uuid('challenge_id');

            // HMAC-SHA256 hex digest of the transaction the key leaves out (an
            // `mfa` challenge's session, factor and proof purpose; an
            // `enrollment` one's session, pending factor and grant), or null
            // for a purpose that has none.
            $blueprint->char('context', 64)->nullable();

            $blueprint->string('purpose', 32);
            $blueprint->string('guard');

            // Random per issuance, and hashed with the code: every check, use
            // and delivery is bound to it, since a resend can draw the same
            // digits as the code it replaces.
            $blueprint->uuid('issue_id');
            $blueprint->char('code_hash', 64);
            $blueprint->unsignedSmallInteger('attempts');

            // Deliveries to the key since its delivery window began, across
            // every challenge the window held.
            $blueprint->unsignedSmallInteger('deliveries');
            $blueprint->dateTime('window_started_at', 0);

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
        Schema::connection($this->getConnection())->dropIfExists(Config::string('authentication.codes.table', 'one_time_codes'));
    }

    /**
     * The connection the package's tables live on (see `StorageConnection`),
     * the one the model reads and writes the table on.
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
