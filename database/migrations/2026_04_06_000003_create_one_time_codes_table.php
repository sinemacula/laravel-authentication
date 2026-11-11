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
            // HMAC digest of the delivery key, so there is one challenge per
            // key and the table holds no identifier.
            $blueprint->char('id', 64)->primary();

            // Kept across resends; compared after the row is found by key, so
            // it needs no index.
            $blueprint->uuid('challenge_id');

            // HMAC digest of the transaction the key leaves out, if any.
            $blueprint->char('context', 64)->nullable();

            $blueprint->string('purpose', 32);
            $blueprint->string('guard');

            // Hashed with the code, since a resend can draw the same digits.
            $blueprint->uuid('issue_id');
            $blueprint->char('code_hash', 64);
            $blueprint->unsignedSmallInteger('attempts');

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
