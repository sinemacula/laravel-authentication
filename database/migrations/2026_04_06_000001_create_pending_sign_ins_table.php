<?php

declare(strict_types = 1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Schema;
use SineMacula\Laravel\Authentication\Database\MigrationCollisionGuard;
use SineMacula\Laravel\Authentication\Database\StorageConnection;

/**
 * Create the pending sign-ins table: sign-ins waiting for a further factor, and
 * sign-ins waiting for a choice of principal, which record none.
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
        $table = Config::string('authentication.sign_in.pending_table', 'pending_sign_ins');

        $schema = Schema::connection($this->getConnection());

        (new MigrationCollisionGuard($schema))->ensureNotExists($table, 'sign_in.pending_table');

        $schema->create($table, static function (Blueprint $blueprint) use ($table): void {
            $blueprint->uuid('id')->primary();

            // SHA-256 hex digest of the token's secret, compared in constant
            // time; the secret itself is never stored.
            $blueprint->string('token_digest', 64);
            $blueprint->string('purpose', 64);

            $blueprint->string('guard');
            $blueprint->string('sign_in_method');
            $blueprint->string('identifier_type')->nullable();

            // Plain string polymorphic columns, as on the devices table, so any
            // key type fits. A sign-in waiting for its identity to choose a
            // principal records none yet.
            $blueprint->string('authenticatable_type');
            $blueprint->string('authenticatable_id');
            $blueprint->string('principal_type')->nullable();
            $blueprint->string('principal_id')->nullable();

            $blueprint->string('client_name')->nullable();
            $blueprint->string('platform')->nullable();
            $blueprint->string('created_ip', 45)->nullable();
            $blueprint->string('created_user_agent', 512)->nullable();

            // The device the client proved it holds, and the digest it was
            // proven against, so completion continues it only if unchanged.
            $blueprint->string('device_id')->nullable();
            $blueprint->string('device_refresh_key', 64)->nullable();

            // The windows of the attempt-limit slots the sign-in took, as JSON,
            // kept until it completes and given back only then, so a further
            // factor cannot be guessed by signing in again.
            $blueprint->text('attempt_windows')->nullable();

            $blueprint->dateTime('expires_at', 0);
            $blueprint->datetimes(0);

            $blueprint->index('expires_at');

            // Signing an identity or a principal out everywhere deletes the
            // pending sign-ins that record it, in the same transaction as its
            // devices. Named short, so a long configured table name still fits
            // MySQL's 64-character identifiers.
            $blueprint->index(['authenticatable_type', 'authenticatable_id'], $table . '_owner_index');
            $blueprint->index(['principal_type', 'principal_id'], $table . '_principal_index');
        });
    }

    /**
     * Reverse the migrations.
     *
     * @return void
     */
    public function down(): void
    {
        Schema::connection($this->getConnection())->dropIfExists(Config::string('authentication.sign_in.pending_table', 'pending_sign_ins'));
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
