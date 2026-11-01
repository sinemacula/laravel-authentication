<?php

declare(strict_types = 1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Schema;
use SineMacula\Laravel\Authentication\Database\MigrationCollisionGuard;
use SineMacula\Laravel\Authentication\Database\StorageConnection;

/**
 * Create the provenance table: how each session established through an external
 * identity provider began, written once with the session.
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
        $table = Config::string('authentication.proofs.provenance_table', 'authentication_provenance');

        $schema = Schema::connection($this->getConnection());

        (new MigrationCollisionGuard($schema))->ensureNotExists($table, 'proofs.provenance_table');

        $schema->create($table, static function (Blueprint $blueprint) use ($table): void {

            // The session's key as a string, whatever the session model's key
            // type: one provenance per session.
            $blueprint->string('session_id')->primary();

            $blueprint->string('connection_id');
            $blueprint->string('tenant_id')->nullable();
            $blueprint->dateTime('provider_authenticated_at', 0)->nullable();

            // The evidence the provider asserted, once the evidence contract
            // accepted it, as JSON; nothing records any yet.
            $blueprint->text('accepted_evidence')->nullable();

            $blueprint->dateTime('provider_session_expires_at', 0)->nullable();
            $blueprint->string('policy_version', 64)->nullable();
            $blueprint->dateTime('created_at', 0)->nullable();

            // The sessions of a connection, and those of a tenant's
            // connections, are found by these. Named short, so a configured
            // table name of up to 47 characters still fits.
            $blueprint->index('connection_id', $table . '_connection_index');
            $blueprint->index(['tenant_id', 'connection_id'], $table . '_tenant_index');
        });
    }

    /**
     * Reverse the migrations.
     *
     * @return void
     */
    public function down(): void
    {
        Schema::connection($this->getConnection())->dropIfExists(Config::string('authentication.proofs.provenance_table', 'authentication_provenance'));
    }

    /**
     * The connection the package's tables live on (see `StorageConnection`),
     * the one the sessions, and so their provenance, are written on.
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
