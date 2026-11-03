<?php

declare(strict_types = 1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Database\Schema\Builder;
use Illuminate\Database\Schema\ColumnDefinition;
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

        $schema->create($table, static function (Blueprint $blueprint) use ($schema, $table): void {

            // The session's key as a string, whatever the session model's key
            // type: one provenance per session.
            self::exact($schema, $blueprint, 'session_id')->primary();

            // The connection that established the session, compared exactly, so
            // revoking one connection's sessions never ends those of another
            // whose id differs from it only in case, accents or a trailing
            // space.
            self::exact($schema, $blueprint, 'connection_id');

            $blueprint->string('tenant_id')->nullable();
            $blueprint->dateTime('provider_authenticated_at', 0)->nullable();

            // The evidence the provider asserted, once the evidence contract
            // accepted it, as JSON; nothing records any yet.
            $blueprint->text('accepted_evidence')->nullable();

            $blueprint->dateTime('provider_session_expires_at', 0)->nullable();
            $blueprint->string('policy_version', 64)->nullable();

            // The link the result was mapped to its identity through, opaque
            // and compared exactly, so a reauthentication or a revocation
            // through one link never matches another whose id differs from it
            // only in case, accents or a trailing space. Not indexed: a link's
            // sessions are found by their identity's session keys first.
            self::exact($schema, $blueprint, 'link_id')->nullable();

            $blueprint->dateTime('created_at', 0)->nullable();

            // Indexes for finding the sessions of a connection, which revoking
            // them by connection reads, or of a tenant's connections. Named
            // short (the connection's after the provider it configures), so a
            // configured table name of up to 47 characters still fits
            // PostgreSQL's 63.
            $blueprint->index('connection_id', $table . '_provider_index');
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

    /**
     * A string column that compares byte for byte: binary on MySQL and MariaDB,
     * whose default collations ignore case and accents and whose `utf8mb4_bin`
     * pads (`'abc'` equals `'abc '`), while the binary collation that does not
     * pad has a different name on each. Two session keys that differ only in
     * those would otherwise match, so one session would clear or prune
     * another's provenance, or could not record its own, and one connection's
     * or link's revocation would end another's sessions. PostgreSQL and SQLite
     * already compare bytes. A binary column's length is in bytes, so it is
     * given the four a `utf8mb4` character may take for each of the 255
     * characters the column holds elsewhere.
     *
     * @param  \Illuminate\Database\Schema\Builder  $schema
     * @param  \Illuminate\Database\Schema\Blueprint  $blueprint
     * @param  string  $name
     * @return \Illuminate\Database\Schema\ColumnDefinition
     */
    private static function exact(Builder $schema, Blueprint $blueprint, string $name): ColumnDefinition
    {
        return in_array($schema->getConnection()->getDriverName(), ['mysql', 'mariadb'], true)
            ? $blueprint->binary($name, 1020)
            : $blueprint->string($name);
    }
};
