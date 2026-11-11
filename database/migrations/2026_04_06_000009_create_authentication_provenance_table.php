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
 * Create the provenance and connection guards tables.
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
        $table  = Config::string('authentication.proofs.provenance_table', 'authentication_provenance');
        $guards = Config::string('authentication.proofs.guards_table', 'authentication_connection_guards');

        $schema = Schema::connection($this->getConnection());

        // Check both before creating either, so a collision leaves no table.
        (new MigrationCollisionGuard($schema))->ensureNotExists($table, 'proofs.provenance_table');
        (new MigrationCollisionGuard($schema))->ensureNotExists($guards, 'proofs.guards_table');

        $schema->create($table, static function (Blueprint $blueprint) use ($schema, $table): void {

            self::exact($schema, $blueprint, 'session_id')->primary();

            self::exact($schema, $blueprint, 'connection_id');

            $blueprint->string('tenant_id')->nullable();
            $blueprint->dateTime('provider_authenticated_at', 0)->nullable();

            $blueprint->text('accepted_evidence')->nullable();

            $blueprint->dateTime('provider_session_expires_at', 0)->nullable();
            $blueprint->string('policy_version', 64)->nullable();

            // Not indexed: a link's sessions are found by their identity's
            // session keys first.
            self::exact($schema, $blueprint, 'link_id')->nullable();

            $blueprint->text('provider_context')->nullable();

            $blueprint->dateTime('created_at', 0)->nullable();

            // Named short, so a 47-character table name fits PostgreSQL's 63.
            $blueprint->index('connection_id', $table . '_provider_index');
            $blueprint->index(['tenant_id', 'connection_id'], $table . '_tenant_index');
        });

        $schema->create($guards, static function (Blueprint $blueprint) use ($schema, $guards): void {

            // One guard per connection and the slot a link's id hashes to.
            self::exact($schema, $blueprint, 'connection_id');
            $blueprint->unsignedSmallInteger('slot');

            $blueprint->primary(['connection_id', 'slot'], $guards . '_primary');
        });
    }

    /**
     * Reverse the migrations.
     *
     * @return void
     */
    public function down(): void
    {
        $schema = Schema::connection($this->getConnection());

        $schema->dropIfExists(Config::string('authentication.proofs.guards_table', 'authentication_connection_guards'));
        $schema->dropIfExists(Config::string('authentication.proofs.provenance_table', 'authentication_provenance'));
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

    /**
     * A string column that compares byte for byte.
     *
     * MySQL and MariaDB collations ignore case and accents or pad, so there it
     * is binary, four bytes per character.
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
