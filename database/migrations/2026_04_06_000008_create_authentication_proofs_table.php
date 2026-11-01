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
 * Create the proofs table: the timestamped proofs recorded on each session,
 * kept apart by kind, from which a session's `auth_time` and `amr` are derived.
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
        $table = Config::string('authentication.proofs.table', 'authentication_proofs');

        $schema = Schema::connection($this->getConnection());

        (new MigrationCollisionGuard($schema))->ensureNotExists($table, 'proofs.table');

        $schema->create($table, static function (Blueprint $blueprint) use ($schema, $table): void {
            $blueprint->uuid('id')->primary();

            // The session's key as a string, whatever the session model's key
            // type, so proofs are found and pruned by bound string values.
            self::exact($schema, $blueprint->string('session_id'));

            $blueprint->string('kind', 40);
            $blueprint->string('purpose', 32);
            $blueprint->string('method');
            $blueprint->string('channel_kind', 32);
            $blueprint->string('channel_reference')->nullable();
            $blueprint->string('factor_reference')->nullable();

            // What was observed about the authenticator: `null` when it was not
            // observed, which is never read as true.
            $blueprint->boolean('user_presence')->nullable();
            $blueprint->boolean('user_verification')->nullable();
            $blueprint->boolean('backup_eligible')->nullable();
            $blueprint->boolean('backup_state')->nullable();
            $blueprint->boolean('phishing_resistant')->nullable();
            $blueprint->string('key_protection', 16)->nullable();

            // The adapter's evaluation; `null` for a proof the package verified
            // itself.
            $blueprint->boolean('accepted')->nullable();
            $blueprint->boolean('multifactor')->nullable();

            // The proof's `amr` values as a JSON list. A bounded string rather
            // than text, so the claims query can group by it on every database.
            self::exact($schema, $blueprint->string('methods', 1024));

            self::exact($schema, $blueprint->string('authenticatable_type'));
            self::exact($schema, $blueprint->string('authenticatable_id'));
            self::exact($schema, $blueprint->string('guard'));

            $blueprint->dateTime('authenticated_at', 0);

            // When the proof stopped counting, which nothing sets yet; a voided
            // proof never counts.
            $blueprint->dateTime('voided_at', 0)->nullable();

            $blueprint->dateTime('created_at', 0)->nullable();

            // The claims read groups a session's proofs by kind, and the
            // freshness read takes the newest of some kinds, both from this
            // index. Named short, so a configured table name of up to 47
            // characters still fits PostgreSQL's and MySQL's identifiers.
            $blueprint->index(['session_id', 'kind', 'authenticated_at'], $table . '_session_index');
        });
    }

    /**
     * Reverse the migrations.
     *
     * @return void
     */
    public function down(): void
    {
        Schema::connection($this->getConnection())->dropIfExists(Config::string('authentication.proofs.table', 'authentication_proofs'));
    }

    /**
     * The connection the package's tables live on (see `StorageConnection`),
     * the one the sessions, and so their proofs, are written on.
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
     * The column, compared byte for byte on MySQL and MariaDB, whose default
     * collations ignore case and accents: two session keys, guards, owners or
     * `amr` values that differ only in those would otherwise match, so one
     * session would count, clear or prune another's proofs and the claims read
     * would merge two values. PostgreSQL and SQLite already compare bytes.
     *
     * @param  \Illuminate\Database\Schema\Builder  $schema
     * @param  \Illuminate\Database\Schema\ColumnDefinition  $column
     * @return \Illuminate\Database\Schema\ColumnDefinition
     */
    private static function exact(Builder $schema, ColumnDefinition $column): ColumnDefinition
    {
        return in_array($schema->getConnection()->getDriverName(), ['mysql', 'mariadb'], true)
            ? $column->charset('utf8mb4')->collation('utf8mb4_bin')
            : $column;
    }
};
