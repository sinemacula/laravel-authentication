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
 * Create the proofs table.
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
            // The order the proofs were recorded in, which a UUIDv7 id does not
            // keep across processes or a clock stepped back.
            $blueprint->id('sequence');
            $blueprint->uuid('id')->unique($table . '_id_unique');

            self::exact($schema, $blueprint, 'session_id');

            $blueprint->string('kind', 40);
            $blueprint->string('purpose', 32);
            $blueprint->string('method');
            $blueprint->string('channel_kind', 32);
            $blueprint->string('channel_reference')->nullable();

            self::exact($schema, $blueprint, 'factor_reference')->nullable();

            // `null` when not observed, which is never read as true.
            $blueprint->boolean('user_presence')->nullable();
            $blueprint->boolean('user_verification')->nullable();
            $blueprint->boolean('backup_eligible')->nullable();
            $blueprint->boolean('backup_state')->nullable();
            $blueprint->boolean('phishing_resistant')->nullable();
            $blueprint->string('key_protection', 16)->nullable();

            // `null` for a proof the package verified itself.
            $blueprint->boolean('accepted')->nullable();
            $blueprint->boolean('multifactor')->nullable();
            $blueprint->boolean('additional_verification')->nullable();

            $blueprint->text('evidence')->nullable();

            // A bounded string so the claims query can group by it on every
            // database; its JSON is ASCII, so bytes equal characters.
            self::exact($schema, $blueprint, 'methods', 1024, 1024);

            self::exact($schema, $blueprint, 'authenticatable_type');
            self::exact($schema, $blueprint, 'authenticatable_id');
            self::exact($schema, $blueprint, 'guard');

            $blueprint->dateTime('authenticated_at', 0);

            $blueprint->dateTime('voided_at', 0)->nullable();

            $blueprint->dateTime('created_at', 0)->nullable();

            // Named short, so a 47-character table name fits PostgreSQL's and
            // MySQL's identifiers.
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
     * @param  int  $characters
     * @param  int  $bytes
     * @return \Illuminate\Database\Schema\ColumnDefinition
     */
    private static function exact(Builder $schema, Blueprint $blueprint, string $name, int $characters = 255, int $bytes = 1020): ColumnDefinition
    {
        return in_array($schema->getConnection()->getDriverName(), ['mysql', 'mariadb'], true)
            ? $blueprint->binary($name, $bytes)
            : $blueprint->string($name, $characters);
    }
};
