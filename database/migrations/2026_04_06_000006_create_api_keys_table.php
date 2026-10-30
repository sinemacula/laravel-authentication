<?php

declare(strict_types = 1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Schema;
use SineMacula\Laravel\Authentication\Database\MigrationCollisionGuard;
use SineMacula\Laravel\Authentication\Database\StorageConnection;

/**
 * Create the API keys table: the keys non-human identities authenticate with,
 * each bound to one guard, one principal and its tenant.
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
        $table = Config::string('authentication.api_keys.table', 'api_keys');

        $schema = Schema::connection($this->getConnection());

        (new MigrationCollisionGuard($schema))->ensureNotExists($table, 'api_keys.table');

        $schema->create($table, static function (Blueprint $blueprint) use ($table): void {
            $blueprint->uuid('id')->primary();

            // The key's public part, `<prefix>_<public>`: displayed, and the
            // one indexed lookup a presented key costs.
            $blueprint->string('public_id', 64)->unique();

            // SHA-256 hex digest of the secret, compared in constant time; the
            // secret itself is never stored.
            $blueprint->char('secret_hash', 64);

            $blueprint->string('guard');
            $blueprint->string('name')->nullable();

            // Plain string polymorphic columns, as on the devices table, so any
            // key type fits.
            $blueprint->string('authenticatable_type');
            $blueprint->string('authenticatable_id');
            $blueprint->string('principal_type');
            $blueprint->string('principal_id');
            $blueprint->string('tenant_type')->nullable();
            $blueprint->string('tenant_id')->nullable();

            // The granted scopes, as a JSON list.
            $blueprint->text('scopes');

            $blueprint->dateTime('expires_at', 0)->nullable();
            $blueprint->dateTime('last_used_at', 0)->nullable();
            $blueprint->dateTime('rotated_at', 0)->nullable();
            $blueprint->uuid('replaced_by')->nullable();
            $blueprint->dateTime('revoked_at', 0)->nullable();
            $blueprint->datetimes(0);

            // Named short, so a long configured table name still fits MySQL's
            // 64-character identifiers.
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
        Schema::connection($this->getConnection())->dropIfExists(Config::string('authentication.api_keys.table', 'api_keys'));
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
