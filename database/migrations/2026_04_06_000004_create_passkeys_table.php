<?php

declare(strict_types = 1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Schema;
use SineMacula\Laravel\Authentication\Database\MigrationCollisionGuard;
use SineMacula\Laravel\Authentication\Database\StorageConnection;

/**
 * Create the passkeys table.
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
        $table  = $this->table();
        $schema = Schema::connection($this->getConnection());

        (new MigrationCollisionGuard($schema))->ensureNotExists($table, 'passkeys.table');

        $schema->create($table, static function (Blueprint $blueprint) use ($table): void {
            $blueprint->uuid('id')->primary();

            // A credential id reaches 1023 bytes, beyond what MySQL indexes, so
            // it is found by its digest.
            $blueprint->char('credential_id_hash', 64)->unique();
            $blueprint->text('credential_id');

            $blueprint->string('authenticatable_type');
            $blueprint->string('authenticatable_id');

            $blueprint->string('rp_id');
            $blueprint->string('user_handle');

            // Nothing bounds a COSE key, and MySQL silently truncates past 64
            // KiB on an insert that ignores duplicates.
            $blueprint->longText('public_key');

            $blueprint->unsignedBigInteger('sign_count')->default(0);
            $blueprint->text('transports');
            $blueprint->string('aaguid', 36)->nullable();
            $blueprint->boolean('backup_eligible')->default(false);
            $blueprint->boolean('backup_state')->default(false);
            $blueprint->boolean('uv_initialized')->default(false);
            $blueprint->string('name')->nullable();

            $blueprint->dateTime('last_used_at', 0)->nullable();
            $blueprint->datetimes(0);

            // Named short, so a long table name fits MySQL's 64 characters.
            $blueprint->index(['authenticatable_type', 'authenticatable_id', 'rp_id'], $table . '_owner_index');
        });
    }

    /**
     * Reverse the migrations.
     *
     * @return void
     */
    public function down(): void
    {
        Schema::connection($this->getConnection())->dropIfExists($this->table());
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
     * The configured table name.
     *
     * @return string
     */
    private function table(): string
    {
        return Config::string('authentication.passkeys.table', 'passkeys');
    }
};
