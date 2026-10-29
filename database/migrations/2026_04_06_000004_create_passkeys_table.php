<?php

declare(strict_types = 1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Schema;
use SineMacula\Laravel\Authentication\Database\MigrationCollisionGuard;

/**
 * Create the passkeys table: the WebAuthn credentials identities sign in with,
 * each scoped to the relying party it was registered for.
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
        $schema = Schema::getConnection()->getSchemaBuilder();

        (new MigrationCollisionGuard($schema))->ensureNotExists($table, 'passkeys.table');

        Schema::create($table, static function (Blueprint $blueprint) use ($table): void {
            $blueprint->uuid('id')->primary();

            // A credential id reaches 1023 bytes, beyond what MySQL indexes as
            // base64url text, so it is found by the SHA-256 hex digest of its
            // raw bytes and kept in full beside it.
            $blueprint->char('credential_id_hash', 64)->unique();
            $blueprint->text('credential_id');

            // Plain string polymorphic columns, as on the devices table, so any
            // key type fits.
            $blueprint->string('authenticatable_type');
            $blueprint->string('authenticatable_id');

            $blueprint->string('rp_id');
            $blueprint->string('user_handle');

            // Long text: nothing bounds a COSE key, which may carry further
            // parameters such as a key id, and MySQL silently cuts a value past
            // its 64 KiB text when the insert ignores duplicates.
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

            // Named short, so a long configured table name still fits MySQL's
            // 64-character identifiers.
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
        Schema::dropIfExists($this->table());
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
