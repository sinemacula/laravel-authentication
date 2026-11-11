<?php

declare(strict_types = 1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Schema;
use SineMacula\Laravel\Authentication\Database\MigrationCollisionGuard;
use SineMacula\Laravel\Authentication\Database\StorageConnection;

/**
 * Create the passkey challenges table.
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

        (new MigrationCollisionGuard($schema))->ensureNotExists($table, 'passkeys.challenges_table');

        $schema->create($table, static function (Blueprint $blueprint): void {
            $blueprint->uuid('id')->primary();
            $blueprint->string('purpose', 16);
            $blueprint->string('guard');
            $blueprint->string('rp_id');

            // None for a usernameless sign-in ceremony.
            $blueprint->string('authenticatable_type')->nullable();
            $blueprint->string('authenticatable_id')->nullable();

            $blueprint->string('session_id')->nullable();
            $blueprint->string('binding_purpose', 32)->nullable();

            // Long text: listing every passkey the identity has can outgrow
            // MySQL's 64 KiB text.
            $blueprint->longText('options');

            $blueprint->dateTime('expires_at', 0);

            // The row is kept, so a later response is told the challenge was
            // used.
            $blueprint->dateTime('consumed_at', 0)->nullable();
            $blueprint->dateTime('created_at', 0)->nullable();

            $blueprint->index('expires_at');
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
        return Config::string('authentication.passkeys.challenges_table', 'passkey_challenges');
    }
};
