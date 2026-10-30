<?php

declare(strict_types = 1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Schema;
use SineMacula\Laravel\Authentication\Database\MigrationCollisionGuard;
use SineMacula\Laravel\Authentication\Database\StorageConnection;

/**
 * Create the rate limits table.
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
        $schema = Schema::connection($this->getConnection());

        (new MigrationCollisionGuard($schema))->ensureNotExists($this->table(), 'rate_limits.table');

        $schema->create($this->table(), static function (Blueprint $blueprint): void {
            // HMAC-SHA256 hex digest, keyed from the application key, of what
            // the counter counts (see CounterKeys), so the table alone gives
            // none of it back.
            $blueprint->char('key', 64)->primary();
            $blueprint->unsignedInteger('hits');

            // Whole seconds, compared with the window boundaries the limiter
            // computes, and indexed for pruning ended windows.
            $blueprint->dateTime('window_ends_at', 0)->index();
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
     * The connection the counters live on, the one the model reads and writes
     * them on: the configured one, or the storage connection (see
     * `StorageConnection::forRateLimits()`).
     *
     * @return ?string
     *
     * @throws \InvalidArgumentException
     */
    #[Override]
    public function getConnection(): ?string
    {
        return StorageConnection::forRateLimits();
    }

    /**
     * The configured table name.
     *
     * @return string
     */
    private function table(): string
    {
        return Config::string('authentication.rate_limits.table', 'rate_limits');
    }
};
