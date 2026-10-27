<?php

declare(strict_types = 1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Schema;

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
     */
    public function up(): void
    {
        Schema::connection($this->getConnection())->create($this->table(), static function (Blueprint $blueprint): void {
            // SHA-256 hex digest of the guard, flow, scope and identifier or IP
            // address, so neither is stored in clear.
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
     * The connection the counters live on: the configured one, or the default.
     *
     * @return ?string
     */
    #[Override]
    public function getConnection(): ?string
    {
        $connection = Config::get('authentication.rate_limits.connection');

        return is_string($connection) && $connection !== '' ? $connection : null;
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
