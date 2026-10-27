<?php

declare(strict_types = 1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Schema;

/**
 * Create the pending sign-ins table: sign-ins waiting for a further factor.
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
        Schema::create(Config::string('authentication.sign_in.pending_table', 'pending_sign_ins'), static function (Blueprint $blueprint): void {
            $blueprint->uuid('id')->primary();

            // SHA-256 hex digest of the token's secret, compared in constant
            // time; the secret itself is never stored.
            $blueprint->string('token_digest', 64);
            $blueprint->string('purpose', 64);

            $blueprint->string('guard');
            $blueprint->string('sign_in_method');
            $blueprint->string('identifier_type')->nullable();

            // Plain string polymorphic columns, as on the devices table, so any
            // key type fits.
            $blueprint->string('authenticatable_type');
            $blueprint->string('authenticatable_id');
            $blueprint->string('principal_type');
            $blueprint->string('principal_id');

            $blueprint->string('client_name')->nullable();
            $blueprint->string('platform')->nullable();
            $blueprint->string('created_ip', 45)->nullable();
            $blueprint->string('created_user_agent', 512)->nullable();

            // The device the client proved it holds, and the digest it was
            // proven against, so completion continues it only if unchanged.
            $blueprint->string('device_id')->nullable();
            $blueprint->string('device_refresh_key', 64)->nullable();

            $blueprint->dateTime('expires_at', 0);
            $blueprint->datetimes(0);

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
        Schema::dropIfExists(Config::string('authentication.sign_in.pending_table', 'pending_sign_ins'));
    }
};
