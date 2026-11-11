<?php

declare(strict_types = 1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Schema;
use SineMacula\Laravel\Authentication\Database\MigrationCollisionGuard;
use SineMacula\Laravel\Authentication\Database\StorageConnection;

/**
 * Create the sessions table.
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
        $table = Config::string('authentication.session.table', 'authentication_sessions');

        $schema = Schema::connection($this->getConnection());

        (new MigrationCollisionGuard($schema))->ensureNotExists($table, 'session.table');

        $schema->create($table, static function (Blueprint $blueprint) use ($table): void {
            $blueprint->uuid('id')->primary();

            // Random and immutable, so a row reissued under the same key is
            // never taken for the session a caller holds.
            $blueprint->uuid('generation');

            // Strings rather than `morphs()`, so UUID and ULID keys work too.
            $blueprint->string('authenticatable_type');
            $blueprint->string('authenticatable_id');
            $blueprint->string('principal_type')->nullable();
            $blueprint->string('principal_id')->nullable();

            // `requires` is a JSON list such as `["mfa","principal"]`, `null`
            // once active.
            $blueprint->string('status', 16)->default('active');
            $blueprint->string('requires', 64)->nullable();
            $blueprint->string('pending_key', 64)->nullable();

            // The session a first activation supersedes while it is unchanged,
            // and the attempt-limit slots held until then (JSON).
            $blueprint->string('supersedes_session_id')->nullable();
            $blueprint->string('supersedes_refresh_key', 64)->nullable();
            $blueprint->text('attempt_windows')->nullable();

            $blueprint->string('tenant_id')->nullable();
            $blueprint->string('tenant_policy_version', 64)->nullable();

            // The floor for the `iat` of the session's access tokens, moved by
            // every change of its context.
            $blueprint->dateTime('switched_at', 0)->nullable();

            // Written, never read, so an issuance and a proof change in
            // concurrent transactions cannot pass each other unseen.
            $blueprint->unsignedBigInteger('issuance_sequence')->default(0);

            $blueprint->string('guard')->nullable();
            $blueprint->string('sign_in_method')->nullable();
            $blueprint->string('sign_in_identifier_type')->nullable();
            $blueprint->string('client_name')->nullable();
            $blueprint->string('platform')->nullable();
            $blueprint->string('created_ip', 45)->nullable();
            $blueprint->string('created_user_agent', 512)->nullable();

            $blueprint->dateTime('last_used_at', 0)->nullable();
            $blueprint->string('last_used_ip', 45)->nullable();
            $blueprint->string('last_used_user_agent', 512)->nullable();

            // Not indexed: a session is found by its key and its digest
            // compared in constant time.
            $blueprint->string('refresh_key', 64)->nullable();
            $blueprint->string('previous_refresh_key', 64)->nullable();

            // Whole seconds because rotation compares deadlines by equality;
            // `dateTime` because MySQL's `timestamp` ends in 2038.
            $blueprint->dateTime('refresh_rotated_at', 0)->nullable();
            $blueprint->dateTime('signed_in_at', 0);
            $blueprint->dateTime('idle_expires_at', 0);

            $blueprint->dateTime('absolute_expires_at', 0)->nullable();

            $blueprint->dateTime('revoked_at', 0)->nullable();
            $blueprint->string('revoked_reason', 64)->nullable();

            $blueprint->datetimes(0);

            // Short names keep a 47-character table name within PostgreSQL's
            // 63-character limit, which truncates silently.
            $blueprint->index(['authenticatable_type', 'authenticatable_id'], $table . '_owner_index');
            $blueprint->index(['principal_type', 'principal_id'], $table . '_principal_index');
            $blueprint->index('guard', $table . '_guard_index');
            $blueprint->index('tenant_id', $table . '_tenant_index');

            // One index per pruning condition.
            $blueprint->index('idle_expires_at', $table . '_idle_index');
            $blueprint->index('absolute_expires_at', $table . '_absolute_index');
            $blueprint->index('revoked_at', $table . '_revoked_index');
        });
    }

    /**
     * Reverse the migrations.
     *
     * @return void
     */
    public function down(): void
    {
        $table = Config::string('authentication.session.table', 'authentication_sessions');

        Schema::connection($this->getConnection())->dropIfExists($table);
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
};
