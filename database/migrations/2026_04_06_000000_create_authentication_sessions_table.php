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

            // A random UUID written when the row is inserted and never changed:
            // a session a model that reissues keys puts under the same key, of
            // the same owner and even in the same second, has another, so it is
            // never taken for the session a caller holds.
            $blueprint->uuid('generation');

            // Plain string polymorphic columns so the table works against
            // integer, UUID, or ULID keys. `morphs()` would pin the id to
            // unsignedBigInteger and break non-integer keys.
            $blueprint->string('authenticatable_type');
            $blueprint->string('authenticatable_id');
            $blueprint->string('principal_type')->nullable();
            $blueprint->string('principal_id')->nullable();

            // When the session last switched the principal it acts as: access
            // tokens issued before it are rejected, so a switch back to an
            // earlier principal does not revive that principal's old tokens.
            $blueprint->dateTime('principal_switched_at', 0)->nullable();

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

            // SHA-256 hex digests of the current and the immediately previous
            // refresh rotation ids. Not indexed: a session is always found by
            // its primary key and its digest compared in constant time.
            $blueprint->string('refresh_key', 64)->nullable();
            $blueprint->string('previous_refresh_key', 64)->nullable();

            // Every time is a whole-second `dateTime`. Whole seconds because
            // the refresh rotation compares the stored deadlines by equality,
            // which a fractional part the application never wrote would
            // break; `dateTime` because MySQL's `timestamp` ends in January
            // 2038, before the longest session lifetime the package accepts.
            $blueprint->dateTime('refresh_rotated_at', 0)->nullable();
            $blueprint->dateTime('signed_in_at', 0);
            $blueprint->dateTime('idle_expires_at', 0);

            // No absolute deadline when the application sets no absolute limit
            // and the sign-in supplied no deadline of its own.
            $blueprint->dateTime('absolute_expires_at', 0)->nullable();

            $blueprint->dateTime('revoked_at', 0)->nullable();
            $blueprint->string('revoked_reason', 64)->nullable();

            $blueprint->datetimes(0);

            // Named short, so a configured table name of up to 47 characters
            // gives index names within PostgreSQL's 63 characters (it cuts a
            // longer one short without an error) and MySQL's 64; Laravel's
            // default name for the owner index would not fit the default table.
            $blueprint->index(['authenticatable_type', 'authenticatable_id'], $table . '_owner_index');
            $blueprint->index(['principal_type', 'principal_id'], $table . '_principal_index');
            $blueprint->index('guard', $table . '_guard_index');

            // Separate single-column indexes so each condition of a pruning
            // query that matches either deadline or the revocation time can use
            // its own index.
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
     * The connection the package's tables live on (see `StorageConnection`),
     * the one the session model must live on.
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
