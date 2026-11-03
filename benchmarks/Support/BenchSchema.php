<?php

declare(strict_types = 1);

namespace Benchmarks\Support;

use Carbon\Carbon;
use Carbon\CarbonImmutable;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Str;
use SineMacula\Laravel\Authentication\Models\Session;
use SineMacula\Laravel\Authentication\Proofs\Channel;
use SineMacula\Laravel\Authentication\Proofs\Enums\ChannelKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\Purpose;
use SineMacula\Laravel\Authentication\Proofs\NewProof;
use SineMacula\Laravel\Authentication\Proofs\ObservedProperties;
use SineMacula\Laravel\Authentication\Proofs\ProofWriter;
use SineMacula\Laravel\Authentication\Sessions\Enums\SessionStatus;

/**
 * Shared benchmark schema builder.
 *
 * Creates the tables the benchmark harnesses rely on, keyed by fixture shape,
 * skipping any table that already exists so repeated harness boots stay
 * idempotent.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class BenchSchema
{
    /**
     * Create an auto-incrementing identity table with credential columns.
     *
     * @param  string  $table
     * @return void
     */
    public static function ensureIdentityTable(string $table): void
    {
        self::ensureTable($table, static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('email')->unique();
            $blueprint->string('password');
            $blueprint->boolean('is_active')->default(true);
            $blueprint->timestamps();
        });
    }

    /**
     * Create the big-increments access-only identity table.
     *
     * @return void
     */
    public static function ensureAccessOnlyIdentityTable(): void
    {
        self::ensureTable('access_only_identities', static function (Blueprint $blueprint): void {
            $blueprint->id();
            $blueprint->string('email')->unique();
            $blueprint->string('password');
            $blueprint->timestamps();
        });
    }

    /**
     * Create the coexistence 3D principal table.
     *
     * @return void
     */
    public static function ensureCoexistPrincipalTable(): void
    {
        self::ensureTable('coexist_3d_principals', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->unsignedInteger('identity_id');
            $blueprint->string('name');
            $blueprint->boolean('is_active')->default(true);
            $blueprint->timestamps();
        });
    }

    /**
     * Create the tenant and tenant-scoped principal tables.
     *
     * @return void
     */
    public static function ensureTenantTables(): void
    {
        self::ensureTable('tenant_aware_3d_tenants', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('name');
            $blueprint->string('type');
            $blueprint->timestamps();
        });

        self::ensureTable('tenant_aware_3d_principals', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->unsignedInteger('identity_id');
            $blueprint->unsignedInteger('tenant_id');
            $blueprint->string('name');
            $blueprint->boolean('is_active')->default(true);
            $blueprint->timestamps();
        });
    }

    /**
     * Create the sessions table.
     *
     * @return void
     */
    public static function ensureSessionTable(): void
    {
        self::ensureTable('authentication_sessions', static function (Blueprint $blueprint): void {
            self::defineSessionColumns($blueprint);
        });
    }

    /**
     * Define the columns and indexes of the shipped sessions migration.
     *
     * @param  \Illuminate\Database\Schema\Blueprint  $blueprint
     * @return void
     */
    public static function defineSessionColumns(Blueprint $blueprint): void
    {
        $blueprint->uuid('id')->primary();
        $blueprint->uuid('generation');
        $blueprint->string('authenticatable_type')->nullable();
        $blueprint->string('authenticatable_id')->nullable();
        $blueprint->string('principal_type')->nullable();
        $blueprint->string('principal_id')->nullable();
        $blueprint->string('status', 16)->default('active');
        $blueprint->string('requires', 64)->nullable();
        $blueprint->string('pending_key', 64)->nullable();
        $blueprint->string('supersedes_session_id')->nullable();
        $blueprint->string('supersedes_refresh_key', 64)->nullable();
        $blueprint->text('attempt_windows')->nullable();
        $blueprint->string('tenant_id')->nullable();
        $blueprint->string('tenant_policy_version', 64)->nullable();
        $blueprint->dateTime('switched_at', 0)->nullable();
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
        $blueprint->string('refresh_key', 64)->nullable();
        $blueprint->string('previous_refresh_key', 64)->nullable();
        $blueprint->dateTime('refresh_rotated_at', 0)->nullable();
        $blueprint->dateTime('signed_in_at', 0);
        $blueprint->dateTime('idle_expires_at', 0);
        $blueprint->dateTime('absolute_expires_at', 0)->nullable();
        $blueprint->dateTime('revoked_at', 0)->nullable();
        $blueprint->string('revoked_reason', 64)->nullable();
        $blueprint->datetimes(0);
        $blueprint->index(['authenticatable_type', 'authenticatable_id']);
        $blueprint->index(['principal_type', 'principal_id']);
        $blueprint->index('guard');
        $blueprint->index('tenant_id');
        $blueprint->index('idle_expires_at');
        $blueprint->index('absolute_expires_at');
        $blueprint->index('revoked_at');
    }

    /**
     * Create the proofs, provenance and connection guard tables, as the shipped
     * migrations do: every session the package writes records its proofs, and
     * every access token for a session derives `auth_time` and `amr` from them.
     *
     * @return void
     */
    public static function ensureProofTables(): void
    {
        self::ensureTable('authentication_proofs', static function (Blueprint $blueprint): void {
            $blueprint->uuid('id')->primary();
            $blueprint->string('session_id');
            $blueprint->string('kind', 40);
            $blueprint->string('purpose', 32);
            $blueprint->string('method');
            $blueprint->string('channel_kind', 32);
            $blueprint->string('channel_reference')->nullable();
            $blueprint->string('factor_reference')->nullable();
            $blueprint->boolean('user_presence')->nullable();
            $blueprint->boolean('user_verification')->nullable();
            $blueprint->boolean('backup_eligible')->nullable();
            $blueprint->boolean('backup_state')->nullable();
            $blueprint->boolean('phishing_resistant')->nullable();
            $blueprint->string('key_protection', 16)->nullable();
            $blueprint->boolean('accepted')->nullable();
            $blueprint->boolean('multifactor')->nullable();
            $blueprint->boolean('additional_verification')->nullable();
            $blueprint->text('evidence')->nullable();
            $blueprint->string('methods', 1024);
            $blueprint->string('authenticatable_type');
            $blueprint->string('authenticatable_id');
            $blueprint->string('guard');
            $blueprint->dateTime('authenticated_at', 0);
            $blueprint->dateTime('voided_at', 0)->nullable();
            $blueprint->dateTime('created_at', 0)->nullable();
            $blueprint->index(['session_id', 'kind', 'authenticated_at'], 'authentication_proofs_session_index');
        });

        self::ensureTable('authentication_provenance', static function (Blueprint $blueprint): void {
            $blueprint->string('session_id')->primary();
            $blueprint->string('connection_id');
            $blueprint->string('tenant_id')->nullable();
            $blueprint->dateTime('provider_authenticated_at', 0)->nullable();
            $blueprint->text('accepted_evidence')->nullable();
            $blueprint->dateTime('provider_session_expires_at', 0)->nullable();
            $blueprint->string('policy_version', 64)->nullable();
            $blueprint->string('link_id')->nullable();
            $blueprint->text('provider_context')->nullable();
            $blueprint->dateTime('created_at', 0)->nullable();
            $blueprint->index('connection_id', 'authentication_provenance_provider_index');
            $blueprint->index(['tenant_id', 'connection_id'], 'authentication_provenance_tenant_index');
        });

        self::ensureTable('authentication_connection_guards', static function (Blueprint $blueprint): void {
            $blueprint->string('connection_id');
            $blueprint->unsignedSmallInteger('slot');
            $blueprint->primary(['connection_id', 'slot'], 'authentication_connection_guards_primary');
        });
    }

    /**
     * Create the machine client table: a non-human identity that acts as its
     * own principal.
     *
     * @return void
     */
    public static function ensureMachineClientTable(): void
    {
        self::ensureTable('machine_clients', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('email')->unique();
            $blueprint->string('password')->nullable();
            $blueprint->boolean('is_active')->default(true);
            $blueprint->timestamps();
        });
    }

    /**
     * Create the table of identities that sign in by a one-time code sent to
     * their phone number or email address.
     *
     * @return void
     */
    public static function ensureCodeIdentityTable(): void
    {
        self::ensureTable('code_identities', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('phone')->nullable()->unique();
            $blueprint->dateTime('phone_verified_at', 0)->nullable();
            $blueprint->string('email')->nullable()->unique();
            $blueprint->dateTime('email_verified_at', 0)->nullable();
            $blueprint->string('password')->nullable();
            $blueprint->boolean('is_active')->default(true);
            $blueprint->datetimes(0);
        });
    }

    /**
     * Create the API keys table, as the shipped migration does.
     *
     * @return void
     */
    public static function ensureApiKeyTable(): void
    {
        self::ensureTable('api_keys', static function (Blueprint $blueprint): void {
            $blueprint->uuid('id')->primary();
            $blueprint->string('public_id', 64)->unique();
            $blueprint->char('secret_hash', 64);
            $blueprint->string('guard');
            $blueprint->string('name')->nullable();
            $blueprint->string('authenticatable_type');
            $blueprint->string('authenticatable_id');
            $blueprint->string('principal_type');
            $blueprint->string('principal_id');
            $blueprint->string('tenant_type')->nullable();
            $blueprint->string('tenant_id')->nullable();
            $blueprint->text('scopes');
            $blueprint->dateTime('expires_at', 0)->nullable();
            $blueprint->dateTime('last_used_at', 0)->nullable();
            $blueprint->dateTime('rotated_at', 0)->nullable();
            $blueprint->uuid('replaced_by')->nullable();
            $blueprint->dateTime('revoked_at', 0)->nullable();
            $blueprint->datetimes(0);
            $blueprint->index(['authenticatable_type', 'authenticatable_id']);
            $blueprint->index(['principal_type', 'principal_id']);
        });
    }

    /**
     * Create the attempt limiter's counters table, as the shipped migration
     * does.
     *
     * @return void
     */
    public static function ensureRateLimitTable(): void
    {
        self::ensureTable('rate_limits', static function (Blueprint $blueprint): void {
            $blueprint->char('key', 64)->primary();
            $blueprint->unsignedInteger('hits');
            $blueprint->dateTime('window_ends_at', 0)->index();
        });
    }

    /**
     * Create the one-time codes table, as the shipped migration does.
     *
     * @return void
     */
    public static function ensureOneTimeCodeTable(): void
    {
        self::ensureTable('one_time_codes', static function (Blueprint $blueprint): void {
            $blueprint->char('id', 64)->primary();
            $blueprint->uuid('challenge_id');
            $blueprint->char('context', 64)->nullable();
            $blueprint->string('purpose', 32);
            $blueprint->string('guard');
            $blueprint->uuid('issue_id');
            $blueprint->char('code_hash', 64);
            $blueprint->unsignedSmallInteger('attempts');
            $blueprint->unsignedSmallInteger('deliveries');
            $blueprint->dateTime('window_started_at', 0);
            $blueprint->dateTime('issued_at', 0);
            $blueprint->dateTime('expires_at', 0)->index();
            $blueprint->dateTime('consumed_at', 0)->nullable();
        });
    }

    /**
     * The state, generation, start and deadlines of a session that starts
     * active now, with the package's default lifetimes: waiting on nothing,
     * superseding nothing, never switched and acting in no tenant, with a new
     * generation on every call, as the session service writes for every session
     * it inserts. Every state column is set, so the saved session reads as the
     * row would load.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @return array{status: string, requires: null, pending_key: null, supersedes_session_id: null, supersedes_refresh_key: null, attempt_windows: null, tenant_id: null, switched_at: null, generation: string, signed_in_at: \Carbon\CarbonInterface, idle_expires_at: \Carbon\CarbonInterface, absolute_expires_at: \Carbon\CarbonInterface}
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    public static function liveSession(): array
    {
        return [
            'status'                 => SessionStatus::ACTIVE->value,
            'requires'               => null,
            'pending_key'            => null,
            'supersedes_session_id'  => null,
            'supersedes_refresh_key' => null,
            'attempt_windows'        => null,
            'tenant_id'              => null,
            'switched_at'            => null,
            'generation'             => Str::uuid7()->toString(),
            'signed_in_at'           => Carbon::now(),
            'idle_expires_at'        => Carbon::now()->addDays(90),
            'absolute_expires_at'    => Carbon::now()->addDays(180),
        ];
    }

    /**
     * A session the guard's password sign-in started now: the guard and method
     * a session records, which refresh and the bearer path check, and the
     * tenant it acts in (the principal's own, as a sign-in records it), with
     * the rest of `liveSession()`.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  string  $guard
     * @param  ?string  $tenantId
     * @return array{status: string, requires: null, pending_key: null, supersedes_session_id: null, supersedes_refresh_key: null, attempt_windows: null, tenant_id: ?string, switched_at: null, generation: string, signed_in_at: \Carbon\CarbonInterface, idle_expires_at: \Carbon\CarbonInterface, absolute_expires_at: \Carbon\CarbonInterface, guard: string, sign_in_method: string}
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    public static function signedIn(string $guard, ?string $tenantId = null): array
    {
        return [...self::liveSession(), 'tenant_id' => $tenantId, 'guard' => $guard, 'sign_in_method' => 'password'];
    }

    /**
     * Record on a session a fixture saved itself the first-factor proof the
     * password sign-in `signedIn()` describes would have recorded, at its
     * `signed_in_at`, so the access tokens issued for it carry the `auth_time`
     * and `amr` a real sign-in's would.
     *
     * @param  \SineMacula\Laravel\Authentication\Models\Session  $session
     * @return void
     *
     * @throws \LogicException
     */
    public static function recordFirstFactor(Session $session): void
    {
        $guard    = $session->getGuard()      ?? throw new \LogicException('A fixture session records the guard it was signed in to.');
        $signedIn = $session->getSignedInAt() ?? throw new \LogicException('A fixture session records when it was signed in.');
        $at       = CarbonImmutable::instance($signedIn);
        $proof    = new NewProof(ProofKind::FIRST_FACTOR, Purpose::SIGN_IN, 'password', new Channel(ChannelKind::PASSWORD), null, new ObservedProperties, null, ['pwd'], $at);

        ProofWriter::record($session, $guard, $proof);
    }

    /**
     * Create a table from its blueprint definition unless it already exists.
     *
     * @param  string  $table
     * @param  \Closure(\Illuminate\Database\Schema\Blueprint): void  $definition
     * @return void
     */
    private static function ensureTable(string $table, \Closure $definition): void
    {
        $schema = BenchDatabase::schema();

        if ($schema->hasTable($table)) {
            return;
        }

        $schema->create($table, $definition);
    }
}
