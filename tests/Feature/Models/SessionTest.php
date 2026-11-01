<?php

declare(strict_types = 1);

namespace Tests\Feature\Models;

use Carbon\Carbon;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Eloquent\Relations\MorphTo;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Schema;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use Orchestra\Testbench\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Models\Session;
use Tests\Concerns\InteractsWithSessionRecords;
use Tests\Integration\Fixtures\SeparateConnectionSession;

/**
 * Feature tests for the shipped Session Eloquent model.
 *
 * Uses Orchestra Testbench with an in-memory sqlite connection and a
 * manually-created `authentication_sessions` table, so the test does not
 * transitively depend on the package migration file.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Session::class)]
final class SessionTest extends TestCase
{
    use InteractsWithSessionRecords, MockeryPHPUnitIntegration;

    /** @var string Shared timestamp for session factory tests. */
    private const string FIXED_TIMESTAMP = '2026-04-06 12:00:00';

    /**
     * Set up the in-memory schema for the Session table after the Testbench
     * application is ready.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        self::createSessionRecordTable('authentication_sessions');
    }

    /**
     * Drop the in-memory schema once each test has completed.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Schema::dropIfExists('authentication_sessions');

        parent::tearDown();
    }

    /**
     * Asserts that swapping `authentication.session.table` at runtime is
     * observed by the next Session instantiation. The model reads the config
     * lazily in its constructor, so no cache priming is required - tests and
     * runtime tenancy swaps pick up the new value immediately.
     *
     * @return void
     */
    public function testConstructorReadsConfiguredTableLazilyOnEachInstantiation(): void
    {
        config()->set('authentication.session.table', 'custom_sessions');

        $session = new Session;

        self::assertSame('custom_sessions', $session->getTable());
    }

    /**
     * The model takes the storage connection, read on each instantiation,
     * unless its class names a connection of its own; a storage connection that
     * is not a name fails closed rather than falling back to the default.
     *
     * @return void
     */
    public function testTakesTheStorageConnectionUnlessTheClassNamesItsOwn(): void
    {
        self::assertNull((new Session)->getConnectionName());

        config()->set('authentication.storage.connection', 'package_store');

        self::assertSame('package_store', (new Session)->getConnectionName());
        self::assertSame(SeparateConnectionSession::CONNECTION, (new SeparateConnectionSession)->getConnectionName());

        config()->set('authentication.storage.connection', true);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('`authentication.storage.connection` must be a connection name');

        new Session;
    }

    /**
     * Asserts the Session model populates the `id` column with a 36-character
     * UUID v7 on insert via HasUuids.
     *
     * @return void
     */
    public function testGeneratesUuidPrimaryKeyOnInsert(): void
    {
        $session = new Session;
        $session->save();

        self::assertIsString($session->id);
        self::assertSame(36, strlen($session->id));
    }

    /**
     * Every timestamp column is cast to a Carbon instance when read back.
     *
     * @return void
     */
    public function testCastsTimestampColumnsToCarbon(): void
    {
        $columns = ['last_used_at', 'refresh_rotated_at', 'idle_expires_at', 'absolute_expires_at', 'revoked_at'];

        $session = new Session;
        $session->forceFill(array_fill_keys($columns, self::FIXED_TIMESTAMP))->save();

        $fresh = Session::query()->findOrFail($session->id);

        foreach ($columns as $column) {
            self::assertInstanceOf(Carbon::class, $fresh->getAttribute($column), $column);
            self::assertSame(self::FIXED_TIMESTAMP, $fresh->getAttribute($column)->format('Y-m-d H:i:s'), $column);
        }
    }

    /**
     * Asserts the string columns are cast to strings when read back, so scalar
     * values assigned to them never leak through with their original type.
     *
     * @return void
     */
    public function testCastsStringColumnsToString(): void
    {
        $columns = [
            'generation',
            'authenticatable_type',
            'authenticatable_id',
            'principal_type',
            'principal_id',
            'guard',
            'sign_in_method',
            'client_name',
            'platform',
            'created_ip',
            'created_user_agent',
            'last_used_ip',
            'last_used_user_agent',
            'refresh_key',
            'previous_refresh_key',
            'revoked_reason',
        ];

        $session = new Session;
        $session->forceFill(array_combine($columns, range(1, count($columns))));

        foreach ($columns as $index => $column) {
            self::assertSame((string) ($index + 1), $session->getAttribute($column), $column);
        }
    }

    /**
     * Only the client-described metadata is mass assignable: ownership, the
     * request-derived columns, and the session state are set with `forceFill()`
     * or by the package's own writes.
     *
     * @return void
     */
    public function testOnlyClientMetadataIsMassAssignable(): void
    {
        $session = new Session([
            'client_name'          => 'Work laptop',
            'platform'             => 'macOS',
            'authenticatable_type' => 'App\Models\User',
            'authenticatable_id'   => '1',
            'principal_type'       => 'App\Models\Member',
            'principal_id'         => '2',
            'guard'                => 'api',
            'sign_in_method'       => 'password',
            'created_ip'           => '203.0.113.7',
            'created_user_agent'   => 'Mozilla/5.0',
            'last_used_at'         => self::FIXED_TIMESTAMP,
            'last_used_ip'         => '203.0.113.7',
            'last_used_user_agent' => 'Mozilla/5.0',
            'refresh_key'          => 'digest',
            'previous_refresh_key' => 'previous-digest',
            'refresh_rotated_at'   => self::FIXED_TIMESTAMP,
            'idle_expires_at'      => self::FIXED_TIMESTAMP,
            'absolute_expires_at'  => self::FIXED_TIMESTAMP,
            'revoked_at'           => self::FIXED_TIMESTAMP,
            'revoked_reason'       => 'rotation_reuse',
        ]);

        self::assertSame(['client_name' => 'Work laptop', 'platform' => 'macOS'], $session->getAttributes());
    }

    /**
     * The shipped model leaves both refresh digests out of its serialised form.
     *
     * @return void
     */
    public function testDigestsAreHiddenFromSerialization(): void
    {
        $session = new Session;
        $session->forceFill([
            'client_name'          => 'Work laptop',
            'refresh_key'          => 'current-digest',
            'previous_refresh_key' => 'previous-digest',
        ])->save();

        $serialized = Session::query()->findOrFail($session->id)->toArray();

        self::assertSame('Work laptop', $serialized['client_name']);
        self::assertArrayNotHasKey('refresh_key', $serialized);
        self::assertArrayNotHasKey('previous_refresh_key', $serialized);
    }

    /**
     * Asserts `authenticatable()` returns a polymorphic MorphTo relation.
     *
     * @return void
     */
    public function testAuthenticatableRelationIsMorphTo(): void
    {
        $session = new Session;

        self::assertInstanceOf(MorphTo::class, $session->authenticatable());
    }

    /**
     * `principal()` is a polymorphic relation over the principal columns, which
     * are strings so a principal with any key type can be recorded.
     *
     * @return void
     */
    public function testPrincipalRelationIsMorphToOverThePrincipalColumns(): void
    {
        $relation = (new Session)->principal();

        self::assertSame('principal_type', $relation->getMorphType());
        self::assertSame('principal_id', $relation->getForeignKeyName());
    }

    /**
     * Asserts the shipped model satisfies the explicit Eloquent-backed session
     * persistence boundary used by refresh rotation and last-use writes.
     *
     * @return void
     */
    public function testImplementsEloquentSessionContract(): void
    {
        self::assertInstanceOf(EloquentSession::class, new Session);
    }

    /**
     * Asserts the model falls back to the literal `'authentication_sessions'`
     * table when the configured table value is the empty string. The
     * conditional collapses the empty value to the default rather than letting
     * Eloquent issue queries against the empty table name.
     *
     * @return void
     */
    public function testFallsBackToDefaultTableNameWhenConfiguredValueIsEmpty(): void
    {
        config()->set('authentication.session.table', '');

        $session = new Session;

        self::assertSame('authentication_sessions', $session->getTable());
    }

    /**
     * Asserts the model takes the `'authentication_sessions'` table when the
     * session block has no `table` key at all.
     *
     * @return void
     */
    public function testTakesTheDefaultTableNameWhenTheKeyIsAbsent(): void
    {
        config()->set('authentication.session', ['model' => Session::class]);

        self::assertFalse(config()->has('authentication.session.table'));
        self::assertSame('authentication_sessions', (new Session)->getTable());
    }

    /**
     * Asserts the model falls back to `'authentication_sessions'` when the
     * Config facade throws while reading `session.table`.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testFallsBackToDefaultTableNameWhenConfigFacadeThrows(): void
    {
        $previous = $this->app?->make(ConfigRepository::class);

        $config = \Mockery::mock(ConfigRepository::class)->makePartial();
        $config->shouldReceive('string')
            ->with('authentication.session.table', 'authentication_sessions')
            ->andThrow(new \RuntimeException('config repository unavailable'));

        $this->app?->instance('config', $config);
        Config::clearResolvedInstance('config');

        try {
            $session = new Session;

            self::assertSame('authentication_sessions', $session->getTable());
        } finally {
            if ($previous !== null) {
                $this->app->instance('config', $previous);
            }
            Config::clearResolvedInstance('config');
        }
    }

    /**
     * Asserts `getLastUsedAt()` returns the Carbon instance when the attribute
     * holds a datetime, and null when the attribute is null, through the
     * shipped model.
     *
     * @return void
     */
    public function testGetLastUsedAtReturnsCarbonOrNull(): void
    {
        $session = new Session;
        $session->forceFill(['last_used_at' => self::FIXED_TIMESTAMP])->save();

        $fresh = Session::query()->findOrFail($session->id);

        self::assertInstanceOf(Carbon::class, $fresh->getLastUsedAt());

        $nilSession = new Session;
        $nilSession->save();

        $freshNil = Session::query()->findOrFail($nilSession->id);

        self::assertNull($freshNil->getLastUsedAt());
    }

    /**
     * The identifier of the shipped model is its generated primary key.
     *
     * @return void
     */
    public function testSessionIdentifierIsThePrimaryKey(): void
    {
        $session = new Session;
        $session->save();

        self::assertSame($session->getKey(), $session->getSessionIdentifier());
        self::assertSame($session->id, Session::query()->whereKey($session->getSessionIdentifier())->firstOrFail()->id);
    }

    /**
     * Asserts `getRefreshKey()` returns null when the attribute is null.
     * Exercises the null branch in `ActsAsSession::getRefreshKey()`.
     *
     * @return void
     */
    public function testGetRefreshKeyReturnsNullWhenNotSet(): void
    {
        $session = new Session;
        $session->save();

        $fresh = Session::query()->findOrFail($session->id);

        self::assertNull($fresh->getRefreshKey());
    }

    /**
     * Define the test environment: in-memory sqlite and package config defaults
     * that the Session model depends on.
     *
     * @param  mixed  $app
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        assert($app instanceof Application);

        /** @var \Illuminate\Config\Repository $config */
        $config = $app->make(ConfigRepository::class);

        $config->set('database.default', 'testing');
        $config->set('database.connections.testing', [
            'driver'   => 'sqlite',
            'database' => ':memory:',
            'prefix'   => '',
        ]);

        $config->set('authentication.session.model', Session::class);
        $config->set('authentication.session.table', 'authentication_sessions');
    }
}
