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
 * Feature tests for the shipped `Session` Eloquent model.
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
     * A change to `authentication.session.table` applies to the next instance
     * built.
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
     * The model takes the storage connection unless its class names its own,
     * and fails closed on one that is not a name.
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
     * An inserted session gets a UUID v7 primary key.
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
     * String columns read back as strings, whatever scalar type was assigned.
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
     * The issuance guard's sequence reads back as an integer, whatever type the
     * driver returns it as.
     *
     * @return void
     */
    public function testCastsTheIssuanceSequenceToAnInteger(): void
    {
        $session = new Session;
        $session->forceFill(['issuance_sequence' => '3']);

        self::assertSame(3, $session->getAttribute('issuance_sequence'));
    }

    /**
     * Only client-described metadata is mass assignable, so a new session keeps
     * the status it starts with.
     *
     * @return void
     */
    public function testOnlyClientMetadataIsMassAssignable(): void
    {
        $session = new Session([
            'client_name'            => 'Work laptop',
            'platform'               => 'macOS',
            'authenticatable_type'   => 'App\Models\User',
            'authenticatable_id'     => '1',
            'principal_type'         => 'App\Models\Member',
            'principal_id'           => '2',
            'guard'                  => 'api',
            'sign_in_method'         => 'password',
            'created_ip'             => '203.0.113.7',
            'created_user_agent'     => 'Mozilla/5.0',
            'last_used_at'           => self::FIXED_TIMESTAMP,
            'last_used_ip'           => '203.0.113.7',
            'last_used_user_agent'   => 'Mozilla/5.0',
            'refresh_key'            => 'digest',
            'previous_refresh_key'   => 'previous-digest',
            'refresh_rotated_at'     => self::FIXED_TIMESTAMP,
            'idle_expires_at'        => self::FIXED_TIMESTAMP,
            'absolute_expires_at'    => self::FIXED_TIMESTAMP,
            'revoked_at'             => self::FIXED_TIMESTAMP,
            'revoked_reason'         => 'rotation_reuse',
            'status'                 => 'pending',
            'requires'               => '["mfa"]',
            'pending_key'            => 'pending-digest',
            'supersedes_session_id'  => 'another-session',
            'supersedes_refresh_key' => 'another-digest',
            'attempt_windows'        => '[]',
            'tenant_id'              => 'tenant-1',
            'tenant_policy_version'  => 'v1',
            'switched_at'            => self::FIXED_TIMESTAMP,
        ]);

        self::assertSame(['status' => 'active', 'client_name' => 'Work laptop', 'platform' => 'macOS'], $session->getAttributes());
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
     * `authenticatable()` is a `MorphTo` relation.
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
     * The shipped model implements the `EloquentSession` contract.
     *
     * @return void
     */
    public function testImplementsEloquentSessionContract(): void
    {
        self::assertInstanceOf(EloquentSession::class, new Session);
    }

    /**
     * An empty configured table falls back to `authentication_sessions`.
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
     * A session block with no `table` key takes `authentication_sessions`.
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
     * The model falls back to `authentication_sessions` when the Config facade
     * throws.
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
     * `getLastUsedAt()` returns the Carbon instance, or null when the attribute
     * is null.
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
     * `getRefreshKey()` returns null when the attribute is null.
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
