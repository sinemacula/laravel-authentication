<?php

declare(strict_types = 1);

namespace Tests\Integration\Database;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Connection;
use Illuminate\Database\ConnectionResolverInterface;
use Illuminate\Database\DatabaseManager;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\ModelNotFoundException;
use Illuminate\Database\Schema\Blueprint;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Database\PinningConnectionResolver;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use SineMacula\Laravel\Authentication\Models\Session;
use Tests\Concerns\InteractsWithLaggingReplica;
use Tests\Concerns\InteractsWithSessionRecords;
use Tests\Integration\Fixtures\LandlordTenant;
use Tests\TestCase;

/**
 * Integration tests for `WriteConnection` against a read/write split whose
 * replica lags behind the primary.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(WriteConnection::class)]
#[CoversClass(PinningConnectionResolver::class)]
final class WriteConnectionTest extends TestCase
{
    use InteractsWithLaggingReplica, InteractsWithSessionRecords;

    /**
     * Remove the temporary primary and replica files.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        parent::tearDown();

        $this->removeLaggingReplicaFiles();
    }

    /**
     * `query()` routes a lookup to the write connection and returns the
     * builder.
     *
     * @return void
     */
    public function testQueryRoutesTheLookupToTheWriteConnection(): void
    {
        $session = $this->seedSession();

        self::assertNull(Session::query()->find($session->getKey()));

        $builder = Session::query();

        self::assertSame($builder, WriteConnection::query($builder));
        self::assertInstanceOf(Session::class, $builder->find($session->getKey()));
    }

    /**
     * Reads inside the callback go to the write connection, and to the replica
     * again afterwards.
     *
     * @return void
     */
    public function testDuringRoutesReadsToTheWriteConnectionOnlyForTheCallback(): void
    {
        $session = $this->seedSession();

        $found = WriteConnection::during(new Session, static fn (): ?Session => Session::query()->whereKey($session->getKey())->first());

        self::assertInstanceOf(Session::class, $found);
        self::assertNull(Session::query()->find($session->getKey()));
    }

    /**
     * A connection that already reads from the write PDO keeps doing so after
     * the callback.
     *
     * @return void
     */
    public function testDuringKeepsAConnectionThatAlreadyReadsFromTheWriter(): void
    {
        $session = $this->seedSession();

        $this->splitConnection()->useWriteConnectionWhenReading();

        WriteConnection::during(new Session, static fn (): null => null);

        self::assertInstanceOf(Session::class, Session::query()->find($session->getKey()));
    }

    /**
     * The previous read mode is restored when the callback throws.
     *
     * @return void
     */
    public function testDuringRestoresTheReadModeWhenTheCallbackThrows(): void
    {
        $session = $this->seedSession();

        try {
            WriteConnection::during(new Session, static fn (): Session => Session::query()->whereKey('missing')->firstOrFail());

            self::fail('The lookup inside the callback should have thrown.');
        } catch (ModelNotFoundException $exception) {
            self::assertSame(Session::class, $exception->getModel());
        }

        self::assertNull(Session::query()->find($session->getKey()));
    }

    /**
     * A model on another connection read inside the callback is read from that
     * connection's writer.
     *
     * @return void
     */
    public function testDuringPinsAnotherConnectionAModelResolvesInsideTheCallback(): void
    {
        $tenant = $this->seedLandlordTenant();

        $found = WriteConnection::during(new Session, static fn (): ?LandlordTenant => LandlordTenant::query()->whereKey($tenant->getKey())->first());

        self::assertInstanceOf(LandlordTenant::class, $found);
        self::assertNull(LandlordTenant::query()->find($tenant->getKey()));
    }

    /**
     * The model connection resolver is swapped only for the callback, also when
     * it throws.
     *
     * @return void
     */
    public function testDuringReinstatesTheModelConnectionResolver(): void
    {
        $resolver = Model::getConnectionResolver();

        $inside = WriteConnection::during(new Session, static fn (): ?ConnectionResolverInterface => Model::getConnectionResolver());

        self::assertInstanceOf(PinningConnectionResolver::class, $inside);
        self::assertSame($resolver, Model::getConnectionResolver());

        try {
            WriteConnection::during(new Session, static fn (): Session => Session::query()->whereKey('missing')->firstOrFail());

            self::fail('The lookup inside the callback should have thrown.');
        } catch (ModelNotFoundException) {
            self::assertSame($resolver, Model::getConnectionResolver());
        }
    }

    /**
     * A nested `during()` leaves the outer pin in place.
     *
     * @return void
     */
    public function testNestedDuringKeepsTheOuterPin(): void
    {
        $session = $this->seedSession();

        $found = WriteConnection::during(new Session, static function () use ($session): ?Session {

            WriteConnection::during(new Session, static fn (): ?Session => Session::query()->whereKey($session->getKey())->first());

            return Session::query()->whereKey($session->getKey())->first();
        });

        self::assertInstanceOf(Session::class, $found);
        self::assertNull(Session::query()->find($session->getKey()));
    }

    /**
     * Without a model connection resolver, the subject's own connection is
     * still pinned and no resolver is installed.
     *
     * @return void
     */
    public function testDuringPinsTheSubjectsConnectionWithoutAModelConnectionResolver(): void
    {
        $session    = $this->seedSession();
        $connection = $this->splitConnection();
        $resolver   = Model::getConnectionResolver();

        self::assertNotNull($resolver);

        $subject = \Mockery::mock(Session::class)->makePartial();
        $subject->shouldReceive('getConnection')->andReturn($connection);

        Model::unsetConnectionResolver();

        try {
            $found = WriteConnection::during($subject, static fn (): ?object => $connection->table('authentication_sessions')->where('id', $session->getKey())->first());

            self::assertNull(Model::getConnectionResolver());
        } finally {
            Model::setConnectionResolver($resolver);
        }

        self::assertNotNull($found);
        self::assertNull($connection->table('authentication_sessions')->where('id', $session->getKey())->first());
    }

    /**
     * For a subject that is not a model, only model reads inside the callback
     * go to the writer.
     *
     * @return void
     */
    public function testDuringPinsModelReadsForANonModelSubject(): void
    {
        $session    = $this->seedSession();
        $connection = $this->splitConnection();

        $found = WriteConnection::during(new \stdClass, static fn (): array => [
            'row'     => $connection->table('authentication_sessions')->where('id', $session->getKey())->first(),
            'session' => Session::query()->find($session->getKey()),
        ]);

        self::assertNull($found['row']);
        self::assertInstanceOf(Session::class, $found['session']);
        self::assertNull(Session::query()->find($session->getKey()));
    }

    /**
     * A model subject is handed over as a copy without its loaded relations,
     * read on the writer.
     *
     * @return void
     */
    public function testStoredHandsOverACopyWithoutRelationsReadOnTheWriter(): void
    {
        $session = $this->seedSession();
        $subject = new Session;
        $subject->forceFill(['id' => $session->getKey()]);
        $subject->setRelation('authenticatable', new Session);

        [$copy, $found] = WriteConnection::stored($subject, static fn (Session $stored): array => [$stored, Session::query()->find($session->getKey())]);

        self::assertNotSame($subject, $copy);
        self::assertSame($session->getKey(), $copy->getKey());
        self::assertFalse($copy->relationLoaded('authenticatable'));
        self::assertTrue($subject->relationLoaded('authenticatable'));
        self::assertInstanceOf(Session::class, $found);
        self::assertNull(Session::query()->find($session->getKey()));
    }

    /**
     * The copy may lazy-load under strict mode, while the subject stays strict.
     *
     * @return void
     */
    public function testStoredLetsTheCopyLazyLoadUnderStrictMode(): void
    {
        $subject                      = new Session;
        $subject->preventsLazyLoading = true;

        $copy = WriteConnection::stored($subject, static fn (Session $stored): Session => $stored);

        self::assertFalse($copy->preventsLazyLoading);
        self::assertTrue($subject->preventsLazyLoading);
    }

    /**
     * A subject that is not a model is handed over as it is.
     *
     * @return void
     */
    public function testStoredHandsOverANonModelSubjectAsItIs(): void
    {
        $session = $this->seedSession();
        $subject = new \stdClass;

        [$given, $found] = WriteConnection::stored($subject, static fn (\stdClass $stored): array => [$stored, Session::query()->find($session->getKey())]);

        self::assertSame($subject, $given);
        self::assertInstanceOf(Session::class, $found);
    }

    /**
     * The constructor is private.
     *
     * @return void
     *
     * @SuppressWarnings("php:S3011")
     */
    public function testConstructorIsPrivate(): void
    {
        $reflection  = new \ReflectionClass(WriteConnection::class);
        $constructor = $reflection->getConstructor();

        self::assertNotNull($constructor);
        self::assertTrue($constructor->isPrivate());

        $instance = $reflection->newInstanceWithoutConstructor();
        $constructor->invoke($instance);

        self::assertInstanceOf(WriteConnection::class, $instance);
    }

    /**
     * Use the lagging split connection as the default connection.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        $this->configureLaggingReplica(app(ConfigRepository::class));
        $this->configureLaggingLandlordReplica(app(ConfigRepository::class));
    }

    /**
     * Create the package tables on the primary and the replica.
     *
     * @return void
     */
    #[\Override]
    protected function defineDatabaseMigrations(): void
    {
        $this->migratePackageTablesOnPrimaryAndReplica();
    }

    /**
     * Write a session through the split connection, so it exists on the primary
     * only.
     *
     * @return \SineMacula\Laravel\Authentication\Models\Session
     */
    private function seedSession(): Session
    {
        $session = new Session;
        $session->forceFill([
            ...self::liveSession(),
            'authenticatable_type' => 'identity',
            'authenticatable_id'   => '1',
        ])->save();

        return $session;
    }

    /**
     * Write an active tenant through the landlord split connection, so it
     * exists on the landlord primary only.
     *
     * @return \Tests\Integration\Fixtures\LandlordTenant
     */
    private function seedLandlordTenant(): LandlordTenant
    {
        $this->createOnPrimaryAndReplica('landlord_tenants', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('name');
            $blueprint->boolean('is_active')->default(true);
            $blueprint->timestamps();
        }, self::LANDLORD_PRIMARY_CONNECTION, self::LANDLORD_REPLICA_CONNECTION);

        $tenant = new LandlordTenant;
        $tenant->forceFill(['name' => 'Tenant', 'is_active' => true])->save();

        return $tenant;
    }

    /**
     * Resolve the split connection.
     *
     * @return \Illuminate\Database\Connection
     */
    private function splitConnection(): Connection
    {
        /** @var \Illuminate\Database\DatabaseManager $manager */
        $manager = app(DatabaseManager::class);

        return $manager->connection(self::SPLIT_CONNECTION);
    }
}
