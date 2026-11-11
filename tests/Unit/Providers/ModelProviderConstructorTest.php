<?php

declare(strict_types = 1);

namespace Tests\Unit\Providers;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Database\Connection;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use Mockery\MockInterface;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Providers\ModelProvider;
use Tests\Unit\Stubs\PlainIdentityFixture;
use Tests\Unit\Stubs\StubAuthenticatableModel;
use Tests\Unit\Stubs\StubModel;

/**
 * Unit tests for the `ModelProvider` constructor validation, `createModel()`
 * factory, and credential-key filter regex.
 *
 * @internal
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
#[CoversClass(ModelProvider::class)]
final class ModelProviderConstructorTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    /** @var string Shared exception message for the type-shape guard. */
    private const string MODEL_AUTH_MESSAGE = 'must be both an Eloquent Model and implement Authenticatable';

    /** @var \Illuminate\Contracts\Hashing\Hasher&\Mockery\MockInterface Mocked password hasher collaborator. */
    private MockInterface $hasher;

    /**
     * Setup.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->hasher = \Mockery::mock(Hasher::class);
    }

    /**
     * The constructor refuses an empty model class string.
     *
     * @return void
     */
    public function testConstructorRejectsEmptyModelClass(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('ModelProvider requires a non-empty Eloquent model class - set `auth.providers.<name>.model`'
            . ' to a fully-qualified class name in config/auth.php.');

        $provider = new ModelProvider($this->hasher, '');

        unset($provider);
    }

    /**
     * The constructor refuses an unknown class name.
     *
     * @return void
     */
    public function testConstructorRejectsUnknownModelClass(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('ModelProvider received unknown class "App\Models\Nope" as its identity model.');

        $provider = new ModelProvider($this->hasher, 'App\Models\Nope');

        unset($provider);
    }

    /**
     * The constructor refuses a class that is neither an Eloquent `Model` nor
     * `Authenticatable`.
     *
     * @return void
     */
    public function testConstructorRejectsClassThatIsNotEloquentModelAuthenticatable(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage(self::MODEL_AUTH_MESSAGE);

        $provider = new ModelProvider($this->hasher, \stdClass::class);

        unset($provider);
    }

    /**
     * The constructor refuses a class that extends `Model` but does not
     * implement `Authenticatable`.
     *
     * @return void
     */
    public function testConstructorRejectsModelWithoutAuthenticatable(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage(self::MODEL_AUTH_MESSAGE);

        $provider = new ModelProvider($this->hasher, StubModel::class);

        unset($provider);
    }

    /**
     * The constructor refuses a class that implements `Authenticatable` but
     * does not extend `Model`.
     *
     * @return void
     */
    public function testConstructorRejectsAuthenticatableWithoutModel(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage(self::MODEL_AUTH_MESSAGE);

        $provider = new ModelProvider($this->hasher, PlainIdentityFixture::class);

        unset($provider);
    }

    /**
     * `createModel()` returns a fresh instance of the configured class.
     *
     * @return void
     */
    public function testCreateModelReturnsFreshConfiguredClassInstance(): void
    {
        $provider = new class ($this->hasher, StubAuthenticatableModel::class) extends ModelProvider {
            /**
             * Build a model as the provider does.
             *
             * @return \Illuminate\Contracts\Auth\Authenticatable&\Illuminate\Database\Eloquent\Model
             */
            public function build(): Authenticatable&Model
            {
                return $this->createModel();
            }
        };

        $first  = $provider->build();
        $second = $provider->build();

        self::assertInstanceOf(StubAuthenticatableModel::class, $first);
        self::assertInstanceOf(StubAuthenticatableModel::class, $second);
        self::assertNotSame($first, $second, 'Each createModel() call must return a fresh instance.');
    }

    /**
     * Keys that are not valid SQL identifiers never reach `where()`.
     *
     * @return void
     */
    public function testRetrieveByCredentialsDropsKeysWithInvalidIdentifierShape(): void
    {
        $provider = new ModelProvider($this->hasher, StubAuthenticatableModel::class);

        self::assertNull($provider->retrieveByCredentials([
            'email; drop table users' => 'malicious',
        ]));
    }

    /**
     * Password-family column names the filter drops.
     *
     * @return \Generator<string, array{0: string}>
     */
    public static function providePasswordKeyVariants(): iterable
    {
        yield from [
            'password'              => ['password'],
            'old_password'          => ['old_password'],
            'password_confirmation' => ['password_confirmation'],
            'user_password'         => ['user_password'],
            'PASSWORD-uppercase'    => ['PASSWORD'],
            'Password-title-case'   => ['Password'],
        ];
    }

    /**
     * Every key whose name contains `password`, in any case, is dropped.
     *
     * @param  string  $key
     * @return void
     */
    #[DataProvider('providePasswordKeyVariants')]
    public function testRetrieveByCredentialsDropsPasswordKeyVariant(string $key): void
    {
        $provider = new ModelProvider($this->hasher, StubAuthenticatableModel::class);

        self::assertNull($provider->retrieveByCredentials([$key => 'secret']));
    }

    /**
     * A key that only contains `pass` is kept.
     *
     * @return void
     */
    public function testRetrieveByCredentialsDoesNotDropPassSubstringOnlyKeys(): void
    {
        $builder = \Mockery::mock(Builder::class);
        $builder->shouldReceive('useWritePdo')
            ->once()
            ->andReturnSelf();
        $builder->shouldReceive('where')
            ->once()
            ->with('pass', 'something')
            ->andReturnSelf();
        $builder->shouldReceive('first')
            ->once()
            ->andReturn(new StubAuthenticatableModel);

        $provider = $this->makeFilteringProvider($builder);

        self::assertNotNull($provider->retrieveByCredentials(['pass' => 'something']));
    }

    /**
     * No rehash happens when the password is not a string.
     *
     * @return void
     */
    public function testRehashPasswordIfRequiredNoOpsWhenPasswordNotString(): void
    {
        $provider = new ModelProvider($this->hasher, StubAuthenticatableModel::class);

        $user = \Mockery::mock(Authenticatable::class);
        $this->hasher->shouldNotReceive('needsRehash');
        $this->hasher->shouldNotReceive('make');

        $provider->rehashPasswordIfRequired($user, ['password' => 123]);

        self::assertTrue(true, 'rehashPasswordIfRequired returned without touching the hasher.');
    }

    /**
     * A boolean credential value is applied as a `where()` clause.
     *
     * @return void
     */
    public function testRetrieveByCredentialsAppliesBoolCredentialAsWhereClause(): void
    {
        $builder = \Mockery::mock(Builder::class);
        $builder->shouldReceive('useWritePdo')
            ->once()
            ->andReturnSelf();
        $builder->shouldReceive('where')
            ->once()
            ->with('is_active', true)
            ->andReturnSelf();
        $builder->shouldReceive('first')
            ->once()
            ->andReturnNull();

        $provider = $this->makeFilteringProvider($builder);

        self::assertNull($provider->retrieveByCredentials(['is_active' => true]));
    }

    /**
     * A `Stringable` credential value is applied as a `where()` clause.
     *
     * @return void
     */
    public function testRetrieveByCredentialsAppliesStringableCredentialAsWhereClause(): void
    {
        $stringable = new class implements \Stringable {
            /**
             * Return the stringable value.
             *
             * @return string
             */
            #[\Override]
            public function __toString(): string
            {
                return 'stringable-value';
            }
        };

        $builder = \Mockery::mock(Builder::class);
        $builder->shouldReceive('useWritePdo')
            ->once()
            ->andReturnSelf();
        $builder->shouldReceive('where')
            ->once()
            ->with('token', $stringable)
            ->andReturnSelf();
        $builder->shouldReceive('first')
            ->once()
            ->andReturnNull();

        $provider = $this->makeFilteringProvider($builder);

        self::assertNull($provider->retrieveByCredentials(['token' => $stringable]));
    }

    /**
     * `retrieveByCredentials()` returns `null` without querying when a
     * credential value has an unsupported type.
     *
     * @return void
     */
    public function testRetrieveByCredentialsReturnsNullForUnsupportedValueType(): void
    {
        $builder = \Mockery::mock(Builder::class);
        $builder->shouldReceive('useWritePdo')
            ->once()
            ->andReturnSelf();
        $builder->shouldNotReceive('where');
        $builder->shouldNotReceive('whereIn');
        $builder->shouldNotReceive('first');

        /** @var \Mockery\MockInterface&\Tests\Unit\Stubs\StubAuthenticatableModel $model */
        $model = \Mockery::mock(StubAuthenticatableModel::class)->makePartial();
        $model->shouldReceive('newQuery')
            ->andReturn($builder);
        $model->shouldReceive('getAuthIdentifierName')
            ->andReturn('id');
        $model->shouldReceive('getConnection')
            ->andReturn($this->mockConnection());

        $provider = new class ($this->hasher, StubAuthenticatableModel::class, $model) extends ModelProvider {
            /**
             * Constructor.
             *
             * @param  \Illuminate\Contracts\Hashing\Hasher  $hasher
             * @param  string  $modelClass
             * @param  \Illuminate\Contracts\Auth\Authenticatable&\Illuminate\Database\Eloquent\Model  $instance
             */
            public function __construct(

                // Password hasher forwarded to the parent provider.
                Hasher $hasher,

                // Model class name forwarded to the parent provider.
                string $modelClass,

                /** Pre-built model instance returned from createModel(). */
                private readonly Authenticatable&Model $instance,
            ) {
                parent::__construct($hasher, $modelClass);
            }

            /**
             * Return the pre-built model.
             *
             * @return \Illuminate\Contracts\Auth\Authenticatable&\Illuminate\Database\Eloquent\Model
             */
            #[\Override]
            protected function createModel(): Authenticatable&Model
            {
                return $this->instance;
            }
        };

        self::assertNull($provider->retrieveByCredentials([
            'email' => new \stdClass,
        ]));
    }

    /**
     * Build a `ModelProvider` whose model queries through the given builder.
     *
     * @param  \Mockery\MockInterface  $builder
     * @return \SineMacula\Laravel\Authentication\Providers\ModelProvider
     */
    private function makeFilteringProvider(MockInterface $builder): ModelProvider
    {
        /** @var \Mockery\MockInterface&\Tests\Unit\Stubs\StubAuthenticatableModel $model */
        $model = \Mockery::mock(StubAuthenticatableModel::class)->makePartial();
        $model->shouldReceive('newQuery')
            ->andReturn($builder);
        $model->shouldReceive('getConnection')
            ->andReturn($this->mockConnection());

        return new class ($this->hasher, StubAuthenticatableModel::class, $model) extends ModelProvider {
            /**
             * Constructor.
             *
             * @param  \Illuminate\Contracts\Hashing\Hasher  $hasher
             * @param  string  $modelClass
             * @param  \Illuminate\Contracts\Auth\Authenticatable&\Illuminate\Database\Eloquent\Model  $instance
             */
            public function __construct(

                // Password hasher forwarded to the parent provider.
                Hasher $hasher,

                // Model class name forwarded to the parent provider.
                string $modelClass,

                /** Pre-built model instance returned from createModel(). */
                private readonly Authenticatable&Model $instance,
            ) {
                parent::__construct($hasher, $modelClass);
            }

            /**
             * Return the pre-built model.
             *
             * @return \Illuminate\Contracts\Auth\Authenticatable&\Illuminate\Database\Eloquent\Model
             */
            #[\Override]
            protected function createModel(): Authenticatable&Model
            {
                return $this->instance;
            }
        };
    }

    /**
     * Build a database connection double the lookup pins to the write
     * connection for its duration.
     *
     * @return \Illuminate\Database\Connection&\Mockery\MockInterface
     */
    private function mockConnection(): MockInterface
    {
        $connection = \Mockery::mock(Connection::class);
        $connection->shouldReceive('useWriteConnectionWhenReading')
            ->andReturnSelf();

        return $connection;
    }
}
