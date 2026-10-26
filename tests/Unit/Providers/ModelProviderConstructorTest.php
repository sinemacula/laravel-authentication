<?php

declare(strict_types = 1);

namespace Tests\Unit\Providers;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Hashing\Hasher;
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
 * Split out of `ModelProviderTest` so each class stays focused on a single
 * behavioural slice.
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
        $this->expectExceptionMessage('non-empty Eloquent model class');

        $provider = new ModelProvider($this->hasher, '');

        unset($provider); // Constructor must throw before this point.
    }

    /**
     * The constructor refuses an unknown class name.
     *
     * @return void
     */
    public function testConstructorRejectsUnknownModelClass(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('App\Models\Nope');

        $provider = new ModelProvider($this->hasher, 'App\Models\Nope');

        unset($provider); // Constructor must throw before this point.
    }

    /**
     * The constructor refuses a class that exists but does NOT extend
     * Eloquent's `Model` or implement the framework `Authenticatable` contract.
     * Pins the type-shape guard in `__construct()`.
     *
     * @return void
     */
    public function testConstructorRejectsClassThatIsNotEloquentModelAuthenticatable(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage(self::MODEL_AUTH_MESSAGE);

        $provider = new ModelProvider($this->hasher, \stdClass::class);

        unset($provider); // Constructor must throw before this point.
    }

    /**
     * The constructor refuses a class that extends `Model` but does NOT
     * implement `Authenticatable`. Pins the `!is_subclass_of($model,
     * Authenticatable::class)` arm in `__construct()` independently of the
     * Model check - a mutation that removes this arm would let the class
     * through.
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
     * does NOT extend `Model`. Pins the `!is_subclass_of($model, Model::class)`
     * arm independently - a mutation that removes this arm would let the class
     * through.
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
     * `createModel()` returns a fresh instance of the configured Eloquent class
     * on every call. Pins the parent `createModel()` body so a test that
     * overrides the method on a subclass cannot mask a regression to the
     * production path.
     *
     * @return void
     *
     * @throws \ReflectionException
     */
    public function testCreateModelReturnsFreshConfiguredClassInstance(): void
    {
        $provider = new ModelProvider($this->hasher, StubAuthenticatableModel::class);

        $reflection = new \ReflectionClass(ModelProvider::class);
        $method     = $reflection->getMethod('createModel');

        $first  = $method->invoke($provider);
        $second = $method->invoke($provider);

        self::assertInstanceOf(StubAuthenticatableModel::class, $first);
        self::assertInstanceOf(StubAuthenticatableModel::class, $second);
        self::assertNotSame($first, $second, 'Each createModel() call must return a fresh instance.');
    }

    /**
     * `retrieveByCredentials()` silently drops keys whose name is not a valid
     * SQL identifier so attacker-controlled column fragments cannot reach
     * `where()`. Pins the regex guard in `filterCredentialKeys()`.
     *
     * @return void
     */
    public function testRetrieveByCredentialsDropsKeysWithInvalidIdentifierShape(): void
    {
        $provider = new ModelProvider($this->hasher, StubAuthenticatableModel::class);

        // After dropping the malformed key the credentials array is empty - the
        // provider returns null without composing a query.
        self::assertNull($provider->retrieveByCredentials([
            'email; drop table users' => 'malicious',
        ]));
    }

    /**
     * Data provider for `testRetrieveByCredentialsDropsPasswordKeyVariant`.
     * Each row is one password-family column name the filter must reject so
     * that the hasher stays the single source of truth for password
     * verification.
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
     * `filterCredentialKeys()` drops every key whose lowercased name contains
     * the substring `'password'` - not just the literal `'password'` key. Pins
     * the substring filter against a data-provider of common password-column
     * variants.
     *
     * @param  string  $key
     * @return void
     */
    #[DataProvider('providePasswordKeyVariants')]
    public function testRetrieveByCredentialsDropsPasswordKeyVariant(string $key): void
    {
        $provider = new ModelProvider($this->hasher, StubAuthenticatableModel::class);

        // The password-family key is the only entry, so after filtering the
        // credentials array is empty and the provider returns null without
        // composing a query.
        self::assertNull($provider->retrieveByCredentials([$key => 'secret']));
    }

    /**
     * `filterCredentialKeys()` does NOT drop a key whose name merely contains
     * the substring `'pass'` (without the `'word'` suffix). Mutation guard
     * against a rule that over-filters: the hasher operates on the literal
     * `password` key only, and columns like `api_pass` or `pass_phrase` must
     * remain routable through the query builder.
     *
     * @return void
     */
    public function testRetrieveByCredentialsDoesNotDropPassSubstringOnlyKeys(): void
    {
        $builder = \Mockery::mock(Builder::class);
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
     * `rehashPasswordIfRequired()` rehashes and saves when the hasher reports
     * the stored hash is out of date, even when the caller did NOT pass `force
     * = true`. Pins the natural auto-rehash path that keeps legacy hashes
     * rolling forward as the `bcrypt` cost factor is bumped.
     *
     * @return void
     */
    public function testRehashPasswordIfRequiredRehashesWhenHasherReportsOutdated(): void
    {
        $provider = new ModelProvider($this->hasher, StubAuthenticatableModel::class);

        /** @var \Mockery\MockInterface&\Tests\Unit\Stubs\StubAuthenticatableModel $user */
        $user = \Mockery::mock(StubAuthenticatableModel::class)->makePartial();
        $user->shouldReceive('getAuthPassword')
            ->andReturn('stale-hash');
        $user->shouldReceive('getAuthPasswordName')
            ->andReturn('password');
        $user->shouldReceive('save')
            ->once()
            ->andReturnTrue();

        $this->hasher->shouldReceive('needsRehash')
            ->once()
            ->with('stale-hash')
            ->andReturnTrue();
        $this->hasher->shouldReceive('make')
            ->once()
            ->with('plain')
            ->andReturn('fresh-hash');

        $provider->rehashPasswordIfRequired($user, ['password' => 'plain']);

        self::assertSame('fresh-hash', $user->getAttribute('password'));
    }

    /**
     * `rehashPasswordIfRequired()` is a no-op when the supplied password value
     * is not a string (e.g. `null`, array). Pins the early-return on
     * `!is_string($plain)`.
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
     * A boolean credential value is applied as a scalar `where()` clause.
     * Mutation guard: pins the `is_bool($value)` match arm in
     * `applyCredentialClause()` independently of `is_string`.
     *
     * @return void
     */
    public function testRetrieveByCredentialsAppliesBoolCredentialAsWhereClause(): void
    {
        $builder = \Mockery::mock(Builder::class);
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
     * A `Stringable` credential value is applied as a scalar `where()` clause.
     * Mutation guard: pins the `$value instanceof \Stringable` match arm
     * independently of `is_string`.
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
     * `retrieveByCredentials()` returns `null` when one of the supplied
     * credential values is an unsupported type (e.g. an `\stdClass` object that
     * is neither scalar, array, closure, nor Stringable). The provider refuses
     * to compose the query rather than letting an unsafe value reach `where()`.
     * Pins the failure branch in `retrieveByCredentials()` and the `default =>
     * false` arm in `applyCredentialClause()`.
     *
     * @return void
     */
    public function testRetrieveByCredentialsReturnsNullForUnsupportedValueType(): void
    {
        // The mocked builder receives no `where`/`whereIn` calls -
        // applyCredentialClause's default arm returns false BEFORE touching the
        // query, so the caller bails out with null and the query is never
        // executed.
        $builder = \Mockery::mock(Builder::class);
        $builder->shouldNotReceive('where');
        $builder->shouldNotReceive('whereIn');
        $builder->shouldNotReceive('first');

        /** @var \Mockery\MockInterface&\Tests\Unit\Stubs\StubAuthenticatableModel $model */
        $model = \Mockery::mock(StubAuthenticatableModel::class)->makePartial();
        $model->shouldReceive('newQuery')
            ->andReturn($builder);
        $model->shouldReceive('getAuthIdentifierName')
            ->andReturn('id');

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
             * Createmodel.
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
     * Build a `ModelProvider` whose `createModel()` returns an Eloquent model
     * wired to the supplied Builder mock, so tests can observe the composed
     * `where` clauses without a real database connection.
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
             * Create model.
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
}
