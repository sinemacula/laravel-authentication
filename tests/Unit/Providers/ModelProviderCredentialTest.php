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
use Tests\Unit\Stubs\StubAuthenticatableModel;

/**
 * Unit tests for the ModelProvider credential filtering, password validation,
 * and password rehashing paths.
 *
 * Covers credential-key sanitisation edge cases, validateCredentials type
 * guarding, hasher delegation, and the rehashPasswordIfRequired lifecycle.
 * Constructor validation and basic retrieval tests live in ModelProviderTest.
 *
 * @internal
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
#[CoversClass(ModelProvider::class)]
final class ModelProviderCredentialTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    /** @var string Shared email used across credential-lookup assertions. */
    private const string ALICE_EMAIL = 'alice@example.test';

    /** @var \Illuminate\Contracts\Hashing\Hasher&\Mockery\MockInterface Mocked password hasher collaborator. */
    private MockInterface $hasher;

    /**
     * Setup.
     *
     * @return void
     */
    protected function setUp(): void
    {
        parent::setUp();

        $this->hasher = \Mockery::mock(Hasher::class);
    }

    /**
     * Password-like keys are filtered case-insensitively and do not block
     * later valid credentials from reaching the query.
     *
     * @return void
     */
    public function testRetrieveByCredentialsSkipsCaseInsensitivePasswordKeysAndContinues(): void
    {
        $found = new StubAuthenticatableModel;

        $builder = \Mockery::mock(Builder::class);
        $builder->shouldReceive('where')
            ->once()
            ->with('email', self::ALICE_EMAIL)
            ->andReturnSelf();
        $builder->shouldReceive('first')
            ->once()
            ->andReturn($found);

        $provider = $this->makeProvider($builder);

        self::assertSame($found, $provider->retrieveByCredentials([
            'PASSWORD' => 'secret',
            'email'    => self::ALICE_EMAIL,
        ]));
    }

    /**
     * Invalid credential keys with a leading non-identifier byte are dropped
     * without blocking later valid credentials.
     *
     * @return void
     */
    public function testRetrieveByCredentialsSkipsLeadingJunkKeyAndContinues(): void
    {
        $found = new StubAuthenticatableModel;

        $builder = \Mockery::mock(Builder::class);
        $builder->shouldReceive('where')
            ->once()
            ->with('email', self::ALICE_EMAIL)
            ->andReturnSelf();
        $builder->shouldReceive('first')
            ->once()
            ->andReturn($found);

        $provider = $this->makeProvider($builder);

        self::assertSame($found, $provider->retrieveByCredentials([
            '1email' => 'malicious',
            'email'  => self::ALICE_EMAIL,
        ]));
    }

    /**
     * Invalid credential keys with a trailing dot are dropped without blocking
     * later valid credentials.
     *
     * @return void
     */
    public function testRetrieveByCredentialsSkipsTrailingDotKeyAndContinues(): void
    {
        $found = new StubAuthenticatableModel;

        $builder = \Mockery::mock(Builder::class);
        $builder->shouldReceive('where')
            ->once()
            ->with('email', self::ALICE_EMAIL)
            ->andReturnSelf();
        $builder->shouldReceive('first')
            ->once()
            ->andReturn($found);

        $provider = $this->makeProvider($builder);

        self::assertSame($found, $provider->retrieveByCredentials([
            'email.' => 'malicious',
            'email'  => self::ALICE_EMAIL,
        ]));
    }

    /**
     * Array credentials are passed through to whereIn() for IN expansion.
     *
     * @return void
     */
    public function testRetrieveByCredentialsAppliesArrayCredentialsAsWhereInClauses(): void
    {
        $roles = ['admin', 'staff'];

        $builder = \Mockery::mock(Builder::class);
        $builder->shouldReceive('whereIn')
            ->once()
            ->with('role', $roles)
            ->andReturnSelf();
        $builder->shouldReceive('first')
            ->once()
            ->andReturnNull();

        $provider = $this->makeProvider($builder);

        self::assertNull($provider->retrieveByCredentials(['role' => $roles]));
    }

    /**
     * Closure credentials are invoked with the query builder.
     *
     * @return void
     */
    public function testRetrieveByCredentialsInvokesClosureCredentialsAgainstQuery(): void
    {
        $builder = \Mockery::mock(Builder::class);
        $builder->shouldReceive('where')
            ->once()
            ->with('flag', true)
            ->andReturnSelf();
        $builder->shouldReceive('first')
            ->once()
            ->andReturnNull();

        $provider = $this->makeProvider($builder);

        $closureInvoked = false;

        $provider->retrieveByCredentials([
            'custom' => static function (Builder $query) use (&$closureInvoked): void {
                $closureInvoked = true;
                $query->where('flag', true);
            },
        ]);

        self::assertTrue($closureInvoked);
    }

    /**
     * Multiple scalar credential entries compose as AND-combined `where()`
     * clauses - the query builder receives one `where()` call per entry in
     * declaration order. Pins the iteration path through
     * `applyCredentialClauses`.
     *
     * @return void
     */
    public function testRetrieveByCredentialsAndCombinesMultipleScalarClauses(): void
    {
        $found = new StubAuthenticatableModel;

        $builder = \Mockery::mock(Builder::class);
        $builder->shouldReceive('where')
            ->once()
            ->with('email', self::ALICE_EMAIL)
            ->andReturnSelf();
        $builder->shouldReceive('where')
            ->once()
            ->with('tenant_id', 42)
            ->andReturnSelf();
        $builder->shouldReceive('first')
            ->once()
            ->andReturn($found);

        $provider = $this->makeProvider($builder);

        self::assertSame($found, $provider->retrieveByCredentials([
            'email'     => self::ALICE_EMAIL,
            'tenant_id' => 42,
        ]));
    }

    /**
     * validateCredentials returns false when the password is missing.
     *
     * @return void
     */
    public function testValidateCredentialsReturnsFalseWhenPasswordMissing(): void
    {
        $provider = new ModelProvider($this->hasher, StubAuthenticatableModel::class);

        $user = \Mockery::mock(Authenticatable::class);
        $this->hasher->shouldNotReceive('check');

        self::assertFalse($provider->validateCredentials($user, []));
    }

    /**
     * Data provider for
     * `testValidateCredentialsReturnsFalseWhenPasswordNotString`.
     *
     * @return \Generator<string, array{0: mixed}>
     */
    public static function provideNonStringPasswords(): iterable
    {
        yield from [
            'integer'      => [123],
            'float'        => [1.5],
            'true'         => [true],
            'false'        => [false],
            'array'        => [['secret']],
            'object'       => [new \stdClass],
            'null'         => [null],
            'empty-string' => [''],
        ];
    }

    /**
     * validateCredentials returns false when the password is not a string
     * (integer, array, object, boolean, or null). Uses a data provider so each
     * non-string variant is its own assertion row and a mutation that loosens
     * the type check fails a single row cleanly.
     *
     * @param  mixed  $password
     * @return void
     */
    #[DataProvider('provideNonStringPasswords')]
    public function testValidateCredentialsReturnsFalseWhenPasswordNotString(mixed $password): void
    {
        $provider = new ModelProvider($this->hasher, StubAuthenticatableModel::class);

        $user = \Mockery::mock(Authenticatable::class);
        $this->hasher->shouldNotReceive('check');

        self::assertFalse($provider->validateCredentials($user, ['password' => $password]));
    }

    /**
     * validateCredentials delegates to Hasher::check when a plain password is
     * provided.
     *
     * @return void
     */
    public function testValidateCredentialsDelegatesToHasherCheck(): void
    {
        $provider = new ModelProvider($this->hasher, StubAuthenticatableModel::class);

        $user = \Mockery::mock(Authenticatable::class);
        $user->shouldReceive('getAuthPassword')
            ->once()
            ->andReturn('hashed');

        $this->hasher->shouldReceive('check')
            ->once()
            ->with('plain', 'hashed')
            ->andReturnTrue();

        self::assertTrue($provider->validateCredentials($user, ['password' => 'plain']));
    }

    /**
     * rehashPasswordIfRequired is a no-op when no password is supplied.
     *
     * @return void
     */
    public function testRehashPasswordIfRequiredNoOpsWhenPasswordMissing(): void
    {
        $provider = new ModelProvider($this->hasher, StubAuthenticatableModel::class);

        $user = \Mockery::mock(Authenticatable::class);
        $this->hasher->shouldNotReceive('needsRehash');
        $this->hasher->shouldNotReceive('make');

        $provider->rehashPasswordIfRequired($user, []);

        self::assertTrue(true, 'rehashPasswordIfRequired returned without touching the hasher.');
    }

    /**
     * rehashPasswordIfRequired is a no-op when the password is an empty string,
     * even for an Eloquent model user.
     *
     * @return void
     */
    public function testRehashPasswordIfRequiredNoOpsWhenPasswordEmptyString(): void
    {
        $provider = new ModelProvider($this->hasher, StubAuthenticatableModel::class);

        /** @var \Mockery\MockInterface&\Tests\Unit\Stubs\StubAuthenticatableModel $user */
        $user = \Mockery::mock(StubAuthenticatableModel::class)->makePartial();
        $user->shouldNotReceive('save');

        $this->hasher->shouldNotReceive('needsRehash');
        $this->hasher->shouldNotReceive('make');

        $provider->rehashPasswordIfRequired($user, ['password' => '']);

        self::assertTrue(true, 'rehashPasswordIfRequired short-circuited for an empty string password.');
    }

    /**
     * rehashPasswordIfRequired is a no-op when the user is not an Eloquent
     * model.
     *
     * @return void
     */
    public function testRehashPasswordIfRequiredNoOpsWhenUserNotEloquentModel(): void
    {
        $provider = new ModelProvider($this->hasher, StubAuthenticatableModel::class);

        $user = \Mockery::mock(Authenticatable::class);
        $this->hasher->shouldNotReceive('needsRehash');
        $this->hasher->shouldNotReceive('make');

        $provider->rehashPasswordIfRequired($user, ['password' => 'plain']);

        self::assertTrue(true, 'rehashPasswordIfRequired short-circuited for a non-Model user.');
    }

    /**
     * rehashPasswordIfRequired skips rehash when Hasher::needsRehash returns
     * false.
     *
     * @return void
     */
    public function testRehashPasswordIfRequiredSkipsWhenHasherNeedsRehashFalse(): void
    {
        $provider = new ModelProvider($this->hasher, StubAuthenticatableModel::class);

        /** @var \Mockery\MockInterface&\Tests\Unit\Stubs\StubAuthenticatableModel $user */
        $user = \Mockery::mock(StubAuthenticatableModel::class)->makePartial();
        $user->shouldReceive('getAuthPassword')
            ->andReturn('hashed');
        $user->shouldNotReceive('save');

        $this->hasher->shouldReceive('needsRehash')
            ->once()
            ->with('hashed')
            ->andReturnFalse();
        $this->hasher->shouldNotReceive('make');

        $provider->rehashPasswordIfRequired($user, ['password' => 'plain']);

        self::assertTrue(true, 'rehashPasswordIfRequired skipped without calling hasher->make().');
    }

    /**
     * rehashPasswordIfRequired rehashes and saves when forced.
     *
     * @return void
     */
    public function testRehashPasswordIfRequiredRehashesWhenForced(): void
    {
        $provider = new ModelProvider($this->hasher, StubAuthenticatableModel::class);

        /** @var \Mockery\MockInterface&\Tests\Unit\Stubs\StubAuthenticatableModel $user */
        $user = \Mockery::mock(StubAuthenticatableModel::class)->makePartial();
        $user->shouldReceive('getAuthPasswordName')
            ->andReturn('password');
        $user->shouldReceive('save')
            ->once()
            ->andReturnTrue();

        $this->hasher->shouldNotReceive('needsRehash');
        $this->hasher->shouldReceive('make')
            ->once()
            ->with('plain')
            ->andReturn('rehashed');

        $provider->rehashPasswordIfRequired($user, ['password' => 'plain'], true);

        self::assertSame('rehashed', $user->getAttribute('password'));
    }

    /**
     * Build a ModelProvider whose createModel() returns an Eloquent model whose
     * newQuery() yields the supplied builder mock, so collaborators can be
     * asserted without a real database connection.
     *
     * @param  \Mockery\MockInterface  $builder
     * @return \SineMacula\Laravel\Authentication\Providers\ModelProvider
     */
    private function makeProvider(MockInterface $builder): ModelProvider
    {
        /** @var \Mockery\MockInterface&\Tests\Unit\Stubs\StubAuthenticatableModel $model */
        $model = \Mockery::mock(StubAuthenticatableModel::class)->makePartial();
        $model->shouldReceive('newQuery')
            ->andReturn($builder);
        $model->shouldReceive('getAuthIdentifierName')
            ->andReturn('id');

        return new class ($this->hasher, StubAuthenticatableModel::class, $model) extends ModelProvider {
            /**
             * Constructor.
             *
             * @param  \Illuminate\Contracts\Hashing\Hasher  $hasher
             * @param  string  $modelClass
             * @param  \Illuminate\Contracts\Auth\Authenticatable&\Illuminate\Database\Eloquent\Model  $instance
             */
            public function __construct(

                // Hasher forwarded to the parent constructor.
                Hasher $hasher,

                // Fully-qualified Eloquent model class forwarded to the parent.
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
            protected function createModel(): Authenticatable&Model
            {
                return $this->instance;
            }
        };
    }
}
