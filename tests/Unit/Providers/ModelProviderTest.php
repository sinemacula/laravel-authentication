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
 * Unit tests for the ModelProvider identity provider.
 *
 * @internal
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 */
#[CoversClass(ModelProvider::class)]
final class ModelProviderTest extends TestCase
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
     * Data provider for
     * `testValidateCredentialsReturnsFalseWhenPasswordNotString`.
     *
     * @return array<string, array{0: mixed}>
     */
    public static function provideNonStringPasswords(): array
    {
        return [
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
     * retrieveById returns the resolved model when the query finds one.
     *
     * @return void
     */
    public function testRetrieveByIdReturnsModelWhenFound(): void
    {
        $found = new StubAuthenticatableModel;

        $builder = \Mockery::mock(Builder::class);
        $builder->shouldReceive('where')
            ->once()
            ->with('id', 7)
            ->andReturnSelf();
        $builder->shouldReceive('first')
            ->once()
            ->andReturn($found);

        $provider = $this->makeProvider($builder);

        self::assertSame($found, $provider->retrieveById(7));
    }

    /**
     * retrieveById returns null when the query finds no match.
     *
     * @return void
     */
    public function testRetrieveByIdReturnsNullWhenNotFound(): void
    {
        $builder = \Mockery::mock(Builder::class);
        $builder->shouldReceive('where')
            ->once()
            ->with('id', 99)
            ->andReturnSelf();
        $builder->shouldReceive('first')
            ->once()
            ->andReturnNull();

        $provider = $this->makeProvider($builder);

        self::assertNull($provider->retrieveById(99));
    }

    /**
     * retrieveByToken is inert and always returns null.
     *
     * @return void
     */
    public function testRetrieveByTokenReturnsNull(): void
    {
        $provider = new ModelProvider($this->hasher, StubAuthenticatableModel::class);

        self::assertNull($provider->retrieveByToken(1, 'token'));
    }

    /**
     * updateRememberToken is inert and performs no mutations.
     *
     * @return void
     */
    public function testUpdateRememberTokenIsNoOp(): void
    {
        $provider = new ModelProvider($this->hasher, StubAuthenticatableModel::class);

        $user = \Mockery::mock(Authenticatable::class);
        $user->shouldNotReceive('setRememberToken');

        $provider->updateRememberToken($user, 'token');

        self::assertTrue(true, 'updateRememberToken returned without touching the user.');
    }

    /**
     * retrieveByCredentials returns null when only a password is supplied.
     *
     * @return void
     */
    public function testRetrieveByCredentialsReturnsNullWhenOnlyPasswordSupplied(): void
    {
        $provider = new ModelProvider($this->hasher, StubAuthenticatableModel::class);

        self::assertNull($provider->retrieveByCredentials(['password' => 'secret']));
    }

    /**
     * Scalar credentials are applied as where() clauses on the query.
     *
     * @return void
     */
    public function testRetrieveByCredentialsAppliesScalarCredentialsAsWhereClauses(): void
    {
        $found = new StubAuthenticatableModel;

        $builder = \Mockery::mock(Builder::class);
        $builder->shouldReceive('where')
            ->once()
            ->with('email', 'a@b.com')
            ->andReturnSelf();
        $builder->shouldReceive('first')
            ->once()
            ->andReturn($found);

        $provider = $this->makeProvider($builder);

        self::assertSame($found, $provider->retrieveByCredentials(['email' => 'a@b.com']));
    }

    /**
     * Numeric credential keys are silently dropped - they cannot be passed
     * safely to `where()` and would otherwise crash the query.
     *
     * @return void
     */
    public function testRetrieveByCredentialsDropsNumericKeys(): void
    {
        $provider = new ModelProvider($this->hasher, StubAuthenticatableModel::class);

        // After dropping numeric keys the credentials array is empty - the
        // provider returns null without composing a query.
        self::assertNull($provider->retrieveByCredentials([self::ALICE_EMAIL]));
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
     * Build a ModelProvider whose createModel() returns an Eloquent model
     * whose newQuery() yields the supplied builder mock, so collaborators can
     * be asserted without a real database connection.
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
