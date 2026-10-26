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
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Providers\ModelProvider;
use Tests\Unit\Stubs\PlainIdentityFixture;
use Tests\Unit\Stubs\StubAuthenticatableModel;
use Tests\Unit\Stubs\StubModel;

/**
 * Unit tests for the ModelProvider constructor validation, identity retrieval,
 * and basic credential query building.
 *
 * Covers constructor type checks, retrieveById, retrieveByToken,
 * updateRememberToken, simple credential-to-query mapping, and modelClass().
 * Credential filtering edge cases, validateCredentials, and
 * rehashPasswordIfRequired tests live in ModelProviderCredentialTest.
 *
 * @internal
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
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
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->hasher = \Mockery::mock(Hasher::class);
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
     * Constructor rejects a class that extends `Model` but does not implement
     * `Authenticatable`.
     *
     * @return void
     *
     * @SuppressWarnings("php:S1848")
     */
    public function testConstructorRejectsModelWithoutAuthenticatable(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('must be both an Eloquent Model and implement Authenticatable');

        new ModelProvider($this->hasher, StubModel::class);
    }

    /**
     * Constructor rejects a class that implements `Authenticatable` but does
     * not extend `Model`.
     *
     * @return void
     *
     * @SuppressWarnings("php:S1848")
     */
    public function testConstructorRejectsAuthenticatableWithoutModel(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('must be both an Eloquent Model and implement Authenticatable');

        new ModelProvider($this->hasher, PlainIdentityFixture::class);
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
     * `modelClass()` returns the configured Eloquent model class name.
     *
     * @return void
     */
    public function testModelClassReturnsConfiguredClassName(): void
    {
        $provider = new ModelProvider($this->hasher, StubAuthenticatableModel::class);

        self::assertSame(StubAuthenticatableModel::class, $provider->modelClass());
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
            #[\Override]
            protected function createModel(): Authenticatable&Model
            {
                return $this->instance;
            }
        };
    }
}
