<?php

declare(strict_types=1);

namespace Tests\Unit\Providers;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Mockery;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use Mockery\MockInterface;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Providers\ModelProvider;
use Tests\Unit\Stubs\StubAuthenticatableModel;

/**
 * Unit tests for the ModelProvider identity provider.
 *
 * @internal
 *
 * @author    Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright 2026 Sine Macula Limited.
 */
#[CoversNothing]
final class ModelProviderTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    /** @var \Mockery\MockInterface&\Illuminate\Contracts\Hashing\Hasher The mocked password hasher collaborator. */
    private MockInterface $hasher;

    protected function setUp(): void
    {
        parent::setUp();

        $this->hasher = Mockery::mock(Hasher::class);
    }

    /**
     * retrieveById returns the resolved model when the query finds one.
     *
     * @return void
     */
    public function testRetrieveByIdReturnsModelWhenFound(): void
    {
        $found = new StubAuthenticatableModel();

        $builder = Mockery::mock(Builder::class);
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
        $builder = Mockery::mock(Builder::class);
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

        $user = Mockery::mock(Authenticatable::class);
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
        $found = new StubAuthenticatableModel();

        $builder = Mockery::mock(Builder::class);
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
     * Array credentials are passed through to where() for IN expansion.
     *
     * @return void
     */
    public function testRetrieveByCredentialsAppliesArrayCredentialsAsWhereInClauses(): void
    {
        $roles = ['admin', 'staff'];

        $builder = Mockery::mock(Builder::class);
        $builder->shouldReceive('where')
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
        $builder = Mockery::mock(Builder::class);
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

        $user = Mockery::mock(Authenticatable::class);
        $this->hasher->shouldNotReceive('check');

        self::assertFalse($provider->validateCredentials($user, []));
    }

    /**
     * validateCredentials returns false when the password is not a string.
     *
     * @return void
     */
    public function testValidateCredentialsReturnsFalseWhenPasswordNotString(): void
    {
        $provider = new ModelProvider($this->hasher, StubAuthenticatableModel::class);

        $user = Mockery::mock(Authenticatable::class);
        $this->hasher->shouldNotReceive('check');

        self::assertFalse($provider->validateCredentials($user, ['password' => 123]));
    }

    /**
     * validateCredentials delegates to Hasher::check when a plain password is provided.
     *
     * @return void
     */
    public function testValidateCredentialsDelegatesToHasherCheck(): void
    {
        $provider = new ModelProvider($this->hasher, StubAuthenticatableModel::class);

        $user = Mockery::mock(Authenticatable::class);
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

        $user = Mockery::mock(Authenticatable::class);
        $this->hasher->shouldNotReceive('needsRehash');
        $this->hasher->shouldNotReceive('make');

        $provider->rehashPasswordIfRequired($user, []);

        self::assertTrue(true, 'rehashPasswordIfRequired returned without touching the hasher.');
    }

    /**
     * rehashPasswordIfRequired is a no-op when the user is not an Eloquent model.
     *
     * @return void
     */
    public function testRehashPasswordIfRequiredNoOpsWhenUserNotEloquentModel(): void
    {
        $provider = new ModelProvider($this->hasher, StubAuthenticatableModel::class);

        $user = Mockery::mock(Authenticatable::class);
        $this->hasher->shouldNotReceive('needsRehash');
        $this->hasher->shouldNotReceive('make');

        $provider->rehashPasswordIfRequired($user, ['password' => 'plain']);

        self::assertTrue(true, 'rehashPasswordIfRequired short-circuited for a non-Model user.');
    }

    /**
     * rehashPasswordIfRequired skips rehash when Hasher::needsRehash returns false.
     *
     * @return void
     */
    public function testRehashPasswordIfRequiredSkipsWhenHasherNeedsRehashFalse(): void
    {
        $provider = new ModelProvider($this->hasher, StubAuthenticatableModel::class);

        /** @var \Mockery\MockInterface&\Tests\Unit\Stubs\StubAuthenticatableModel $user */
        $user = Mockery::mock(StubAuthenticatableModel::class)->makePartial();
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
        $user = Mockery::mock(StubAuthenticatableModel::class)->makePartial();
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
     * whose newQuery() yields the supplied builder mock, so collaborators
     * can be asserted without a real database connection.
     *
     * @param  \Mockery\MockInterface $builder The builder mock to return from newQuery().
     * @return \SineMacula\Laravel\Authentication\Providers\ModelProvider
     */
    private function makeProvider(MockInterface $builder): ModelProvider
    {
        /** @var \Mockery\MockInterface&\Tests\Unit\Stubs\StubAuthenticatableModel $model */
        $model = Mockery::mock(StubAuthenticatableModel::class)->makePartial();
        $model->shouldReceive('newQuery')
            ->andReturn($builder);
        $model->shouldReceive('getAuthIdentifierName')
            ->andReturn('id');

        return new class ($this->hasher, StubAuthenticatableModel::class, $model) extends ModelProvider {
            public function __construct(

                // Hasher forwarded to the parent constructor.
                Hasher $hasher,

                // Fully-qualified Eloquent model class forwarded to the parent.
                string $modelClass,

                /** Pre-built model instance returned from createModel(). */
                private readonly Model&Authenticatable $instance,

            ) {
                parent::__construct($hasher, $modelClass);
            }

            protected function createModel(): Model&Authenticatable
            {
                return $this->instance;
            }
        };
    }
}
