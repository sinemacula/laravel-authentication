<?php

declare(strict_types = 1);

namespace Tests\Integration\Resolvers;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Eloquent\Relations\Relation;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Resolvers\IdentityReferences;
use Tests\Concerns\InteractsWithLaggingReplica;
use Tests\Integration\Fixtures\IntegrationIdentity;
use Tests\Integration\Fixtures\NamedIdentity;
use Tests\Integration\Fixtures\SoftDeletingMember;
use Tests\TestCase;
use Tests\Unit\Stubs\PlainIdentityFixture;
use Tests\Unit\Stubs\StubModel;

/**
 * Integration tests for resolving an identity from its stored morph type and
 * key.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(IdentityReferences::class)]
final class IdentityReferencesTest extends TestCase
{
    use InteractsWithLaggingReplica;

    /**
     * Create the identity tables on the primary and the replica; rows are
     * written to the primary only.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->createOnPrimaryAndReplica('integration_identities', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('email')->unique();
            $blueprint->string('password')->nullable();
            $blueprint->boolean('is_active')->default(true);
            $blueprint->timestamps();
        });

        $this->createOnPrimaryAndReplica('named_identities', static function (Blueprint $blueprint): void {
            $blueprint->string('id')->collation('NOCASE')->primary();
            $blueprint->timestamps();
        });

        $this->createOnPrimaryAndReplica('soft_deleting_members', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('email')->unique();
            $blueprint->string('password');
            $blueprint->dateTime('tokens_valid_after', 0)->nullable();
            $blueprint->timestamps();
            $blueprint->softDeletes();
        });
    }

    /**
     * Remove the temporary database files.
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
     * An identity named by its class and key is read from the primary, though
     * the replica has not seen it.
     *
     * @return void
     */
    public function testResolvesAnIdentityTheReplicaHasNotSeen(): void
    {
        $identity = IntegrationIdentity::query()->create(['email' => 'ada@example.test']);

        self::assertSame(0, DB::connection(self::REPLICA_CONNECTION)->table('integration_identities')->count());

        $resolved = IdentityReferences::resolve(IntegrationIdentity::class, (string) $identity->id);

        self::assertInstanceOf(IntegrationIdentity::class, $resolved);
        self::assertSame($identity->getKey(), $resolved->getKey());
    }

    /**
     * A mapped identity is named by its alias, and its class name names
     * nothing.
     *
     * @return void
     */
    public function testAMappedIdentityIsNamedByItsAliasOnly(): void
    {
        $id = (string) IntegrationIdentity::query()->create(['email' => 'ada@example.test'])->id;

        Relation::morphMap(['member' => IntegrationIdentity::class]);

        try {
            self::assertInstanceOf(IntegrationIdentity::class, IdentityReferences::resolve('member', $id));
            self::assertNull(IdentityReferences::resolve(IntegrationIdentity::class, $id));
        } finally {
            Relation::morphMap([], false);
        }
    }

    /**
     * Types that name no Eloquent identity model.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideTypesNamingNoIdentityModel(): iterable
    {
        yield from [
            'an unknown class'             => ['Tests\Missing\Identity'],
            'an empty type'                => [''],
            'a model that is no identity'  => [StubModel::class],
            'an identity that is no model' => [PlainIdentityFixture::class],
        ];
    }

    /**
     * A type that names no Eloquent identity model resolves nothing, without a
     * query.
     *
     * @param  string  $type
     * @return void
     */
    #[DataProvider('provideTypesNamingNoIdentityModel')]
    public function testATypeNamingNoIdentityModelResolvesNothing(string $type): void
    {
        $queries = self::countQueries();

        self::assertNull(IdentityReferences::resolve($type, '1'));
        self::assertSame(0, $queries->count);
    }

    /**
     * Ids that cannot be an integer key.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideIdsThatCannotBeAKey(): iterable
    {
        yield from [
            'text'        => ['abc'],
            'a padded id' => ['01'],
            'a spaced id' => [' 1'],
            'an empty id' => [''],
            'a fraction'  => ['1.0'],
        ];
    }

    /**
     * An id that cannot be a key of the model resolves nothing, without a
     * query.
     *
     * @param  string  $id
     * @return void
     */
    #[DataProvider('provideIdsThatCannotBeAKey')]
    public function testAnIdThatCannotBeAKeyIsNotQueried(string $id): void
    {
        IntegrationIdentity::query()->create(['email' => 'ada@example.test']);

        $queries = self::countQueries();

        self::assertNull(IdentityReferences::resolve(IntegrationIdentity::class, $id));
        self::assertSame(0, $queries->count);
    }

    /**
     * A key no row holds resolves nothing.
     *
     * @return void
     */
    public function testAKeyNoRowHoldsResolvesNothing(): void
    {
        self::assertNull(IdentityReferences::resolve(IntegrationIdentity::class, '999'));
    }

    /**
     * An identity the model's global scopes hide is not resolved.
     *
     * @return void
     */
    public function testAnIdentityHiddenByAGlobalScopeIsNotResolved(): void
    {
        $member = SoftDeletingMember::query()->create(['email' => 'ada@example.test', 'password' => 'hash']);
        $id     = (string) $member->id;

        self::assertInstanceOf(SoftDeletingMember::class, IdentityReferences::resolve(SoftDeletingMember::class, $id));

        $member->delete();

        self::assertNull(IdentityReferences::resolve(SoftDeletingMember::class, $id));
    }

    /**
     * A key the column's collation matches to another spelling is not resolved.
     *
     * @return void
     */
    public function testAKeyMatchedOnlyByTheCollationIsNotResolved(): void
    {
        NamedIdentity::query()->create(['id' => 'alice']);

        self::assertSame(1, DB::connection(self::PRIMARY_CONNECTION)->table('named_identities')->where('id', 'Alice')->count());
        self::assertNull(IdentityReferences::resolve(NamedIdentity::class, 'Alice'));
        self::assertSame('alice', IdentityReferences::resolve(NamedIdentity::class, 'alice')?->getKey());
    }

    /**
     * Register the lagging read/write split as the default connection.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        $this->configureLaggingReplica(app(ConfigRepository::class));
    }

    /**
     * Count the queries run from now on.
     *
     * @return object{count: int}
     */
    private static function countQueries(): object
    {
        $queries = new class {
            /** @var int The queries run so far. */
            public int $count = 0;
        };

        DB::listen(static function (QueryExecuted $query) use ($queries): void {
            $queries->count++;
        });

        return $queries;
    }
}
