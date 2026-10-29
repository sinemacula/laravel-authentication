<?php

declare(strict_types = 1);

namespace Tests\Integration\Providers;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Casts\NormalisedIdentifier;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Providers\ModelProvider;
use Tests\Integration\Fixtures\NormalisedEmailIdentity;
use Tests\TestCase;

/**
 * Integration tests for looking identities up by a designated identifier: the
 * `model` provider normalises the credential the way the cast stored it, so the
 * lookup matches on every database engine, PostgreSQL's case-sensitive
 * comparison included.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ModelProvider::class)]
#[CoversClass(NormalisedIdentifier::class)]
final class NormalisedLookupModelProviderTest extends TestCase
{
    /** @var string Plaintext password of the seeded identity. */
    private const string PASSWORD = 'correct horse battery staple';

    /** @var list<array{sql: string, bindings: array<int, mixed>}> Queries run since the last reset. */
    private array $queries = [];

    /**
     * Create the identity table, seed one identity through the cast, and record
     * the queries the tests run.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        Schema::create('normalised_email_identities', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('email')->nullable()->unique();
            $blueprint->string('name');
            $blueprint->string('password');
            $blueprint->timestamps();
        });

        NormalisedEmailIdentity::query()->create([
            'email'    => 'Ben.Carey@Example.COM',
            'name'     => 'Ben',
            'password' => app(Hasher::class)->make(self::PASSWORD),
        ]);

        DB::listen(function (QueryExecuted $query): void {
            $this->queries[] = ['sql' => $query->sql, 'bindings' => $query->bindings];
        });
    }

    /**
     * Drop the identity table.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Schema::dropIfExists('normalised_email_identities');

        parent::tearDown();
    }

    /**
     * The identifier was stored in its normal form, and a lookup with any
     * casing and surrounding whitespace finds it, also as a `Stringable`.
     *
     * @return void
     */
    public function testLookupMatchesTheStoredNormalFormWhateverTheCasing(): void
    {
        self::assertSame('ben.carey@example.com', DB::table('normalised_email_identities')->value('email'));

        self::assertInstanceOf(NormalisedEmailIdentity::class, $this->provider()->retrieveByCredentials(['email' => "  BEN.carey@example.com\t"]));
        self::assertInstanceOf(NormalisedEmailIdentity::class, $this->provider()->retrieveByCredentials(['email' => Str::of('Ben.Carey@EXAMPLE.com')]));
        self::assertSame(['ben.carey@example.com'], $this->queries[1]['bindings']);
    }

    /**
     * An array of identifiers is normalised element by element.
     *
     * @return void
     */
    public function testArrayCredentialIsNormalisedElementByElement(): void
    {
        $found = $this->provider()->retrieveByCredentials(['email' => ['NOBODY@example.com', ' Ben.Carey@Example.com ']]);

        self::assertInstanceOf(NormalisedEmailIdentity::class, $found);
        self::assertSame(['nobody@example.com', 'ben.carey@example.com'], $this->queries[0]['bindings']);
    }

    /**
     * A credential key qualified with the model's own table counts as the
     * attribute; one qualified with another table, even one whose name starts
     * with the model's, does not.
     *
     * @return void
     */
    public function testKeyQualifiedWithTheModelsTableIsNormalised(): void
    {
        self::assertInstanceOf(NormalisedEmailIdentity::class, $this->provider()->retrieveByCredentials(['normalised_email_identities.email' => 'BEN.CAREY@EXAMPLE.COM']));
        self::assertSame(['ben.carey@example.com'], $this->queries[0]['bindings']);

        $pretended = DB::connection()->pretend(fn (): mixed => $this->provider()->retrieveByCredentials(['normalised_email_identities_archive.email' => 'Kept@Example.com']));

        self::assertSame(['Kept@Example.com'], $pretended[0]['bindings']);
    }

    /**
     * Every designated credential is normalised, wherever it comes among the
     * others.
     *
     * @return void
     */
    public function testDesignatedCredentialAfterOthersIsNormalised(): void
    {
        self::assertInstanceOf(NormalisedEmailIdentity::class, $this->provider()->retrieveByCredentials(['name' => 'Ben', 'email' => 'BEN.CAREY@EXAMPLE.COM']));
        self::assertSame(['Ben', 'ben.carey@example.com'], $this->queries[0]['bindings']);
    }

    /**
     * A rejected identifier ends the lookup before any clause is applied, so a
     * closure credential that comes first is never run.
     *
     * @return void
     */
    public function testRejectedIdentifierRunsNoCredentialClosure(): void
    {
        $ran = false;

        $found = $this->provider()->retrieveByCredentials([
            'scope' => static function () use (&$ran): void {
                $ran = true;
            },
            'email' => '   ',
        ]);

        self::assertNull($found);
        self::assertFalse($ran);
    }

    /**
     * Credentials for attributes that are not designated identifiers, and
     * values that are not strings, are applied as given.
     *
     * @return void
     */
    public function testOtherCredentialsAreAppliedAsGiven(): void
    {
        $this->provider()->retrieveByCredentials(['name' => ' Ben ', 'email' => 7]);

        self::assertSame([' Ben ', 7], $this->queries[0]['bindings']);
    }

    /**
     * A closure credential receives the query as before; the identifier it
     * filters on is the closure's own business.
     *
     * @return void
     */
    public function testClosureCredentialsAreLeftAlone(): void
    {
        $found = $this->provider()->retrieveByCredentials([
            'email' => static function ($query): void {
                $query->where('email', 'ben.carey@example.com'); // @phpstan-ignore method.nonObject
            },
        ]);

        self::assertInstanceOf(NormalisedEmailIdentity::class, $found);
    }

    /**
     * Identifier credentials the normaliser rejects.
     *
     * @return iterable<string, array{0: mixed}>
     */
    public static function provideRejectedIdentifiers(): iterable
    {
        yield from [
            'blank'                     => ['   '],
            'invalid UTF-8'             => ["ben\xC3\x28@example.com"],
            'an array with a blank one' => [['ben.carey@example.com', '']],
        ];
    }

    /**
     * A value that cannot be an identifier cannot name an account: the lookup
     * returns `null` without running a query.
     *
     * @param  mixed  $email
     * @return void
     */
    #[DataProvider('provideRejectedIdentifiers')]
    public function testRejectedIdentifierFindsNothingWithoutAQuery(mixed $email): void
    {
        self::assertNull($this->provider()->retrieveByCredentials(['email' => $email]));
        self::assertSame([], $this->queries);
    }

    /**
     * A credential sign-in through the guard finds the identity whatever the
     * casing the person typed.
     *
     * @return void
     */
    public function testAttemptSignsInWithAnyCasingOfTheIdentifier(): void
    {
        app()->instance('request', Request::create('/sign-in', 'POST'));

        self::assertTrue(Auth::guard('api')->attempt(['email' => ' BEN.CAREY@example.com ', 'password' => self::PASSWORD]));

        $identity = Auth::guard('api')->user();

        self::assertInstanceOf(NormalisedEmailIdentity::class, $identity);
        self::assertSame('ben.carey@example.com', $identity->email);
    }

    /**
     * Configure a guard and provider over the identity.
     *
     * @param  mixed  $app
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        assert($app instanceof Application);

        /** @var \Illuminate\Config\Repository $config */
        $config = $app->make(ConfigRepository::class);

        $config->set('auth.guards.api', ['driver' => 'jwt', 'provider' => 'normalised']);
        $config->set('auth.providers.normalised', ['driver' => 'model', 'model' => NormalisedEmailIdentity::class]);
        $config->set('authentication.timebox.credentials_microseconds', 1);
    }

    /**
     * The guard's identity provider.
     *
     * @return \SineMacula\Laravel\Authentication\Providers\ModelProvider
     */
    private function provider(): ModelProvider
    {
        return new ModelProvider(app(Hasher::class), NormalisedEmailIdentity::class);
    }
}
