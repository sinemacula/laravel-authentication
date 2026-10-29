<?php

declare(strict_types = 1);

namespace Tests\Integration\Providers;

use Carbon\Carbon;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Hashing\BcryptHasher;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Providers\ModelProvider;
use Tests\Integration\Fixtures\SeparatePasswordIdentity;
use Tests\TestCase;
use Tests\Unit\Stubs\StubPrincipal;

/**
 * Integration tests for the `model` provider's password rehash: one conditional
 * update that writes the new hash only while the stored hash is still the one
 * the password was checked against.
 *
 * Hashes are made at bcrypt cost 4 and the provider's hasher wants cost 5, so
 * every stored hash is outdated.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ModelProvider::class)]
final class ConditionalRehashModelProviderTest extends TestCase
{
    /** @var string Plaintext password of the seeded identity. */
    private const string PASSWORD = 'correct horse battery staple';

    /** @var list<string> SQL run since the last reset. */
    private array $statements = [];

    /**
     * Create the identity tables and record the statements the tests run.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        Schema::create('stub_principals', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('email')->unique();
            $blueprint->string('password')->nullable();
            $blueprint->boolean('is_active')->default(true);
            $blueprint->timestamps();
        });

        Schema::create('separate_password_identities', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('email')->unique();
            $blueprint->timestamps();
        });

        Schema::create('identity_passwords', static function (Blueprint $blueprint): void {
            $blueprint->unsignedInteger('identity_id');
            $blueprint->string('hash');
        });

        DB::listen(function (QueryExecuted $query): void {
            $this->statements[] = $query->sql;
        });
    }

    /**
     * Drop the identity tables.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Schema::dropIfExists('identity_passwords');
        Schema::dropIfExists('separate_password_identities');
        Schema::dropIfExists('stub_principals');

        parent::tearDown();
    }

    /**
     * An outdated hash is replaced with one at the current cost, in the row and
     * on the model, which is left clean; the write neither touches `updated_at`
     * nor fires model events.
     *
     * @return void
     */
    public function testOutdatedHashIsReplacedInTheRowAndOnTheModel(): void
    {
        $identity = $this->seedIdentity();
        $updated  = $identity->getAttributes()['updated_at'];

        $events = [];

        Event::listen('eloquent.*', static function (string $event) use (&$events): void {
            $events[] = $event;
        });

        Carbon::setTestNow(Carbon::now()->addHour());

        $this->provider()->rehashPasswordIfRequired($identity, ['password' => self::PASSWORD]);

        Carbon::setTestNow();

        $stored = $this->storedHash($identity);

        self::assertSame(['cost' => 5], $this->hasher(5)->info($stored)['options']);
        self::assertTrue($this->hasher(5)->check(self::PASSWORD, $stored));
        self::assertSame($stored, $identity->getAuthPassword());
        self::assertFalse($identity->isDirty());
        self::assertSame($updated, DB::table('stub_principals')->value('updated_at'));
        self::assertSame([], $events);
    }

    /**
     * A current hash is left alone without a write, unless the caller forces
     * the rehash.
     *
     * @return void
     */
    public function testCurrentHashIsRewrittenOnlyWhenForced(): void
    {
        $identity = $this->seedIdentity(5);
        $original = $this->storedHash($identity);

        $this->statements = [];

        $this->provider()->rehashPasswordIfRequired($identity, ['password' => self::PASSWORD]);

        self::assertSame([], $this->recordedStatements());
        self::assertSame($original, $this->storedHash($identity));

        $this->provider()->rehashPasswordIfRequired($identity, ['password' => self::PASSWORD], true);

        self::assertNotSame($original, $this->storedHash($identity));
        self::assertSame($this->storedHash($identity), $identity->getAuthPassword());
    }

    /**
     * A password changed after the check, while the model still holds the old
     * hash, is never overwritten with a hash of the old password, and the model
     * keeps what it had.
     *
     * @return void
     */
    public function testPasswordChangedMeanwhileIsNotOverwritten(): void
    {
        $identity  = $this->seedIdentity();
        $authentic = $identity->getAuthPassword();
        $changed   = $this->hasher(5)->make('a new password');

        DB::table('stub_principals')->where('id', $identity->getKey())->update(['password' => $changed]);

        $this->provider()->rehashPasswordIfRequired($identity, ['password' => self::PASSWORD]);

        self::assertSame($changed, $this->storedHash($identity));
        self::assertSame($authentic, $identity->getAuthPassword());
    }

    /**
     * The row is found by its key alone, so a global scope that would hide it
     * from ordinary queries does not stop the rehash.
     *
     * @return void
     */
    public function testGlobalScopesDoNotHideTheRow(): void
    {
        $identity = $this->seedIdentity();

        StubPrincipal::addGlobalScope('nobody', static function ($query): void {
            $query->whereRaw('1 = 0'); // @phpstan-ignore method.nonObject
        });

        try {
            $this->provider()->rehashPasswordIfRequired($identity, ['password' => self::PASSWORD]);
        } finally {
            StubPrincipal::clearBootedModels();
        }

        self::assertSame(['cost' => 5], $this->hasher(5)->info($this->storedHash($identity))['options']);
    }

    /**
     * A hash that does not come from the model's own password attribute (a
     * `getAuthPassword()` that reads another table) cannot be written by the
     * provider, so nothing is written, and nothing fails.
     *
     * @return void
     */
    public function testHashKeptOutsideTheModelIsLeftAlone(): void
    {
        $identity = SeparatePasswordIdentity::query()->create(['email' => 'separate@example.test']);
        $hash     = $this->hasher(4)->make(self::PASSWORD);

        DB::table('identity_passwords')->insert(['identity_id' => $identity->getKey(), 'hash' => $hash]);

        $this->statements = [];

        $this->provider()->rehashPasswordIfRequired($identity, ['password' => self::PASSWORD]);

        $statements = $this->recordedStatements();

        self::assertCount(1, $statements);
        self::assertStringStartsWith('select', $statements[0]);
        self::assertSame($hash, DB::table('identity_passwords')->value('hash'));
    }

    /**
     * Credentials without a usable password (none, an empty one, or one that is
     * not a string) rehash nothing, even for an outdated hash.
     *
     * @return void
     */
    public function testCredentialsWithoutAUsablePasswordRehashNothing(): void
    {
        $identity = $this->seedIdentity();
        $original = $this->storedHash($identity);

        $this->statements = [];

        foreach ([[], ['password' => ''], ['password' => 12345678], ['password' => null]] as $credentials) {
            $this->provider()->rehashPasswordIfRequired($identity, $credentials, true);
        }

        self::assertSame([], $this->recordedStatements());
        self::assertSame($original, $this->storedHash($identity));
        self::assertSame($original, $identity->getAuthPassword());
    }

    /**
     * An account stored without a password has nothing to rehash.
     *
     * @return void
     */
    public function testAccountWithoutAPasswordIsLeftAlone(): void
    {
        $identity = StubPrincipal::query()->create(['email' => 'passwordless@example.test', 'password' => null]);

        $this->statements = [];

        $this->provider()->rehashPasswordIfRequired($identity, ['password' => self::PASSWORD], true);

        self::assertSame([], $this->recordedStatements());
        self::assertNull(DB::table('stub_principals')->value('password'));
    }

    /**
     * The SQL run since the last reset.
     *
     * @return list<string>
     */
    private function recordedStatements(): array
    {
        return $this->statements;
    }

    /**
     * Seed an identity whose password is hashed at the given bcrypt cost.
     *
     * @param  int  $cost
     * @return \Tests\Unit\Stubs\StubPrincipal
     */
    private function seedIdentity(int $cost = 4): StubPrincipal
    {
        return StubPrincipal::query()->create([
            'email'    => 'rehash@example.test',
            'password' => $this->hasher($cost)->make(self::PASSWORD),
        ]);
    }

    /**
     * The hash the identity's row holds now.
     *
     * @param  \Tests\Unit\Stubs\StubPrincipal  $identity
     * @return string
     */
    private function storedHash(StubPrincipal $identity): string
    {
        $hash = DB::table('stub_principals')->where('id', $identity->getKey())->value('password');

        self::assertIsString($hash);

        return $hash;
    }

    /**
     * A provider whose hasher wants bcrypt cost 5.
     *
     * @return \SineMacula\Laravel\Authentication\Providers\ModelProvider
     */
    private function provider(): ModelProvider
    {
        return new ModelProvider($this->hasher(5), StubPrincipal::class);
    }

    /**
     * A bcrypt hasher at the given cost.
     *
     * @param  int  $cost
     * @return \Illuminate\Hashing\BcryptHasher
     */
    private function hasher(int $cost): BcryptHasher
    {
        return new BcryptHasher(['rounds' => $cost]);
    }
}
