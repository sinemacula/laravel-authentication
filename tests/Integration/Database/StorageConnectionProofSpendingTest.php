<?php

declare(strict_types = 1);

namespace Tests\Integration\Database;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Database\Query\Builder;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Application;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Database\SharedConnection;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\IdentifierChanges\ChangeConfirmation;
use SineMacula\Laravel\Authentication\IdentifierChanges\Enums\IdentifierChangeOutcome;
use SineMacula\Laravel\Authentication\IdentifierChanges\IdentifierChangeService;
use SineMacula\Laravel\Authentication\Models\Device;
use SineMacula\Laravel\Authentication\Passwords\PasswordService;
use SineMacula\Laravel\Authentication\Passwords\PasswordWriter;
use SineMacula\Laravel\Authentication\Passwords\ResetResult;
use SineMacula\Laravel\Authentication\Passwords\ResetSubmissions;
use SineMacula\Laravel\Authentication\Sessions\Reauthentication;
use SineMacula\Laravel\Authentication\Testing\FakeIdentifierChangeNotifier;
use SineMacula\Laravel\Authentication\Testing\FakeOneTimeCodeSender;
use SineMacula\Laravel\Authentication\Testing\FakePasswordResetLinkSender;
use Tests\Concerns\InteractsWithDevices;
use Tests\Concerns\InteractsWithPasswords;
use Tests\Integration\Fixtures\StoredIdentity;
use Tests\TestCase;

/**
 * End-to-end tests of the flows that spend a proof with a change to the
 * identity, with the identities on the storage connection beside the package's
 * tables and neither on the default one, as the shared connection rule
 * requires: an identifier change confirmed by its code and a password reset by
 * its link each write the identity, use the proof up and end what they end
 * where the shipped migrations created the tables, and a failure once the
 * identity is written rolls every one of those writes back, so the same proof
 * still works, once.
 *
 * The storage connection is a second connection to the test database with a
 * table prefix of its own: a database of its own on SQLite, and prefixed tables
 * beside the default connection's on PostgreSQL and MySQL.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SharedConnection::class)]
#[CoversClass(IdentifierChangeService::class)]
#[CoversClass(ChangeConfirmation::class)]
#[CoversClass(ResetSubmissions::class)]
#[CoversClass(PasswordWriter::class)]
final class StorageConnectionProofSpendingTest extends TestCase
{
    use InteractsWithDevices, InteractsWithPasswords;

    /** @var string The connection the identities and the package's tables live on. */
    private const string STORAGE = StoredIdentity::CONNECTION;

    /** @var string The seeded identity's email address. */
    private const string EMAIL = 'ada@example.test';

    /** @var string The address a change moves to. */
    private const string NEW_EMAIL = 'ada@new.example.test';

    /** @var string The password a reset sets. */
    private const string NEW_PASSWORD = 'a brand new passphrase';

    /** @var string What the injected failure says. */
    private const string FAILURE = 'The write could not be completed.';

    /** @var \SineMacula\Laravel\Authentication\Testing\FakeOneTimeCodeSender The sender change codes are delivered through. */
    private FakeOneTimeCodeSender $codes;

    /** @var \SineMacula\Laravel\Authentication\Testing\FakePasswordResetLinkSender The sender reset links are delivered through. */
    private FakePasswordResetLinkSender $links;

    /** @var ?string The table whose next write on the storage connection fails once written, if any. */
    private ?string $failAfterWriting = null;

    /**
     * Freeze the clock, create the identities on the storage connection, fake
     * the senders and the notifier, and fail a write once it has run when a
     * test asks for it.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        self::freezeClock(CarbonImmutable::createStrict(2026, 10, 29, 9, 30, 0));

        Schema::connection(self::STORAGE)->create('stored_identities', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('email')->nullable()->unique();
            $blueprint->dateTime('email_verified_at', 0)->nullable();
            $blueprint->string('password')->nullable();
            $blueprint->dateTime('tokens_valid_after', 0)->nullable();
            $blueprint->timestamps();
        });

        $this->codes = FakeOneTimeCodeSender::fake($this->app);
        $this->links = FakePasswordResetLinkSender::fake($this->app);

        FakeIdentifierChangeNotifier::fake($this->app);

        Event::listen(QueryExecuted::class, function (QueryExecuted $query): void {
            if ($this->failAfterWriting === null || $query->connectionName !== self::STORAGE) {
                return;
            }

            if (preg_match('/^\s*(update|delete)\b/i', $query->sql) === 1 && str_contains($query->sql, $this->failAfterWriting)) {
                throw new \RuntimeException(self::FAILURE);
            }
        });
    }

    /**
     * Drop the identities and release the clock.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Schema::connection(self::STORAGE)->dropIfExists('stored_identities');

        self::freezeClock(null);

        parent::tearDown();
    }

    /**
     * A change requested by code waits on the storage connection; confirming it
     * with the code delivered moves the identity's address there, deletes the
     * pending change and uses the code up.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnIdentifierChangeIsMadeOnTheStorageConnection(): void
    {
        $identity = $this->seedStored();
        $code     = $this->requestChange($identity);

        self::assertSame(IdentifierChangeOutcome::CHANGED, $this->changes()->confirmByCode($identity, 'email', $code));
        self::assertSame(self::NEW_EMAIL, $this->stored()->value('email'));
        self::assertSame(0, $this->storage('identifier_changes')->count());
        self::assertSame(0, $this->unspentCodes());
    }

    /**
     * A failure once the new address is written rolls the confirmation back
     * whole on the storage connection: the address, the pending change and the
     * unspent code are as they were, and the same code then makes the change,
     * once.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFailedIdentifierChangeLeavesItsProofUnspent(): void
    {
        $identity = $this->seedStored();
        $code     = $this->requestChange($identity);

        $this->failAfterWriting = 'stored_identities';

        $this->assertFails(fn (): mixed => $this->changes()->confirmByCode($identity, 'email', $code));

        self::assertSame(self::EMAIL, $this->stored()->value('email'));
        self::assertSame(1, $this->storage('identifier_changes')->count());
        self::assertSame(1, $this->unspentCodes());

        $this->failAfterWriting = null;

        self::assertSame(IdentifierChangeOutcome::CHANGED, $this->changes()->confirmByCode($identity, 'email', $code));
        self::assertSame(self::NEW_EMAIL, $this->stored()->value('email'));
        self::assertSame(IdentifierChangeOutcome::INVALID, $this->changes()->confirmByCode($identity, 'email', $code));
    }

    /**
     * A reset by the link delivered sets the new password on the storage
     * connection, moves the identity's cutoff, revokes its device there and
     * uses the link's token up.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPasswordIsResetOnTheStorageConnection(): void
    {
        $identity = $this->seedStored();

        self::seedStoredDevice($identity);

        $result = $this->reset($this->requestLink());

        self::assertTrue($result->isReset());
        self::assertSame(1, $result->revoked);
        self::assertTrue($this->hasPassword(self::NEW_PASSWORD));
        self::assertNotNull($this->stored()->value('tokens_valid_after'));
        self::assertSame(0, $this->storage('devices')->whereNull('revoked_at')->count());
        self::assertSame(0, $this->unspentCodes());
    }

    /**
     * A failure once the device is revoked, after the password and the cutoff
     * are written, rolls the reset back whole on the storage connection: the
     * old password, no cutoff, a live device and an unspent token; the same
     * token then resets the password, once.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFailedPasswordResetLeavesItsProofUnspent(): void
    {
        $identity = $this->seedStored();

        self::seedStoredDevice($identity);

        $token = $this->requestLink();

        $this->failAfterWriting = 'devices';

        $this->assertFails(fn (): mixed => $this->reset($token));

        self::assertTrue($this->hasPassword(self::PASSWORD));
        self::assertNull($this->stored()->value('tokens_valid_after'));
        self::assertSame(1, $this->storage('devices')->whereNull('revoked_at')->count());
        self::assertSame(1, $this->unspentCodes());

        $this->failAfterWriting = null;

        self::assertTrue($this->reset($token)->isReset());
        self::assertTrue($this->hasPassword(self::NEW_PASSWORD));
        self::assertFalse($this->reset($token)->isReset());
    }

    /**
     * Put the package's tables on a prefixed connection to the test database,
     * and register a guard over the identities kept there.
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

        $config = $app->make(ConfigRepository::class);

        $config->set('database.connections.' . self::STORAGE, [...$config->array('database.connections.testing'), 'prefix' => 'store_']);
        $config->set('authentication.storage.connection', self::STORAGE);
        $config->set('auth.providers.stored', ['driver' => 'model', 'model' => StoredIdentity::class]);
        $config->set('auth.guards.web', ['driver' => 'jwt', 'provider' => 'stored', 'audience' => ['methods' => ['password']]]);
        $config->set('queue.default', 'sync');
        $config->set('queue.connections.sync', ['driver' => 'sync']);
        $config->set('hashing.bcrypt.rounds', 4);
        $config->set('authentication.timebox.credentials_microseconds', 1);
    }

    /**
     * Persist the identity with its verified address and the shared password.
     *
     * @return \Tests\Integration\Fixtures\StoredIdentity
     */
    private function seedStored(): StoredIdentity
    {
        return StoredIdentity::query()->create([
            'email'             => self::EMAIL,
            'email_verified_at' => '2026-01-01 00:00:00',
            'password'          => app(Hasher::class)->make(self::PASSWORD),
        ]);
    }

    /**
     * Persist a live device of the identity for the guard.
     *
     * @param  \Tests\Integration\Fixtures\StoredIdentity  $identity
     * @return void
     */
    private static function seedStoredDevice(StoredIdentity $identity): void
    {
        (new Device)->forceFill([
            ...self::liveSession('web', $identity),
            'signed_in_at'         => Carbon::now(),
            'authenticatable_type' => $identity->getMorphClass(),
            'authenticatable_id'   => (string) $identity->id,
        ])->save();
    }

    /**
     * Request a change of the identity's address, proven by code, and return
     * the code delivered to the new address.
     *
     * @param  \Tests\Integration\Fixtures\StoredIdentity  $identity
     * @return string
     *
     * @throws \Throwable
     */
    private function requestChange(StoredIdentity $identity): string
    {
        self::assertTrue($this->changes()->requestByCode($identity, 'email', self::NEW_EMAIL, Reauthentication::confirmedAt(CarbonImmutable::now()))->isSent());
        self::assertSame(1, $this->storage('identifier_changes')->count());

        app()->terminate();

        $code = $this->codes->lastCodeFor(self::NEW_EMAIL);

        self::assertIsString($code);

        return $code;
    }

    /**
     * Request a reset link for the identity and return the token delivered.
     *
     * @return string
     *
     * @throws \Throwable
     */
    private function requestLink(): string
    {
        self::assertTrue($this->passwords()->sendResetLink(['email' => self::EMAIL])->isSent());

        app()->terminate();

        $token = $this->links->lastTokenFor(self::EMAIL);

        self::assertIsString($token);

        return $token;
    }

    /**
     * Reset the identity's password to the new one with the token.
     *
     * @param  string  $token
     * @return \SineMacula\Laravel\Authentication\Passwords\ResetResult
     *
     * @throws \Throwable
     */
    private function reset(string $token): ResetResult
    {
        return $this->passwords()->reset(['email' => self::EMAIL, 'token' => $token, 'password' => self::NEW_PASSWORD]);
    }

    /**
     * Assert the attempt fails with the injected failure.
     *
     * @param  \Closure(): mixed  $attempt
     * @return void
     */
    private function assertFails(\Closure $attempt): void
    {
        try {
            $attempt();

            self::fail('Expected the write to fail.');
        } catch (\RuntimeException $exception) {
            self::assertSame(self::FAILURE, $exception->getMessage());
        }
    }

    /**
     * The guard's identifier change service, on a guard resolved for a fresh
     * request.
     *
     * @return \SineMacula\Laravel\Authentication\IdentifierChanges\IdentifierChangeService
     */
    private function changes(): IdentifierChangeService
    {
        $this->freshGuard('web');

        return Auth::manager()->identifierChanges('web');
    }

    /**
     * The guard's password service, on a guard resolved for a fresh request.
     *
     * @return \SineMacula\Laravel\Authentication\Passwords\PasswordService
     */
    private function passwords(): PasswordService
    {
        $this->freshGuard('web');

        return Auth::passwords('web');
    }

    /**
     * Whether the stored identity's password is the one given.
     *
     * @param  string  $password
     * @return bool
     */
    private function hasPassword(string $password): bool
    {
        return app(Hasher::class)->check($password, $this->stored()->value('password'));
    }

    /**
     * How many one-time codes and tokens on the storage connection are still
     * unspent.
     *
     * @return int
     */
    private function unspentCodes(): int
    {
        return $this->storage('one_time_codes')->whereNull('consumed_at')->count();
    }

    /**
     * A query on the stored identities.
     *
     * @return \Illuminate\Database\Query\Builder
     */
    private function stored(): Builder
    {
        return $this->storage('stored_identities');
    }

    /**
     * A query on the table, on the storage connection.
     *
     * @param  string  $table
     * @return \Illuminate\Database\Query\Builder
     */
    private function storage(string $table): Builder
    {
        return DB::connection(self::STORAGE)->table($table);
    }
}
