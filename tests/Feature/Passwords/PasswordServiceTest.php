<?php

declare(strict_types = 1);

namespace Tests\Feature\Passwords;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Database\Events\TransactionBeginning;
use Illuminate\Database\Events\TransactionCommitted;
use Illuminate\Database\QueryException;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Application;
use Illuminate\Hashing\BcryptHasher;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Exceptions;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Facades\Validator;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\AuthManager;
use SineMacula\Laravel\Authentication\Contracts\BreachedPasswordChecker;
use SineMacula\Laravel\Authentication\Events\DeviceRevoked;
use SineMacula\Laravel\Authentication\Events\PasswordSet;
use SineMacula\Laravel\Authentication\Events\SignedOutEverywhere;
use SineMacula\Laravel\Authentication\Exceptions\BreachedPasswordCheckUnavailableException;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Listeners\RevokeDevicesOnPasswordChange;
use SineMacula\Laravel\Authentication\Models\Device;
use SineMacula\Laravel\Authentication\Passwords\Enums\PasswordFlow;
use SineMacula\Laravel\Authentication\Passwords\Enums\PasswordViolation;
use SineMacula\Laravel\Authentication\Passwords\PasswordPolicy;
use SineMacula\Laravel\Authentication\Passwords\PasswordResult;
use SineMacula\Laravel\Authentication\Passwords\PasswordService;
use SineMacula\Laravel\Authentication\Passwords\PasswordWriter;
use SineMacula\Laravel\Authentication\Testing\FakeBreachedPasswordChecker;
use Tests\Concerns\DefinesPasswordChangeRoute;
use Tests\Concerns\InspectsTraces;
use Tests\Concerns\InteractsWithPasswords;
use Tests\Fixtures\Passwords\FailingBreachedPasswordChecker;
use Tests\Integration\Fixtures\PasswordIdentity;
use Tests\Integration\Fixtures\PasswordMachine;
use Tests\TestCase;
use Tests\Unit\Stubs\PlainIdentityFixture;

/**
 * Feature tests of `Auth::passwords()`: the policy and its Laravel rule, and
 * setting a password at a registration, a change and a reset through the
 * package's guards, against the shipped device table, with the sessions each
 * flow ends, the event it reports, the refusals, and a change made over HTTP
 * from a signed-in device.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PasswordService::class)]
#[CoversClass(PasswordWriter::class)]
#[CoversClass(PasswordPolicy::class)]
#[CoversClass(PasswordSet::class)]
#[CoversClass(AuthManager::class)]
final class PasswordServiceTest extends TestCase
{
    use DefinesPasswordChangeRoute, InspectsTraces, InteractsWithPasswords;

    /** @var string A new password the default policy accepts. */
    private const string NEW_PASSWORD = 'a brand new passphrase';

    /** @var string The frozen time every write happens at. */
    private const string NOW = '2026-10-29 09:30:00';

    /**
     * Freeze the clock and create the tables.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        self::freezeClock(CarbonImmutable::parse(self::NOW));
        self::createPasswordTables();
    }

    /**
     * Release the clock and drop the tables.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        self::dropPasswordTables();
        self::freezeClock(null);

        parent::tearDown();
    }

    /**
     * A registration of an identity not stored yet inserts it with the hash of
     * the password, which Laravel's hasher verifies, reads the row it stored to
     * outdate the reset proofs of its identifiers, revokes nothing, and reports
     * `PasswordSet` for the registration with the guard, the request's client
     * and the new identity.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARegistrationStoresANewIdentity(): void
    {
        $this->recordEvents([PasswordSet::class, SignedOutEverywhere::class]);

        $identity  = (new PasswordIdentity)->forceFill(['email' => 'grace@example.test']);
        $passwords = $this->passwords();

        /** @var \ArrayObject<int, false|string> $statements */
        $statements = new \ArrayObject;

        DB::listen(static function (QueryExecuted $query) use ($statements): void {
            $statements->append(strtok(strtolower($query->sql), ' '));
        });

        $result = $passwords->set($identity, self::NEW_PASSWORD, PasswordFlow::REGISTRATION);

        self::assertSame([true, [], 0], [$result->set, $result->violations, $result->revoked]);
        self::assertSame(['insert', 'select', 'delete'], $statements->getArrayCopy());
        self::assertTrue($identity->exists);

        $stored = DB::table('password_identities')->where('email', 'grace@example.test')->value('password');

        self::assertIsString($stored);
        self::assertTrue(app(Hasher::class)->check(self::NEW_PASSWORD, $stored));
        self::assertSame($stored, $identity->password);
        self::assertSame([PasswordSet::class], $this->recordedClasses());

        $event = $this->recordedEvent(PasswordSet::class);

        self::assertSame(PasswordFlow::REGISTRATION, $event->flow);
        self::assertSame($event->context, $event->context());
        self::assertSame(['web', self::CLIENT_IP, (string) $identity->id], [$event->context->guard, $event->context->client->ip, $event->context->identityId]);
        self::assertNull($event->context->device);
    }

    /**
     * The values a stored identity with no password yet holds.
     *
     * @return iterable<string, array{0: ?string}>
     */
    public static function provideNoPassword(): iterable
    {
        yield from [
            'null'  => [null],
            'empty' => [''],
        ];
    }

    /**
     * A registration of an identity the application stored first, with no
     * password yet (`null` or empty), sets only its password (and
     * `updated_at`), revoking nothing, even sessions it already had.
     *
     * @param  ?string  $none
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideNoPassword')]
    public function testARegistrationOfAStoredIdentityRevokesNothing(?string $none): void
    {
        $identity = self::seedPasswordIdentity();

        $this->signInWithPassword();

        DB::table('password_identities')->update(['password' => $none, 'updated_at' => '2026-01-01 00:00:00']);

        $identity = $identity->fresh() ?? $identity;
        $result   = $this->passwords()->set($identity, self::NEW_PASSWORD, PasswordFlow::REGISTRATION);

        self::assertSame([true, 0], [$result->set, $result->revoked]);
        $stored = DB::table('password_identities')->value('password');

        self::assertIsString($stored);
        self::assertTrue(app(Hasher::class)->check(self::NEW_PASSWORD, $stored));
        self::assertSame(0, DB::table('devices')->whereNotNull('revoked_at')->count());
        self::assertSame(self::NOW, $identity->refresh()->updated_at?->format('Y-m-d H:i:s'));
        self::assertNull($identity->fresh()?->tokens_valid_after);
    }

    /**
     * A registration never replaces a password a stored identity has, which
     * would be a change that ends no session: it throws, and the password, the
     * sessions and the events stay as they were.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARegistrationNeverReplacesAPassword(): void
    {
        $identity = self::seedPasswordIdentity();
        $stored   = (string) $identity->password;

        $this->signInWithPassword();
        $this->recordEvents([PasswordSet::class, DeviceRevoked::class]);

        try {
            $this->passwords()->set($identity->fresh() ?? $identity, self::NEW_PASSWORD, PasswordFlow::REGISTRATION);
            self::fail('A registration replaced a password.');
        } catch (\LogicException $exception) {
            $message = PasswordIdentity::class . " {$identity->id} already has a password, or is no longer stored: a registration sets only a first password.";

            self::assertSame($message, $exception->getMessage());
        }

        self::assertSame($stored, DB::table('password_identities')->value('password'));
        self::assertNull(DB::table('devices')->value('revoked_at'));
        self::assertSame([], $this->recordedClasses());
    }

    /**
     * The events of a password set report the client the caller names, not the
     * request the guard is serving.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheClientNamedIsReported(): void
    {
        $identity = self::seedPasswordIdentity();
        $client   = new ClientContext('198.51.100.9', 'Worker/1.0');

        $this->recordEvents([PasswordSet::class]);

        self::assertTrue($this->passwords()->set($identity, self::NEW_PASSWORD, PasswordFlow::CHANGE, client: $client)->isSet());
        self::assertSame($client, $this->recordedEvent(PasswordSet::class)->context->client);
    }

    /**
     * A change ends every session of the identity, through every guard whose
     * provider returns it, except the device it was made from; moves the
     * identity's cutoff; and reports `PasswordSet` with the device kept, after
     * each `DeviceRevoked` and the `SignedOutEverywhere`.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAChangeKeepsOnlyTheDeviceItWasMadeFrom(): void
    {
        $identity = self::seedPasswordIdentity();
        $kept     = $this->signInWithPassword('web')->device;

        $this->signInWithPassword('web');
        $this->signInWithPassword('admin');
        $this->recordEvents([DeviceRevoked::class, SignedOutEverywhere::class, PasswordSet::class]);

        $result = $this->passwords()->set($identity, self::NEW_PASSWORD, PasswordFlow::CHANGE, $kept);

        self::assertSame([true, 2], [$result->set, $result->revoked]);
        self::assertSame([$kept->getKey()], DB::table('devices')->whereNull('revoked_at')->pluck('id')->all());
        self::assertSame(['password_changed', 'password_changed'], DB::table('devices')->whereNotNull('revoked_at')->pluck('revoked_reason')->all());
        self::assertSame(self::NOW, $identity->fresh()?->tokens_valid_after?->format('Y-m-d H:i:s'));
        self::assertSame([DeviceRevoked::class, DeviceRevoked::class, SignedOutEverywhere::class, PasswordSet::class], $this->recordedClasses());

        $event = $this->recordedEvent(PasswordSet::class);

        self::assertSame(PasswordFlow::CHANGE, $event->flow);
        self::assertSame($kept, $event->context->device);
    }

    /**
     * A reset ends every session of the identity through every guard, and moves
     * its cutoff.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAResetEndsEverySession(): void
    {
        $identity = self::seedPasswordIdentity();

        $this->signInWithPassword('web');
        $this->signInWithPassword('admin');

        $result = $this->passwords('admin')->set($identity, self::NEW_PASSWORD, PasswordFlow::RESET);

        self::assertSame([true, 2], [$result->set, $result->revoked]);
        self::assertSame(['password_reset', 'password_reset'], DB::table('devices')->pluck('revoked_reason')->all());
        self::assertSame(self::NOW, $identity->fresh()?->tokens_valid_after?->format('Y-m-d H:i:s'));
        self::assertTrue(app(Hasher::class)->check(self::NEW_PASSWORD, (string) $identity->refresh()->password));
    }

    /**
     * A password that breaks the policy writes nothing, revokes nothing and
     * reports nothing: the result lists the rules it breaks.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARejectedPasswordChangesNothing(): void
    {
        config()->set('authentication.passwords.numbers', true);

        $identity = self::seedPasswordIdentity();
        $before   = $identity->password;

        $this->signInWithPassword();
        $this->recordEvents([PasswordSet::class, DeviceRevoked::class, SignedOutEverywhere::class]);

        $result = $this->passwords()->set($identity, 'too short', PasswordFlow::RESET);

        self::assertSame([false, [PasswordViolation::TOO_SHORT, PasswordViolation::NUMBERS], 0], [$result->set, $result->violations, $result->revoked]);
        self::assertSame($before, $identity->fresh()?->password);
        self::assertSame($before, $identity->password);
        self::assertSame(0, DB::table('devices')->whereNotNull('revoked_at')->count());
        self::assertSame([], $this->recordedClasses());
    }

    /**
     * A checker failing with an exception of its own lets it propagate through
     * `check()` and `set()`, and no frame of its trace carries the password as
     * an argument, even with arguments recorded in traces.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFailingCheckerLeavesThePasswordOutOfTheTrace(): void
    {
        $identity = self::seedPasswordIdentity();

        app()->instance(BreachedPasswordChecker::class, new FailingBreachedPasswordChecker);

        $calls = [
            fn (): mixed => $this->passwords()->check(self::NEW_PASSWORD),
            fn (): mixed => $this->passwords()->set($identity, self::NEW_PASSWORD, PasswordFlow::CHANGE),
        ];

        foreach ($calls as $call) {

            $exception = self::withArgumentsInTraces(\RuntimeException::class, $call);

            self::assertSame('a bug in the checker', $exception->getMessage());
            self::assertFalse(self::hasInTrace($exception, self::NEW_PASSWORD));
        }
    }

    /**
     * A write that fails inside its transaction leaves the new password and its
     * hash out of every frame of the trace, the transaction's closure and what
     * it captured included, even with arguments recorded in traces.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFailedWriteLeavesThePasswordAndItsHashOutOfTheTrace(): void
    {
        $identity = self::seedPasswordIdentity();

        DB::table('password_identities')->delete();

        $exception = self::withArgumentsInTraces(\LogicException::class, fn (): mixed => $this->passwords()->set($identity, self::NEW_PASSWORD, PasswordFlow::CHANGE));
        $isSecret  = static fn (string $value): bool => $value === self::NEW_PASSWORD || password_verify(self::NEW_PASSWORD, $value);

        self::assertStringContainsString('is no longer stored', $exception->getMessage());
        $stored = (string) $identity->password;

        self::assertTrue(self::carries([static fn (): string => $stored], static fn (string $value): bool => password_verify(self::PASSWORD, $value)));
        self::assertFalse(self::hasInTrace($exception, $isSecret));
    }

    /**
     * An update the database refuses (here for a column the table lost) throws
     * Laravel's own `QueryException`, which carries the new hash, as the
     * passwords guide says, in its bindings and its message; the password
     * itself is in no frame of the trace.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnUpdateTheDatabaseRefusesCarriesOnlyTheHash(): void
    {
        $identity = self::seedPasswordIdentity();
        $isHash   = static fn (string $value): bool => password_verify(self::NEW_PASSWORD, $value);

        Schema::table('password_identities', static function (Blueprint $blueprint): void {
            $blueprint->dropColumn('updated_at');
        });

        $exception = self::withArgumentsInTraces(QueryException::class, fn (): mixed => $this->passwords()->set($identity, self::NEW_PASSWORD, PasswordFlow::CHANGE));

        $hash = array_values(array_filter($exception->getBindings(), static fn (mixed $binding): bool => is_string($binding) && $isHash($binding)));

        self::assertStringContainsString('updated_at', $exception->getMessage());
        self::assertCount(1, $hash);
        self::assertStringContainsString($hash[0], $exception->getMessage());
        self::assertFalse(self::hasInTrace($exception, static fn (string $value): bool => str_contains($value, self::NEW_PASSWORD)));
    }

    /**
     * Under bcrypt, a password holding a null character, which the hasher would
     * refuse with an exception, is rejected instead, in every flow: nothing is
     * written or reported.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testANullCharacterIsRejectedUnderBcrypt(): void
    {
        config()->set('hashing.driver', 'bcrypt');

        $identity = self::seedPasswordIdentity();
        $before   = $identity->password;

        $this->recordEvents([PasswordSet::class]);

        foreach (PasswordFlow::cases() as $flow) {

            $result = $this->passwords()->set($identity, "correct horse battery\0staple", $flow);

            self::assertSame([false, [PasswordViolation::NULL_CHARACTER]], [$result->set, $result->violations]);
        }

        self::assertSame($before, $identity->fresh()?->password);
        self::assertSame([], $this->recordedClasses());
    }

    /**
     * A breached password is rejected after the other rules pass, and with the
     * checker down the default fails closed, in every flow: each is rejected
     * with the violation, and the stored passwords, the sessions and the events
     * stay as they were.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheBreachedCheckGuardsEveryFlow(): void
    {
        $checker    = FakeBreachedPasswordChecker::fake([self::NEW_PASSWORD], $this->app);
        $identity   = self::seedPasswordIdentity();
        $registered = self::seedPasswordIdentity('new@example.test', ['password' => null]);
        $before     = $identity->password;

        $this->signInWithPassword();
        $this->recordEvents([PasswordSet::class, DeviceRevoked::class, SignedOutEverywhere::class]);

        $for = static fn (PasswordFlow $flow): PasswordIdentity => $flow === PasswordFlow::REGISTRATION ? $registered : $identity;
        $set = fn (PasswordFlow $flow, string $password): PasswordResult => $this->passwords()->set($for($flow), $password, $flow);

        foreach (PasswordFlow::cases() as $flow) {

            $result = $set($flow, self::NEW_PASSWORD);

            self::assertSame([false, [PasswordViolation::BREACHED]], [$result->set, $result->violations]);
        }

        $checker->unavailable();

        foreach (PasswordFlow::cases() as $flow) {

            $result = $set($flow, 'another fine passphrase');

            self::assertSame([false, [PasswordViolation::BREACH_CHECK_UNAVAILABLE]], [$result->set, $result->violations]);
        }

        self::assertSame([$before, null], [$identity->fresh()?->password, $registered->fresh()?->password]);
        self::assertSame(0, DB::table('devices')->whereNotNull('revoked_at')->count());
        self::assertSame([], $this->recordedClasses());
    }

    /**
     * With the checker down and the policy set to fail open, the password is
     * set as if it had passed, and the outage is reported to the exception
     * handler.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnUnavailableCheckerLetsThePasswordThroughWhenSetToFailOpen(): void
    {
        config()->set('authentication.passwords.breached.when_unavailable', 'allow');

        $exceptions = Exceptions::fake([BreachedPasswordCheckUnavailableException::class]);

        FakeBreachedPasswordChecker::fake(container: $this->app)->unavailable();

        $identity = self::seedPasswordIdentity();
        $result   = $this->passwords()->set($identity, self::NEW_PASSWORD, PasswordFlow::CHANGE);

        self::assertSame([true, []], [$result->set, $result->violations]);
        self::assertTrue(app(Hasher::class)->check(self::NEW_PASSWORD, (string) $identity->fresh()?->password));

        $exceptions->assertReported(BreachedPasswordCheckUnavailableException::class);
    }

    /**
     * The helper's write is one query-builder update of the password column:
     * another attribute left dirty on the model is neither saved nor discarded,
     * and no model event fires, so the optional observer does not revoke the
     * device the change kept.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testOnlyThePasswordIsWrittenAndNoObserverSeesIt(): void
    {
        PasswordIdentity::observe(RevokeDevicesOnPasswordChange::class);

        $identity = self::seedPasswordIdentity();
        $kept     = $this->signInWithPassword()->device;

        $identity->nickname = 'Countess';

        $result = $this->passwords()->set($identity, self::NEW_PASSWORD, PasswordFlow::CHANGE, $kept);

        self::assertSame([true, 0], [$result->set, $result->revoked]);
        self::assertNull(DB::table('password_identities')->value('nickname'));
        self::assertSame(['nickname'], array_keys($identity->getDirty()));
        self::assertTrue(app(Hasher::class)->check(self::NEW_PASSWORD, (string) $identity->password));
        self::assertSame($identity->password, $identity->getOriginal('password'));
        self::assertNull(DB::table('devices')->value('revoked_at'));
    }

    /**
     * Rows of a call that misuses the helper, and what it throws.
     *
     * @return iterable<string, array{0: \Closure(\SineMacula\Laravel\Authentication\Passwords\PasswordService): mixed, 1: class-string<\Throwable>, 2: string}>
     */
    public static function provideMisuses(): iterable
    {
        yield from [
            'a machine identity' => [
                static fn (PasswordService $passwords): PasswordResult => $passwords->set(self::seedMachine(), self::NEW_PASSWORD, PasswordFlow::RESET),
                \InvalidArgumentException::class,
                PasswordMachine::class . ' is a machine identity: it has no password to set.',
            ],
            'an identity that is not a model' => [
                static fn (PasswordService $passwords): PasswordResult => $passwords->set(new PlainIdentityFixture(1), self::NEW_PASSWORD, PasswordFlow::CHANGE),
                \LogicException::class,
                PlainIdentityFixture::class . ' is not an Eloquent model, so its password cannot be set.',
            ],
            'a change of an identity not stored' => [
                static fn (PasswordService $passwords): PasswordResult => $passwords->set(new PasswordIdentity, self::NEW_PASSWORD, PasswordFlow::CHANGE),
                \LogicException::class,
                PasswordIdentity::class . ' is not stored yet: only a registration may set the password of a new identity.',
            ],
            'a reset of an identity not stored' => [
                static fn (PasswordService $passwords): PasswordResult => $passwords->set(new PasswordIdentity, self::NEW_PASSWORD, PasswordFlow::RESET),
                \LogicException::class,
                PasswordIdentity::class . ' is not stored yet: only a registration may set the password of a new identity.',
            ],
            'a device kept by a reset' => [
                static fn (PasswordService $passwords): PasswordResult => $passwords->set(self::seedPasswordIdentity(), self::NEW_PASSWORD, PasswordFlow::RESET, new Device),
                \InvalidArgumentException::class,
                'A device to keep signed in is for a change of password, not a reset.',
            ],
            'a device kept by a registration' => [
                static fn (PasswordService $passwords): PasswordResult => $passwords->set(new PasswordIdentity, self::NEW_PASSWORD, PasswordFlow::REGISTRATION, new Device),
                \InvalidArgumentException::class,
                'A device to keep signed in is for a change of password, not a registration.',
            ],
            'a guard that is not a jwt guard' => [
                static fn (): PasswordService => Auth::passwords('session'),
                \InvalidArgumentException::class,
                'Auth guard [session] is not a jwt guard, so it has no password service.',
            ],
        ];
    }

    /**
     * Each misuse is a misconfiguration, refused before the policy runs or
     * anything is written.
     *
     * @param  \Closure(\SineMacula\Laravel\Authentication\Passwords\PasswordService): mixed  $call
     * @param  class-string<\Throwable>  $exception
     * @param  string  $message
     * @return void
     */
    #[DataProvider('provideMisuses')]
    public function testMisusesAreRefused(\Closure $call, string $exception, string $message): void
    {
        $checker = FakeBreachedPasswordChecker::fake(container: $this->app);

        $this->recordEvents([PasswordSet::class]);

        try {
            $call($this->passwords());
            self::fail('The misuse was accepted.');
        } catch (\Throwable $thrown) {
            self::assertSame([$exception, $message], [$thrown::class, $thrown->getMessage()]);
        }

        self::assertSame(0, $checker->count());
        self::assertSame([], $this->recordedClasses());

        foreach (PasswordIdentity::query()->get() as $stored) {
            self::assertTrue(app(Hasher::class)->check(self::PASSWORD, (string) $stored->password));
        }
    }

    /**
     * A registration a model event cancels sets nothing and says so, rather
     * than reporting a password that was never stored.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARegistrationAnObserverCancelsThrows(): void
    {
        PasswordIdentity::creating(static fn (): bool => false);

        $this->recordEvents([PasswordSet::class]);

        try {
            $this->passwords()->set((new PasswordIdentity)->forceFill(['email' => 'grace@example.test']), self::NEW_PASSWORD, PasswordFlow::REGISTRATION);
            self::fail('A cancelled registration was reported as set.');
        } catch (\LogicException $exception) {
            self::assertSame(PasswordIdentity::class . ' was not saved: a model event cancelled the registration, so no password was set.', $exception->getMessage());
        }

        self::assertSame(0, DB::table('password_identities')->count());
        self::assertSame([], $this->recordedClasses());
    }

    /**
     * An identity whose row was deleted since it was loaded gets no password
     * and loses no session: the whole change rolls back.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnIdentityNoLongerStoredThrowsAndRevokesNothing(): void
    {
        $identity = self::seedPasswordIdentity();

        $this->signInWithPassword();
        $this->recordEvents([PasswordSet::class, DeviceRevoked::class]);

        DB::table('password_identities')->delete();

        try {
            $this->passwords()->set($identity, self::NEW_PASSWORD, PasswordFlow::RESET);
            self::fail('A password was set on a row that is gone.');
        } catch (\LogicException $exception) {
            self::assertSame(PasswordIdentity::class . " {$identity->id} is no longer stored, so no password was set.", $exception->getMessage());
        }

        self::assertNull(DB::table('devices')->value('revoked_at'));
        self::assertSame([], $this->recordedClasses());
    }

    /**
     * The policy never applies to the automatic rehash: an identity whose
     * legacy password is shorter than the policy allows still signs in, and its
     * outdated hash is replaced, with nothing reported as set or revoked.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheRehashOnSignInIgnoresThePolicy(): void
    {
        $legacy = 'short1';
        $hash   = (new BcryptHasher(['rounds' => 5]))->make($legacy);

        self::assertSame([PasswordViolation::TOO_SHORT], $this->passwords()->check($legacy)->violations);

        self::seedPasswordIdentity(attributes: ['password' => $hash]);

        $this->recordEvents([PasswordSet::class, DeviceRevoked::class]);

        $session = $this->sessions('web')->signIn('password', ['email' => 'ada@example.test', 'password' => $legacy])->session;
        $stored  = (string) PasswordIdentity::query()->sole()->password;

        self::assertNotNull($session);
        self::assertNotSame($hash, $stored);
        self::assertTrue(app(Hasher::class)->check($legacy, $stored));
        self::assertFalse(app(Hasher::class)->needsRehash($stored));
        self::assertSame([], $this->recordedClasses());
    }

    /**
     * A change of password over HTTP, as an application's route makes it: the
     * signed-in device stays signed in and its token keeps working, while the
     * identity's other session is ended and its token refused.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAChangeOverHttpKeepsTheRequestsDevice(): void
    {
        self::seedPasswordIdentity();

        $current = $this->signInWithPassword()->tokens->accessToken;
        $other   = $this->signInWithPassword()->tokens->accessToken;

        Auth::forgetGuards();

        Route::middleware('auth:web')->post('/password', static function (Request $request): array {
            $identity = Auth::identity();

            assert($identity !== null);

            $result     = Auth::passwords('web')->set($identity, $request->string('password')->value(), PasswordFlow::CHANGE, Auth::device());
            $violations = array_map(static fn (PasswordViolation $violation): string => $violation->value, $result->violations);

            return ['set' => $result->set, 'violations' => $violations, 'revoked' => $result->revoked];
        });

        Route::middleware('auth:web')->get('/me', static fn (): array => ['id' => Auth::id()]);

        $this->withToken($current)->postJson('/password', ['password' => 'short'])->assertExactJson(['set' => false, 'violations' => ['too_short'], 'revoked' => 0]);
        $this->withToken($current)->postJson('/password', ['password' => self::NEW_PASSWORD])->assertExactJson(['set' => true, 'violations' => [], 'revoked' => 1]);

        self::freezeClock(CarbonImmutable::parse(self::NOW)->addSecond());

        $this->withToken($current)->getJson('/me')->assertOk();
        $this->withToken($other)->getJson('/me')->assertUnauthorized();
    }

    /**
     * The documented password change route, over HTTP: a wrong current password
     * sets nothing and keeps its sign-in slots, taken before the transaction; a
     * right one sets the new password, ends the identity's other session, keeps
     * the request's device and gives the slots back. The identity's row is
     * locked as the transaction starts, the current password is checked against
     * it without looking the identity up by its address, and no counter is
     * written inside the transaction.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheDocumentedChangeChecksTheCurrentPasswordUnderTheIdentitysLock(): void
    {
        self::seedPasswordIdentity();

        $current = $this->signInWithPassword()->tokens->accessToken;
        $other   = $this->signInWithPassword()->tokens->accessToken;

        Auth::forgetGuards();
        DB::table('rate_limits')->delete();

        self::definePasswordChangeRoute('web');

        Route::middleware('auth:web')->get('/me', static fn (): array => ['id' => Auth::id()]);

        $wrong = $this->withToken($current)->putJson('/password', ['current_password' => 'not the password', 'password' => self::NEW_PASSWORD]);

        $wrong->assertStatus(422)->assertExactJson(['message' => 'The current password is wrong.']);

        self::assertSame([1, 1], array_map(intval(...), DB::table('rate_limits')->orderBy('key')->pluck('hits')->all()));
        self::assertTrue(app(Hasher::class)->check(self::PASSWORD, (string) PasswordIdentity::query()->sole()->password));

        $statements = [];

        DB::listen(static function (QueryExecuted $query) use (&$statements): void {
            $statements[] = $query->sql;
        });

        Event::listen(TransactionBeginning::class, static function () use (&$statements): void {
            $statements[] = 'begin';
        });

        Event::listen(TransactionCommitted::class, static function () use (&$statements): void {
            $statements[] = 'commit';
        });

        $this->withToken($current)->putJson('/password', ['current_password' => self::PASSWORD, 'password' => self::NEW_PASSWORD])->assertNoContent();

        $begin  = (int) array_search('begin', $statements, true);
        $commit = (int) array_search('commit', $statements, true);
        $inside = array_slice($statements, $begin + 1, $commit - $begin - 1);

        self::assertSame([1, 1], array_map(intval(...), DB::table('rate_limits')->orderBy('key')->pluck('hits')->all()));
        self::assertTrue(app(Hasher::class)->check(self::NEW_PASSWORD, (string) PasswordIdentity::query()->sole()->password));
        self::assertNotSame([], array_filter(array_slice($statements, 0, $begin), static fn (string $sql): bool => str_contains($sql, 'rate_limits')));
        self::assertNotSame([], array_filter(array_slice($statements, $commit), static fn (string $sql): bool => str_contains($sql, 'rate_limits')));
        self::assertSame([], array_filter($inside, static fn (string $sql): bool => str_contains($sql, 'rate_limits')));
        self::assertStringContainsString('password_identities', $inside[0]);
        self::assertSame([], array_filter($statements, static fn (string $sql): bool => (bool) preg_match('/^select .+ where .email. = \?/', $sql)));

        self::freezeClock(CarbonImmutable::parse(self::NOW)->addSecond());

        $this->withToken($current)->getJson('/me')->assertOk();
        $this->withToken($other)->getJson('/me')->assertUnauthorized();
    }

    /**
     * The documented change checks the current password against the identity it
     * locked, never through its address: once the address the session was
     * opened with belongs to another identity, that identity's password does
     * not change this one's.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheDocumentedChangeIgnoresAnotherIdentityNowHoldingTheAddress(): void
    {
        $identity = self::seedPasswordIdentity();
        $access   = $this->signInWithPassword()->tokens->accessToken;
        $moved    = false;

        Auth::forgetGuards();

        self::definePasswordChangeRoute('web');

        Event::listen(TransactionBeginning::class, static function () use (&$moved): void {
            if ($moved) {
                return;
            }

            $moved = true;

            DB::table('password_identities')->update(['email' => 'ada@moved.example.test']);

            self::seedPasswordIdentity(attributes: ['password' => app(Hasher::class)->make('the other identity passphrase')]);
        });

        $this->withToken($access)->putJson('/password', ['current_password' => 'the other identity passphrase', 'password' => self::NEW_PASSWORD])->assertStatus(422);

        self::assertTrue($moved);
        self::assertTrue(app(Hasher::class)->check(self::PASSWORD, (string) $identity->fresh()?->password));
    }

    /**
     * `rule()` is Laravel's `Password` rule for the same length and
     * composition, so a form and `check()` agree on every password the rule can
     * judge; the three differences are pinned: the rule runs no breached check,
     * and cannot see bcrypt's byte ceiling or its refusal of a null character.
     *
     * @return void
     */
    public function testTheRuleAgreesWithTheCheckOverACorpus(): void
    {
        config()->set('hashing.driver', 'argon2id');
        config()->set('authentication.passwords', ['min_length' => 10, 'max_length' => 40, 'letters' => true, 'mixed_case' => true, 'numbers' => true, 'symbols' => true]);

        $corpus = [
            'Aa1!Aa1!Aa', 'Aa1!Aa1!A', 'aa1!aa1!aa', 'AA1!AA1!AA', 'Aaa!Aaa!Aa', 'Aa1aAa1aAa', 'Aa1 Aa1 Aa', 'Ää1!Ää1!Ää',
            'Жж1!Жж1!Жж', 'Aa٣!Aa٣!Aa', str_repeat('Aa1!', 10), str_repeat('Aa1!', 10) . 'x', '1234567890', 'ÉCOLE école 1', "Aa1!\nAa1!aa",
        ];

        foreach ($corpus as $password) {

            $form  = Validator::make(['password' => $password], ['password' => [$this->passwords()->rule()]])->passes();
            $check = $this->passwords()->check($password)->passes();

            self::assertSame($form, $check, "The rule and the check disagree on [{$password}].");
        }

        FakeBreachedPasswordChecker::fake(['Aa1!Aa1!Aa'], $this->app);

        self::assertTrue(Validator::make(['password' => 'Aa1!Aa1!Aa'], ['password' => [$this->passwords()->rule()]])->passes());
        self::assertSame([PasswordViolation::BREACHED], $this->passwords()->check('Aa1!Aa1!Aa')->violations);

        config()->set('hashing.driver', 'bcrypt');

        $wide = str_repeat('€', 25) . 'a1!A';

        self::assertTrue(Validator::make(['password' => $wide], ['password' => [$this->passwords()->rule()]])->passes());
        self::assertSame([PasswordViolation::TOO_LONG], $this->passwords()->check($wide)->violations);

        $null = "Aa1!Aa1!\0Aa";

        self::assertTrue(Validator::make(['password' => $null], ['password' => [$this->passwords()->rule()]])->passes());
        self::assertSame([PasswordViolation::NULL_CHARACTER], $this->passwords()->check($null)->violations);
    }

    /**
     * Configure the guards, and a session guard to refuse.
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

        self::configurePasswordGuards($config);

        $config->set('auth.guards.session', ['driver' => 'session', 'provider' => 'password_identities']);
    }

    /**
     * The password service of the guard, on a guard resolved afresh for a
     * request from the test client.
     *
     * @param  string  $guard
     * @return \SineMacula\Laravel\Authentication\Passwords\PasswordService
     */
    private function passwords(string $guard = 'web'): PasswordService
    {
        $this->freshGuard($guard);

        return Auth::passwords($guard);
    }

    /**
     * Persist a machine identity with a password.
     *
     * @return \Tests\Integration\Fixtures\PasswordMachine
     */
    private static function seedMachine(): PasswordMachine
    {
        $machine = new PasswordMachine;

        $machine->forceFill(['email' => 'robot@example.test', 'password' => app(Hasher::class)->make(self::PASSWORD)])->save();

        return $machine;
    }
}
