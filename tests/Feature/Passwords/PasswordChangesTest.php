<?php

declare(strict_types = 1);

namespace Tests\Feature\Passwords;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\Enums\AuthenticationFlow;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\PasswordSet;
use SineMacula\Laravel\Authentication\Events\SessionRevoked;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Models\Session;
use SineMacula\Laravel\Authentication\Passwords\Enums\PasswordFlow;
use SineMacula\Laravel\Authentication\Passwords\Enums\PasswordViolation;
use SineMacula\Laravel\Authentication\Passwords\PasswordAlreadySet;
use SineMacula\Laravel\Authentication\Passwords\PasswordChanges;
use SineMacula\Laravel\Authentication\Passwords\PasswordResult;
use SineMacula\Laravel\Authentication\Passwords\PasswordService;
use SineMacula\Laravel\Authentication\Passwords\PasswordWriter;
use SineMacula\Laravel\Authentication\RateLimiting\AccountAttempts;
use Tests\Concerns\InteractsWithPasswords;
use Tests\Concerns\InteractsWithRateLimits;
use Tests\Integration\Fixtures\PasswordIdentity;
use Tests\Integration\Fixtures\PasswordMachine;
use Tests\TestCase;

/**
 * Feature tests for changing a signed-in identity's password with its current
 * one, and establishing a first one for an identity that has none on the
 * strength of a recent authentication, through `Auth::passwords()`: the session
 * each keeps and the sessions it ends, what is counted, checked and reported,
 * every refusal, and what a change racing another write finds under its locks.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PasswordChanges::class)]
#[CoversClass(PasswordService::class)]
#[CoversClass(PasswordWriter::class)]
#[CoversClass(PasswordAlreadySet::class)]
#[CoversClass(PasswordResult::class)]
final class PasswordChangesTest extends TestCase
{
    use InteractsWithPasswords, InteractsWithRateLimits;

    /** @var string A new password the default policy accepts. */
    private const string NEW_PASSWORD = 'a brand new passphrase';

    /** @var string The frozen time every write happens at. */
    private const string NOW = '2026-10-29 09:30:00';

    /** @var string A generation no session was issued with. */
    private const string OTHER_GENERATION = '0195f4a2-7b1c-4000-8000-00000000000f';

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
     * The right current password changes the password, keeps the session it was
     * made from, ends every other session of the identity through every guard,
     * pending ones included, moves its cutoff, gives the sign-in slot back, and
     * reports `PasswordSet` for a change with the session kept.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAChangeKeepsOnlyItsSessionAndEndsTheRest(): void
    {
        $identity = self::seedPasswordIdentity();
        $kept     = $this->signInWithPassword()->record;

        $this->signInWithPassword();
        $this->signInWithPassword('admin');

        DB::table('authentication_sessions')->where('id', '!=', $kept->getKey())->limit(1)->update(['status' => 'pending']);

        $this->recordEvents([SessionRevoked::class, PasswordSet::class, AuthenticationFailed::class]);

        $result = Auth::passwords('web')->change($kept, self::PASSWORD, self::NEW_PASSWORD);

        self::assertSame([true, 2, null], [$result->isSet(), $result->revoked, $result->reason]);
        self::assertTrue(app(Hasher::class)->check(self::NEW_PASSWORD, (string) $identity->fresh()?->password));
        self::assertSame([$kept->getKey()], DB::table('authentication_sessions')->whereNull('revoked_at')->pluck('id')->all());
        self::assertSame(['password_changed', 'password_changed'], DB::table('authentication_sessions')->whereNotNull('revoked_at')->pluck('revoked_reason')->all());
        self::assertSame(self::NOW, $identity->fresh()?->tokens_valid_after?->format('Y-m-d H:i:s'));
        self::assertSame(0, self::counterHits('sign_in', 'per_account', AccountAttempts::account($identity)));

        $event = $this->recordedEvent(PasswordSet::class);

        self::assertSame([PasswordFlow::CHANGE, $kept->getKey()], [$event->flow, $event->context->session?->getSessionIdentifier()]);
        self::assertSame([], array_filter($this->recorded, static fn (object $event): bool => $event instanceof AuthenticationFailed));
    }

    /**
     * A wrong current password writes nothing and keeps its sign-in slot,
     * counted against the account, and is reported as `invalid_credentials` on
     * the `password_change` flow; once the account's slots are used up the
     * change is `rate_limited`, with the wait, before the password is checked.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAWrongCurrentPasswordIsCountedAndRefused(): void
    {
        config()->set('authentication.rate_limits.sign_in.per_identifier', ['max' => 1, 'decay_seconds' => 300]);

        $identity = self::seedPasswordIdentity();
        $session  = $this->signInWithPassword()->record;

        DB::table('rate_limits')->delete();

        $this->recordEvents([AuthenticationFailed::class, PasswordSet::class]);

        $wrong = Auth::passwords('web')->change($session, 'not the password', self::NEW_PASSWORD);

        self::assertSame([false, FailureReason::INVALID_CREDENTIALS, null], [$wrong->isSet(), $wrong->reason, $wrong->retryAfter]);
        self::assertSame(1, self::counterHits('sign_in', 'per_account', AccountAttempts::account($identity)));
        self::assertTrue(app(Hasher::class)->check(self::PASSWORD, (string) $identity->fresh()?->password));

        $failed = $this->recordedEvent(AuthenticationFailed::class);

        self::assertSame([AuthenticationFlow::PASSWORD_CHANGE, FailureReason::INVALID_CREDENTIALS], [$failed->flow, $failed->reason]);
        self::assertTrue($identity->is($failed->context->identity));

        $this->recordEvents([AuthenticationFailed::class]);

        $limited = Auth::passwords('web')->change($session, self::PASSWORD, self::NEW_PASSWORD);

        self::assertSame([FailureReason::RATE_LIMITED, 300], [$limited->reason, $limited->retryAfter]);
        self::assertSame(
            [FailureReason::RATE_LIMITED, 300],
            [$this->recordedEvent(AuthenticationFailed::class)->reason, $this->recordedEvent(AuthenticationFailed::class)->retryAfter],
        );
        self::assertTrue(app(Hasher::class)->check(self::PASSWORD, (string) $identity->fresh()?->password));
    }

    /**
     * A new password the policy rejects writes nothing and is reported by no
     * event, once the current one was checked; an identity with no password
     * changes nothing (`password_not_set`), its password never checked.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAChangeNeedsAPasswordAndANewOneThePolicyTakes(): void
    {
        $identity = self::seedPasswordIdentity();
        $session  = $this->signInWithPassword()->record;

        $this->recordEvents([AuthenticationFailed::class, PasswordSet::class]);

        $rejected = Auth::passwords('web')->change($session, self::PASSWORD, 'short');

        self::assertSame([false, [PasswordViolation::TOO_SHORT], null], [$rejected->isSet(), $rejected->violations, $rejected->reason]);
        self::assertSame([], $this->recorded);

        DB::table('password_identities')->update(['password' => null]);

        $notSet = Auth::passwords('web')->change($session, self::PASSWORD, self::NEW_PASSWORD);

        self::assertSame(FailureReason::PASSWORD_NOT_SET, $notSet->reason);
        self::assertSame(FailureReason::PASSWORD_NOT_SET, $this->recordedEvent(AuthenticationFailed::class)->reason);
        self::assertSame(0, self::counterHits('sign_in', 'per_account', AccountAttempts::account($identity)));
    }

    /**
     * Rows of `[what happens to the session, the reason]`: a session that is no
     * longer the one given, revoked, pending, ended, another guard's, a machine
     * identity's, or one whose owner is gone, changes nothing.
     *
     * @return iterable<string, array{0: \Closure(\SineMacula\Laravel\Authentication\Models\Session): ?string, 1: \SineMacula\Laravel\Authentication\Events\Enums\FailureReason}>
     */
    public static function provideUnusableSessions(): iterable
    {
        yield from [
            'reissued'            => [static fn (Session $session): ?string => self::update($session, ['generation' => self::OTHER_GENERATION]), FailureReason::SESSION_UNKNOWN],
            'deleted'             => [static fn (Session $session): ?string => self::remove($session), FailureReason::SESSION_UNKNOWN],
            'revoked'             => [static fn (Session $session): ?string => self::update($session, ['revoked_at' => '2026-10-29 09:00:00']), FailureReason::SESSION_REVOKED],
            'pending'             => [static fn (Session $session): ?string => self::update($session, ['status' => 'pending']), FailureReason::SESSION_PENDING],
            'ended'               => [static fn (Session $session): ?string => self::update($session, ['idle_expires_at' => self::NOW]), FailureReason::SESSION_EXPIRED],
            'another guard\'s'    => [static fn (): string => 'admin', FailureReason::SESSION_GUARD_MISMATCH],
            'a machine\'s'        => [static fn (Session $session): ?string => self::update($session, ['authenticatable_type' => PasswordMachine::class]), FailureReason::MACHINE_IDENTITY], // phpcs:ignore Generic.Files.LineLength.TooLong
            'an unknown owner\'s' => [static fn (Session $session): ?string => self::update($session, ['authenticatable_id' => 999]), FailureReason::IDENTITY_UNKNOWN],
        ];
    }

    /**
     * A change or an establishment from a session the guard may not act on is
     * refused, reported, and counts and writes nothing.
     *
     * @param  \Closure(\SineMacula\Laravel\Authentication\Models\Session): ?string  $spoil
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\FailureReason  $reason
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideUnusableSessions')]
    public function testAnUnusableSessionChangesNothing(\Closure $spoil, FailureReason $reason): void
    {
        $identity = self::seedPasswordIdentity();
        $session  = $this->signInWithPassword()->record;
        $guard    = $spoil($session) ?? 'web';

        DB::table('rate_limits')->delete();

        $this->recordEvents([AuthenticationFailed::class]);

        self::assertSame($reason, Auth::passwords($guard)->change($session, self::PASSWORD, self::NEW_PASSWORD)->reason);
        self::assertSame(
            [AuthenticationFlow::PASSWORD_CHANGE, $reason],
            [$this->recordedEvent(AuthenticationFailed::class)->flow, $this->recordedEvent(AuthenticationFailed::class)->reason],
        );
        self::assertSame($reason, Auth::passwords($guard)->establish($session, self::NEW_PASSWORD)->reason);
        self::assertSame(0, DB::table('rate_limits')->count());
        $stored = DB::table('password_identities')->where('id', $identity->getKey())->value('password');

        self::assertIsString($stored);
        self::assertTrue(app(Hasher::class)->check(self::PASSWORD, $stored));
    }

    /**
     * A password written between the check of the current one and the change's
     * lock (another change, a reset) makes the current password the change was
     * proven with stale: `invalid_credentials`, and nothing more is written or
     * revoked.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPasswordWrittenMeanwhileRefusesTheChange(): void
    {
        $identity = self::seedPasswordIdentity();
        $session  = $this->signInWithPassword()->record;

        $this->signInWithPassword();
        $this->beforeTheIdentityIsLocked(static fn () => DB::table('password_identities')->update(['password' => app(Hasher::class)->make('another passphrase entirely')]));

        self::assertSame(FailureReason::INVALID_CREDENTIALS, Auth::passwords('web')->change($session, self::PASSWORD, self::NEW_PASSWORD)->reason);
        self::assertTrue(app(Hasher::class)->check('another passphrase entirely', (string) $identity->fresh()?->password));
        self::assertSame(0, DB::table('authentication_sessions')->whereNotNull('revoked_at')->count());
    }

    /**
     * A session revoked between the checks and the change's lock is found
     * revoked under the lock: `session_revoked`, nothing written.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASessionRevokedMeanwhileRefusesTheChange(): void
    {
        $identity = self::seedPasswordIdentity();
        $session  = $this->signInWithPassword()->record;

        $this->beforeTheIdentityIsLocked(static fn () => DB::table('authentication_sessions')->update(['revoked_at' => '2026-10-29 09:29:59', 'revoked_reason' => 'revoked']));

        self::assertSame(FailureReason::SESSION_REVOKED, Auth::passwords('web')->change($session, self::PASSWORD, self::NEW_PASSWORD)->reason);
        self::assertTrue(app(Hasher::class)->check(self::PASSWORD, (string) $identity->fresh()?->password));
    }

    /**
     * A passwordless identity establishes a first password from a session it
     * signed in with moments ago: the session is kept, every other session of
     * the identity ends (`password_established`), its cutoff moves, and
     * `PasswordSet` reports the flow `establishment`.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFreshSessionEstablishesAPassword(): void
    {
        $identity = self::seedPasswordIdentity(attributes: ['password' => null]);
        $kept     = $this->started($identity);

        $this->started($identity, 'admin');
        $this->recordEvents([PasswordSet::class]);

        $result = Auth::passwords('web')->establish($kept, self::NEW_PASSWORD);

        self::assertSame([true, 1], [$result->isSet(), $result->revoked]);
        self::assertTrue(app(Hasher::class)->check(self::NEW_PASSWORD, (string) $identity->fresh()?->password));
        self::assertSame([$kept->getKey()], DB::table('authentication_sessions')->whereNull('revoked_at')->pluck('id')->all());
        self::assertSame(['password_established'], DB::table('authentication_sessions')->whereNotNull('revoked_at')->pluck('revoked_reason')->all());
        self::assertSame(self::NOW, $identity->fresh()?->tokens_valid_after?->format('Y-m-d H:i:s'));
        self::assertSame(PasswordFlow::ESTABLISHMENT, $this->recordedEvent(PasswordSet::class)->flow);
    }

    /**
     * A session whose last authentication is older than the
     * `password_establishment` freshness establishes nothing:
     * `reauthentication_required`, reported, nothing written.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAStaleSessionEstablishesNothing(): void
    {
        $identity = self::seedPasswordIdentity(attributes: ['password' => null]);
        $session  = $this->started($identity);

        self::freezeClock(CarbonImmutable::parse(self::NOW)->addSeconds(900));

        $this->recordEvents([AuthenticationFailed::class]);

        self::assertSame(FailureReason::REAUTHENTICATION_REQUIRED, Auth::passwords('web')->establish($session, self::NEW_PASSWORD)->reason);
        self::assertSame(FailureReason::REAUTHENTICATION_REQUIRED, $this->recordedEvent(AuthenticationFailed::class)->reason);
        self::assertNull(DB::table('password_identities')->value('password'));
    }

    /**
     * An identity that has a password establishes nothing
     * (`password_already_set`), whether it had one from the start, one was
     * written before the establishment locked its row, or one was written after
     * the lock's check and before the write, which writes only while the row
     * has none (its transaction rolls back whole, the write that raced it
     * included, as a caller's would on a real database); and a password the
     * policy rejects is `rejected`.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnIdentityWithAPasswordEstablishesNothing(): void
    {
        self::seedPasswordIdentity();

        $session = $this->signInWithPassword()->record;

        self::assertSame(FailureReason::PASSWORD_ALREADY_SET, Auth::passwords('web')->establish($session, self::NEW_PASSWORD)->reason);

        DB::table('password_identities')->update(['password' => '']);

        self::assertSame([PasswordViolation::TOO_SHORT], Auth::passwords('web')->establish($session, 'short')->violations);

        $this->beforeTheIdentityIsLocked(static fn () => DB::table('password_identities')->update(['password' => 'written meanwhile']));

        self::assertSame(FailureReason::PASSWORD_ALREADY_SET, Auth::passwords('web')->establish($session, self::NEW_PASSWORD)->reason);
        self::assertSame('written meanwhile', DB::table('password_identities')->value('password'));

        DB::table('password_identities')->update(['password' => null]);

        $write = static fn (string $sql): bool => str_starts_with($sql, 'update "password_identities"');

        $this->onceBefore($write, static fn () => DB::table('password_identities')->update(['password' => 'raced']));

        self::assertSame(FailureReason::PASSWORD_ALREADY_SET, Auth::passwords('web')->establish($session, self::NEW_PASSWORD)->reason);
        self::assertNull(DB::table('password_identities')->value('password'));
        self::assertSame(0, DB::table('authentication_sessions')->whereNotNull('revoked_at')->count());
    }

    /**
     * A change inside a transaction its caller rolls back changes nothing,
     * revokes nothing and reports nothing; the same change then succeeds.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACallersRollbackUndoesTheChange(): void
    {
        $identity = self::seedPasswordIdentity();
        $session  = $this->signInWithPassword()->record;

        $this->signInWithPassword();
        $this->recordEvents([PasswordSet::class, SessionRevoked::class]);

        DB::beginTransaction();

        self::assertTrue(Auth::passwords('web')->change($session, self::PASSWORD, self::NEW_PASSWORD)->isSet());

        DB::rollBack();

        self::assertSame([], $this->recorded);
        self::assertTrue(app(Hasher::class)->check(self::PASSWORD, (string) $identity->fresh()?->password));
        self::assertSame(0, DB::table('authentication_sessions')->whereNotNull('revoked_at')->count());
        self::assertSame(1, Auth::passwords('web')->change($session, self::PASSWORD, self::NEW_PASSWORD)->revoked);
    }

    /**
     * `set()` refuses the establishment flow: an establishment needs a recent
     * authentication, which only `establish()` checks.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testSetRefusesAnEstablishment(): void
    {
        $identity = self::seedPasswordIdentity(attributes: ['password' => null]);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('A first password is established with establish(), which needs a recent authentication on the session.');

        Auth::passwords('web')->set($identity, self::NEW_PASSWORD, PasswordFlow::ESTABLISHMENT);
    }

    /**
     * The current and new passwords are sensitive parameters.
     *
     * @return void
     */
    public function testThePasswordsAreSensitive(): void
    {
        foreach ([['change', 'current'], ['change', 'password'], ['establish', 'password']] as [$method, $parameter]) {
            self::assertNotSame([], (new \ReflectionParameter([PasswordService::class, $method], $parameter))->getAttributes(\SensitiveParameter::class));
            self::assertNotSame([], (new \ReflectionParameter([PasswordChanges::class, $method], $parameter))->getAttributes(\SensitiveParameter::class));
        }
    }

    /**
     * Configure the guards.
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

        self::configurePasswordGuards($app->make(ConfigRepository::class));
    }

    /**
     * Start an active session for the identity through the guard, as a sign-in
     * by another method would, with its first factor proved now.
     *
     * @param  \Tests\Integration\Fixtures\PasswordIdentity  $identity
     * @param  string  $guard
     * @return \SineMacula\Laravel\Authentication\Models\Session
     *
     * @throws \Throwable
     */
    private function started(PasswordIdentity $identity, string $guard = 'web'): Session
    {
        $record = $this->sessions($guard)->start($identity, null, 'password')->session?->record;

        self::assertInstanceOf(Session::class, $record);

        return $record;
    }

    /**
     * Run the change once, right before the next statement that locks the
     * identity's row.
     *
     * @param  \Closure(): mixed  $change
     * @return void
     */
    private function beforeTheIdentityIsLocked(\Closure $change): void
    {
        $lock = static fn (string $sql): bool => str_starts_with($sql, 'select') && str_contains($sql, 'password_identities') && str_contains($sql, 'limit 1');

        $this->onceBefore($lock, $change, true);
    }

    /**
     * Run the change once, right before the first statement the predicate
     * matches, inside the transaction that runs it.
     *
     * @param  \Closure(string): bool  $matches
     * @param  \Closure(): mixed  $change
     * @param  bool  $inTransaction
     * @return void
     */
    private function onceBefore(\Closure $matches, \Closure $change, bool $inTransaction = false): void
    {
        $done = false;

        DB::beforeExecuting(static function (string $sql) use ($matches, $change, $inTransaction, &$done): void {
            if ($done || !$matches(strtolower($sql)) || ($inTransaction && DB::transactionLevel() === 0)) {
                return;
            }

            $done = true;

            $change();
        });
    }

    /**
     * Update the session's row, and keep its guard.
     *
     * @param  \SineMacula\Laravel\Authentication\Models\Session  $session
     * @param  array<string, mixed>  $values
     * @return null
     */
    private static function update(Session $session, array $values): null
    {
        DB::table('authentication_sessions')->where('id', $session->getKey())->update($values);

        return null;
    }

    /**
     * Delete the session's row, and keep its guard.
     *
     * @param  \SineMacula\Laravel\Authentication\Models\Session  $session
     * @return null
     */
    private static function remove(Session $session): null
    {
        DB::table('authentication_sessions')->where('id', $session->getKey())->delete();

        return null;
    }
}
