<?php

declare(strict_types = 1);

namespace Tests\Feature\IdentifierChanges;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Timebox;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Session as Contract;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\Enums\AuthenticationFlow;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Freshness\ConfiguredFreshness;
use SineMacula\Laravel\Authentication\IdentifierChanges\ChangeRequests;
use SineMacula\Laravel\Authentication\IdentifierChanges\Enums\IdentifierChangeRequestStatus;
use SineMacula\Laravel\Authentication\IdentifierChanges\IdentifierChangeService;
use SineMacula\Laravel\Authentication\Models\Session;
use SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind;
use SineMacula\Laravel\Authentication\Proofs\Evaluation;
use SineMacula\Laravel\Authentication\RateLimiting\AccountAttempts;
use SineMacula\Laravel\Authentication\Runtime\GuardContext;
use SineMacula\Laravel\Authentication\Sessions\Reauthentication;
use SineMacula\Laravel\Authentication\Sessions\RecentAuthentication;
use Tests\Concerns\ChangesIdentifiers;
use Tests\Concerns\InspectsTraces;
use Tests\Concerns\InteractsWithProofs;
use Tests\Concerns\InteractsWithRateLimits;
use Tests\Concerns\MarksSharedLocks;
use Tests\Integration\Fixtures\ChangeableIdentity;
use Tests\TestCase;

/**
 * Feature tests for the recent authentication a change of identifier asks for.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RecentAuthentication::class)]
#[CoversClass(Reauthentication::class)]
#[CoversClass(ChangeRequests::class)]
#[CoversClass(IdentifierChangeService::class)]
#[CoversClass(ConfiguredFreshness::class)]
final class RecentAuthenticationTest extends TestCase
{
    use ChangesIdentifiers, InspectsTraces, InteractsWithProofs, InteractsWithRateLimits, MarksSharedLocks;

    /**
     * Freeze the clock and bind the fakes.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->startChanging();

        Route::get('/email/confirm', static fn (): string => 'ok')->name('email.confirm');
    }

    /**
     * Drop the table and release the clock.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $this->stopChanging();

        parent::tearDown();
    }

    /**
     * Rows of `[seconds before now the proof names, whether it is fresh]` under
     * the default 900-second freshness.
     *
     * @return iterable<string, array{0: int, 1: bool}>
     */
    public static function provideTimes(): iterable
    {
        yield from [
            'now'             => [0, true],
            'the age\'s last' => [899, true],
            'the age\'s end'  => [900, false],
            'long ago'        => [86400, false],
            'a second ahead'  => [-1, false],
        ];
    }

    /**
     * A session is fresh when its stored first factor is within the maximum
     * age.
     *
     * @param  int  $ago
     * @param  bool  $fresh
     * @return void
     */
    #[DataProvider('provideTimes')]
    public function testASessionIsFreshWhenItsFirstFactorIsWithinTheAge(int $ago, bool $fresh): void
    {
        $identity = self::seedChangeable();
        $record   = self::seedSession($identity, 'web', $this->now->subSeconds($ago));

        self::assertSame($fresh ? null : FailureReason::REAUTHENTICATION_REQUIRED, $this->check()->refusal($identity, Reauthentication::session($record), null));
    }

    /**
     * A reauthentication or step-up within the age makes a long-lived session
     * fresh.
     *
     * @return void
     */
    public function testALaterProofMakesALongLivedSessionFresh(): void
    {
        $identity = self::seedChangeable();
        $stale    = self::seedSession($identity, 'web', $this->now->subDays(10));
        $stepped  = self::seedSession($identity, 'web', $this->now->subDays(10));

        self::assertSame(FailureReason::REAUTHENTICATION_REQUIRED, $this->check()->refusal($identity, Reauthentication::session($stale), null));

        self::recordProof($stale, ProofKind::FIRST_FACTOR_REAUTHENTICATION, $this->now->subMinutes(5), ['pwd']);
        self::recordProof($stepped, ProofKind::ADDITIONAL_FACTOR, $this->now->subMinutes(5), ['otp'], new Evaluation(true, true));

        self::assertNull($this->check()->refusal($identity, Reauthentication::session($stale), null));
        self::assertNull($this->check()->refusal($identity, Reauthentication::session($stepped), null));
    }

    /**
     * The freshness configured for the guard applies.
     *
     * @return void
     */
    public function testTheConfiguredFreshnessApplies(): void
    {
        $identity = self::seedChangeable();
        $recent   = Reauthentication::session(self::seedSession($identity, 'web', $this->now->subSeconds(59)));
        $older    = Reauthentication::session(self::seedSession($identity, 'web', $this->now->subSeconds(60)));

        config()->set('authentication.freshness.identifier_change.max_age_seconds', 60);

        self::assertNull($this->check()->refusal($identity, $recent, null));
        self::assertSame(FailureReason::REAUTHENTICATION_REQUIRED, $this->check()->refusal($identity, $older, null));

        config()->set('authentication.freshness.identifier_change.proofs', ['additional_factor']);

        self::assertSame(FailureReason::REAUTHENTICATION_REQUIRED, $this->check()->refusal($identity, $recent, null));

        config()->set('auth.guards.web.freshness', ['identifier_change' => ['max_age_seconds' => 120, 'proofs' => ['first_factor']]]);

        self::assertNull($this->check()->refusal($identity, $older, null));

        config()->set('auth.guards.web.freshness', ['identifier_change' => null]);

        self::assertSame(FailureReason::REAUTHENTICATION_REQUIRED, $this->check()->refusal($identity, $recent, null));
    }

    /**
     * An accepted proof stands under the lock while its rows are as they were
     * read.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnAcceptedProofStandsWhileItsRowsAreAsTheyWere(): void
    {
        $identity = self::seedChangeable();
        $record   = self::seedSession($identity);
        $check    = $this->check();
        $before   = ChangeableIdentity::query()->sole();
        $password = Reauthentication::password(self::PASSWORD);

        self::assertTrue(self::standsInTransaction($check, $before, ChangeableIdentity::query()->sole(), Reauthentication::session($record)));
        self::assertTrue(self::standsInTransaction($check, $before, ChangeableIdentity::query()->sole(), $password));

        DB::table('authentication_sessions')->update(['revoked_at' => '2026-04-06 11:59:00']);
        DB::table('changeable_identities')->update(['password' => app(Hasher::class)->make(self::PASSWORD)]);

        self::assertFalse(self::standsInTransaction($check, $before, ChangeableIdentity::query()->sole(), Reauthentication::session($record)));
        self::assertFalse(self::standsInTransaction($check, $before, ChangeableIdentity::query()->sole(), $password));

        DB::table('changeable_identities')->update(['password' => null]);

        $none = ChangeableIdentity::query()->sole();

        self::assertTrue(self::standsInTransaction($check, $none, ChangeableIdentity::query()->sole(), $password));
        self::assertFalse(self::standsInTransaction($check, $none, $before, $password));
        self::assertSame(0, DB::table('rate_limits')->count());
    }

    /**
     * Only the check under the lock reads the session's proofs current.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testOnlyTheCheckUnderTheLockReadsTheSessionsProofsCurrent(): void
    {
        $identity = self::seedChangeable();
        $proof    = Reauthentication::session(self::seedSession($identity));
        $check    = $this->check();

        self::markSharedLocks();

        $refusal = null;
        $stands  = null;
        $before  = self::statementsDuring(static function () use ($check, $identity, $proof, &$refusal): void {
            $refusal = $check->refusal($identity, $proof, null);
        });
        $under = self::statementsDuring(static function () use ($check, $identity, $proof, &$stands): void {
            $stands = self::standsInTransaction($check, $identity, $identity, $proof);
        });
        $sessionReads = array_values(array_filter($under, static fn (string $sql): bool => str_contains($sql, 'authentication_sessions')));

        self::assertSame([null, true], [$refusal, $stands]);
        self::assertSame([], array_filter($before, static fn (string $sql): bool => self::locksForUpdate($sql) || self::sharesLock($sql)));
        self::assertSame([false], array_map(self::sharesLock(...), array_values(array_filter($before, self::readsProofs(...)))));
        self::assertSame([true, true], array_map(self::locksForUpdate(...), $sessionReads));
        self::assertSame([self::takesSharedLocks()], array_map(self::sharesLock(...), array_values(array_filter($under, self::readsProofs(...)))));
    }

    /**
     * A session that is not a live session of the identity proves nothing.
     *
     * @return void
     */
    public function testASessionThatIsNotALiveSessionOfTheIdentityProvesNothing(): void
    {
        $identity = self::seedChangeable();
        $other    = self::seedChangeable('other@example.test');
        $check    = $this->check();
        $refused  = FailureReason::REAUTHENTICATION_REQUIRED;

        self::assertSame($refused, $check->refusal($identity, Reauthentication::session(self::seedSession($other)), null));
        self::assertSame($refused, $check->refusal($identity, Reauthentication::session(self::seedSession($identity, 'admin')), null));

        $revoked = self::seedSession($identity);

        DB::table('authentication_sessions')->where('id', $revoked->getKey())->update(['revoked_at' => '2026-04-06 11:59:00']);

        self::assertSame($refused, $check->refusal($identity, Reauthentication::session($revoked), null));

        $ended = self::seedSession($identity);

        DB::table('authentication_sessions')->where('id', $ended->getKey())->update(['idle_expires_at' => '2026-04-06 12:00:00']);

        self::assertSame($refused, $check->refusal($identity, Reauthentication::session($ended), null));

        $stale = self::seedSession($identity);

        DB::table('authentication_proofs')->where('session_id', $stale->getKey())->update(['authenticated_at' => '2026-04-06 11:00:00']);

        self::assertSame($refused, $check->refusal($identity, Reauthentication::session($stale), null));

        $voided = self::seedSession($identity);

        DB::table('authentication_proofs')->where('session_id', $voided->getKey())->update(['voided_at' => '2026-04-06 12:00:00']);

        self::assertSame($refused, $check->refusal($identity, Reauthentication::session($voided), null));

        $gone = self::seedSession($identity);

        $gone->delete();

        self::assertSame($refused, $check->refusal($identity, Reauthentication::session($gone), null));
        self::assertSame($refused, $check->refusal($identity, Reauthentication::session(new Session), null));
    }

    /**
     * A retained session is not proved by its replacement.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARetainedSessionIsNotProvedByItsReplacement(): void
    {
        $identity = self::seedChangeable();
        $retained = self::seedSession($identity);
        $row      = (array) DB::table('authentication_sessions')->where('id', $retained->getKey())->first();
        $check    = $this->check();

        $retained->delete();

        $replacement = new Session;
        $replacement->forceFill(array_diff_key($row, array_flip(['generation', 'created_at', 'updated_at'])))->save();

        $locked = ChangeableIdentity::query()->sole();

        self::assertNull($check->refusal($identity, Reauthentication::session($replacement), null));
        self::assertTrue(self::standsInTransaction($check, $locked, $locked, Reauthentication::session($replacement)));
        self::assertSame(FailureReason::REAUTHENTICATION_REQUIRED, $check->refusal($identity, Reauthentication::session($retained), null));
        self::assertFalse(self::standsInTransaction($check, $locked, $locked, Reauthentication::session($retained)));

        foreach ([Contract::class, EloquentSession::class] as $contract) {
            $session = \Mockery::mock($contract);

            self::assertInstanceOf(Contract::class, $session);

            $session->shouldReceive('getSessionIdentifier')->andReturn($replacement->getKey());

            self::assertSame(FailureReason::REAUTHENTICATION_REQUIRED, $check->refusal($identity, Reauthentication::session($session), null), $contract);
            self::assertFalse(self::standsInTransaction($check, $locked, $locked, Reauthentication::session($session)), $contract);
        }
    }

    /**
     * A refresh records no proof, while signing in again does.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARefreshDoesNotRenewTheSignIn(): void
    {
        $identity = self::seedChangeable();
        $session  = $this->sessions('web')->signIn('password', self::credentials(self::EMAIL), self::requestContext())->session;

        self::assertNotNull($session);

        $this->moveTo($this->now->addSeconds(1000));

        self::assertNotNull(
            self::sessionsOf($this->freshGuard('web'))->refresh(self::bodyToken($session->tokens), self::requestClient())->session,
        );

        $refreshed = Session::query()->findOrFail(self::modelKey($session->record));
        $check     = $this->check();

        self::assertSame(FailureReason::REAUTHENTICATION_REQUIRED, $check->refusal($identity, Reauthentication::session($refreshed), null));

        $again = $this->sessions('web')->signIn('password', self::credentials(self::EMAIL), self::requestContext())->session;

        self::assertNotNull($again);
        self::assertNull($check->refusal($identity, Reauthentication::session($again->record), null));
    }

    /**
     * The current password proves the identity and gives back its sign-in
     * slots.
     *
     * @return void
     */
    public function testThePasswordIsCheckedAndCounted(): void
    {
        $identity = self::seedChangeable();
        $check    = $this->check();
        $account  = AccountAttempts::account($identity);

        self::assertNull($check->refusal($identity, Reauthentication::password(self::PASSWORD), self::CLIENT_IP));
        self::assertSame([0, 0], [self::counterHits('sign_in', 'per_account', $account), self::counterHits('web', 'sign_in', 'per_ip', self::CLIENT_IP)]);
        self::assertSame(FailureReason::REAUTHENTICATION_REQUIRED, $check->refusal($identity, Reauthentication::password('wrong'), self::CLIENT_IP));
        self::assertSame([1, 1], [self::counterHits('sign_in', 'per_account', $account), self::counterHits('web', 'sign_in', 'per_ip', self::CLIENT_IP)]);
    }

    /**
     * A guard that does not allow passwords takes none as proof.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAGuardWithoutPasswordsTakesNoPassword(): void
    {
        config()->set('auth.guards.web.application', ['methods' => ['email_code']]);

        $identity = self::seedChangeable();
        $check    = $this->check();

        self::assertSame(FailureReason::REAUTHENTICATION_REQUIRED, $check->refusal($identity, Reauthentication::password(self::PASSWORD), self::CLIENT_IP));
        self::assertSame(0, DB::table('rate_limits')->count());

        $this->recordEvents([AuthenticationFailed::class]);

        $request = $this->changes()->requestByCode($identity, 'email', self::NEW_EMAIL, Reauthentication::password(self::PASSWORD), self::requestClient());

        self::assertSame(IdentifierChangeRequestStatus::REAUTHENTICATION_REQUIRED, $request->status);
        self::assertSame([AuthenticationFlow::IDENTIFIER_CHANGE, FailureReason::REAUTHENTICATION_REQUIRED], [$this->failures()[0]->flow, $this->failures()[0]->reason]);
    }

    /**
     * A password is taken only when the freshness takes a reauthentication
     * without MFA or phishing resistance.
     *
     * @return void
     */
    public function testAPasswordIsTakenOnlyWhenTheFreshnessTakesAReauthentication(): void
    {
        $identity = self::seedChangeable();

        foreach ([['first_factor', 'additional_factor'], ['first_factor_reauthentication']] as $index => $proofs) {

            config()->set('authentication.freshness.identifier_change', ['max_age_seconds' => 900, 'proofs' => $proofs]);

            $refusal = $this->check()->refusal($identity, Reauthentication::password(self::PASSWORD), self::CLIENT_IP);

            self::assertSame($index === 0 ? FailureReason::REAUTHENTICATION_REQUIRED : null, $refusal);
        }

        foreach (['multifactor', 'phishing_resistant'] as $flag) {

            config()->set('authentication.freshness.identifier_change', ['max_age_seconds' => 900, 'proofs' => ['first_factor_reauthentication'], $flag => true]);

            self::assertSame(FailureReason::REAUTHENTICATION_REQUIRED, $this->check()->refusal($identity, Reauthentication::password(self::PASSWORD), self::CLIENT_IP));
        }

        config()->set('authentication.freshness.identifier_change', null);

        self::assertSame(FailureReason::REAUTHENTICATION_REQUIRED, $this->check()->refusal($identity, Reauthentication::password(self::PASSWORD), self::CLIENT_IP));
        self::assertSame(0, self::counterHits('sign_in', 'per_account', AccountAttempts::account($identity)));
    }

    /**
     * A wrong password takes the guard's whole credential timebox.
     *
     * @return void
     */
    public function testAWrongPasswordTakesTheWholeTimebox(): void
    {
        config()->set('authentication.timebox.credentials_microseconds', 400000);

        $identity = self::seedChangeable();
        $check    = $this->check();
        $timed    = static function (\Closure $callback): float {
            $started = microtime(true);

            $callback();

            return microtime(true) - $started;
        };

        self::assertGreaterThanOrEqual(0.4, $timed(static fn (): mixed => $check->refusal($identity, Reauthentication::password('wrong'), null)));
        self::assertLessThan(0.3, $timed(static fn (): mixed => $check->refusal($identity, Reauthentication::password(self::PASSWORD), null)));
    }

    /**
     * A failed password check leaves the password and new identifier out of the
     * trace.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFailedPasswordCheckLeavesTheSecretsOutOfTheTrace(): void
    {
        $identity = self::seedChangeable();
        $proof    = Reauthentication::password(self::PASSWORD);

        DB::listen(static function (QueryExecuted $query): void {
            if (str_starts_with($query->sql, 'update') && str_contains($query->sql, 'rate_limits')) {
                throw new \RuntimeException('the limiter failed');
            }
        });

        $exception = self::withArgumentsInTraces(
            \RuntimeException::class,
            fn (): mixed => $this->changes()->requestByCode($identity, 'email', self::NEW_EMAIL, $proof, self::requestClient()),
        );

        self::assertSame('the limiter failed', $exception->getMessage());
        self::assertContains(Timebox::class, array_column($exception->getTrace(), 'class'));
        self::assertFalse(self::hasInTrace($exception, self::PASSWORD));
        self::assertFalse(self::hasInTrace($exception, self::NEW_EMAIL));
    }

    /**
     * The password is checked against the identity as stored.
     *
     * @return void
     */
    public function testThePasswordIsCheckedAgainstTheStoredIdentity(): void
    {
        $identity = self::seedChangeable();
        $check    = $this->check();

        DB::table('changeable_identities')->update(['password' => app('hash')->make('a newer password')]);

        self::assertSame(FailureReason::REAUTHENTICATION_REQUIRED, $check->refusal($identity, Reauthentication::password(self::PASSWORD), null));

        DB::table('changeable_identities')->delete();

        self::assertSame(FailureReason::REAUTHENTICATION_REQUIRED, $check->refusal($identity, Reauthentication::password('a newer password'), null));
    }

    /**
     * A password checked too often is rate limited with the seconds to wait.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPasswordCheckedTooOftenIsRateLimited(): void
    {
        $identity = self::seedChangeable();
        $check    = $this->check();

        foreach (range(1, 5) as $attempt) {
            $check->refusal($identity, Reauthentication::password("wrong {$attempt}"), null);
        }

        self::assertSame(300, $check->refusal($identity, Reauthentication::password(self::PASSWORD), null));

        $this->recordEvents([AuthenticationFailed::class]);

        $request = $this->changes()->requestByLink($identity, 'email', self::NEW_EMAIL, Reauthentication::password(self::PASSWORD), 'email.confirm', self::requestClient());

        self::assertSame([IdentifierChangeRequestStatus::RATE_LIMITED, 300], [$request->status, $request->retryAfter]);
        $failure = $this->failures()[0];

        self::assertSame([AuthenticationFlow::IDENTIFIER_CHANGE, FailureReason::RATE_LIMITED, 300], [$failure->flow, $failure->reason, $failure->retryAfter]);
    }

    /**
     * A request without a recent authentication is refused before anything is
     * counted or written.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARequestWithoutARecentAuthenticationIsRefused(): void
    {
        $identity = self::seedChangeable();

        $this->recordEvents([AuthenticationFailed::class]);

        $request = $this->changes()->requestByCode(
            $identity,
            'email',
            self::NEW_EMAIL,
            Reauthentication::session(self::seedSession($identity, 'web', $this->now->subHour())),
            self::requestClient(),
        );

        self::assertSame(IdentifierChangeRequestStatus::REAUTHENTICATION_REQUIRED, $request->status);
        $failure = $this->failures()[0];

        self::assertSame([AuthenticationFlow::IDENTIFIER_CHANGE, FailureReason::REAUTHENTICATION_REQUIRED], [$failure->flow, $failure->reason]);
        self::assertSame(self::NEW_EMAIL, $failure->identifier);
        self::assertSame([0, 0, 0], [self::rows('rate_limits'), self::rows('identifier_changes'), self::rows('one_time_codes')]);
    }

    /**
     * Register the guards the tests change identifiers through.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        assert($app instanceof Application);

        self::configureChangeGuards($app->make(ConfigRepository::class));
    }

    /**
     * The check of the `web` guard.
     *
     * @return \SineMacula\Laravel\Authentication\Sessions\RecentAuthentication
     */
    private function check(): RecentAuthentication
    {
        self::assertNotNull($this->app);

        return new RecentAuthentication($this->guardContext(), $this->app);
    }

    /**
     * Whether the proof stands, asked inside a transaction as a change asks it.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\RecentAuthentication  $check
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $before
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $locked
     * @param  \SineMacula\Laravel\Authentication\Sessions\Reauthentication  $proof
     * @return bool
     *
     * @throws \Throwable
     */
    private static function standsInTransaction(RecentAuthentication $check, Identity $before, Identity $locked, Reauthentication $proof): bool
    {
        return DB::transaction(static fn (): bool => $check->stands($before, $locked, $proof));
    }

    /**
     * The context of the `web` guard, resolved afresh for a request from the
     * test client.
     *
     * @return \SineMacula\Laravel\Authentication\Runtime\GuardContext
     */
    private function guardContext(): GuardContext
    {
        return $this->freshGuard('web')->context();
    }
}
