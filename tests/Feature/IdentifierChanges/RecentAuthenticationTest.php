<?php

declare(strict_types = 1);

namespace Tests\Feature\IdentifierChanges;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Timebox;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\Enums\AuthenticationFlow;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\IdentifierChanges\ChangeRequests;
use SineMacula\Laravel\Authentication\IdentifierChanges\Enums\IdentifierChangeRequestStatus;
use SineMacula\Laravel\Authentication\IdentifierChanges\IdentifierChangeService;
use SineMacula\Laravel\Authentication\Models\Device;
use SineMacula\Laravel\Authentication\RateLimiting\AccountAttempts;
use SineMacula\Laravel\Authentication\Runtime\GuardContext;
use SineMacula\Laravel\Authentication\Sessions\Reauthentication;
use SineMacula\Laravel\Authentication\Sessions\RecentAuthentication;
use Tests\Concerns\ChangesIdentifiers;
use Tests\Concerns\InspectsTraces;
use Tests\Concerns\InteractsWithRateLimits;
use Tests\Integration\Fixtures\ChangeableIdentity;
use Tests\TestCase;

/**
 * Feature tests for the recent authentication a change of identifier asks for:
 * when a device, a password or a confirmation time proves it, within the window
 * and from its first second to its last, and what a refusal reports and counts.
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
final class RecentAuthenticationTest extends TestCase
{
    use ChangesIdentifiers, InspectsTraces, InteractsWithRateLimits;

    /**
     * Start every test from a known moment, with the fakes bound.
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
     * Rows of `[seconds before now the proof names, whether it is recent]` with
     * the default 900-second window: from now back to 899 seconds ago, and not
     * from 900 seconds ago or the future.
     *
     * @return iterable<string, array{0: int, 1: bool}>
     */
    public static function provideTimes(): iterable
    {
        yield from [
            'now'                => [0, true],
            'the window\'s last' => [899, true],
            'the window\'s end'  => [900, false],
            'long ago'           => [86400, false],
            'a second ahead'     => [-1, false],
        ];
    }

    /**
     * A confirmation time is recent within the window and not in the future.
     *
     * @param  int  $ago
     * @param  bool  $recent
     * @return void
     */
    #[DataProvider('provideTimes')]
    public function testAConfirmationTimeIsRecentWithinTheWindow(int $ago, bool $recent): void
    {
        $identity = self::seedChangeable();

        $refusal = $this->check()->refusal($identity, Reauthentication::confirmedAt($this->now->subSeconds($ago)), null);

        self::assertSame($recent ? null : FailureReason::REAUTHENTICATION_REQUIRED, $refusal);
    }

    /**
     * A device is recent when, as stored, it signed in within the window.
     *
     * @param  int  $ago
     * @param  bool  $recent
     * @return void
     */
    #[DataProvider('provideTimes')]
    public function testADeviceIsRecentWhenItSignedInWithinTheWindow(int $ago, bool $recent): void
    {
        $identity = self::seedChangeable();
        $device   = self::seedDevice($identity, 'web', $this->now->subSeconds($ago));

        self::assertSame($recent ? null : FailureReason::REAUTHENTICATION_REQUIRED, $this->check()->refusal($identity, Reauthentication::device($device), null));
    }

    /**
     * A confirmation time later in the same second is now: times are compared
     * to the second.
     *
     * @return void
     */
    public function testAConfirmationLaterInTheSecondIsRecent(): void
    {
        $identity = self::seedChangeable();

        self::assertNull($this->check()->refusal($identity, Reauthentication::confirmedAt($this->now->addMicroseconds(999999)), null));
    }

    /**
     * The window is the one configured.
     *
     * @return void
     */
    public function testTheConfiguredWindowApplies(): void
    {
        $identity = self::seedChangeable();
        $check    = new RecentAuthentication($this->guardContext(), $this->app, 60, $this->now);

        self::assertNull($check->refusal($identity, Reauthentication::confirmedAt($this->now->subSeconds(59)), null));
        self::assertSame(FailureReason::REAUTHENTICATION_REQUIRED, $check->refusal($identity, Reauthentication::confirmedAt($this->now->subSeconds(60)), null));
    }

    /**
     * A proof accepted before the transaction stands under the lock as the rows
     * read then: a device while it is still a live session (read with its row
     * locked), a password while the locked row holds the hash read before it
     * was checked, and a confirmation time always; nothing is counted.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnAcceptedProofStandsWhileItsRowsAreAsTheyWere(): void
    {
        $identity = self::seedChangeable();
        $device   = self::seedDevice($identity);
        $check    = $this->check();
        $before   = ChangeableIdentity::query()->sole();
        $password = Reauthentication::password(self::PASSWORD);

        self::assertTrue($check->stands($before, ChangeableIdentity::query()->sole(), Reauthentication::device($device)));
        self::assertTrue($check->stands($before, ChangeableIdentity::query()->sole(), $password));
        self::assertTrue($check->stands($before, ChangeableIdentity::query()->sole(), Reauthentication::confirmedAt($this->now->subYear())));

        DB::table('devices')->update(['revoked_at' => '2026-04-06 11:59:00']);
        DB::table('changeable_identities')->update(['password' => app(Hasher::class)->make(self::PASSWORD)]);

        self::assertFalse($check->stands($before, ChangeableIdentity::query()->sole(), Reauthentication::device($device)));
        self::assertFalse($check->stands($before, ChangeableIdentity::query()->sole(), $password));

        DB::table('changeable_identities')->update(['password' => null]);

        $none = ChangeableIdentity::query()->sole();

        self::assertTrue($check->stands($none, ChangeableIdentity::query()->sole(), $password));
        self::assertFalse($check->stands($none, $before, $password));
        self::assertSame(0, DB::table('rate_limits')->count());
    }

    /**
     * A device proves nothing when, as stored, it is another identity's, of
     * another guard, revoked, past its deadlines or gone, whatever the instance
     * given says.
     *
     * @return void
     */
    public function testADeviceThatIsNotALiveSessionOfTheIdentityProvesNothing(): void
    {
        $identity = self::seedChangeable();
        $other    = self::seedChangeable('other@example.test');
        $check    = $this->check();
        $refused  = FailureReason::REAUTHENTICATION_REQUIRED;

        self::assertSame($refused, $check->refusal($identity, Reauthentication::device(self::seedDevice($other)), null));
        self::assertSame($refused, $check->refusal($identity, Reauthentication::device(self::seedDevice($identity, 'admin')), null));

        $revoked = self::seedDevice($identity);

        DB::table('devices')->where('id', $revoked->getKey())->update(['revoked_at' => '2026-04-06 11:59:00']);

        self::assertSame($refused, $check->refusal($identity, Reauthentication::device($revoked), null));

        $ended = self::seedDevice($identity);

        DB::table('devices')->where('id', $ended->getKey())->update(['idle_expires_at' => '2026-04-06 12:00:00']);

        self::assertSame($refused, $check->refusal($identity, Reauthentication::device($ended), null));

        $stale = self::seedDevice($identity);

        DB::table('devices')->where('id', $stale->getKey())->update(['signed_in_at' => '2026-04-06 11:00:00']);

        self::assertSame($refused, $check->refusal($identity, Reauthentication::device($stale), null));

        $gone = self::seedDevice($identity);

        $gone->delete();

        self::assertSame($refused, $check->refusal($identity, Reauthentication::device($gone), null));
        self::assertSame($refused, $check->refusal($identity, Reauthentication::device(new Device), null));
    }

    /**
     * A refresh does not renew a session's sign-in, so a device signed in long
     * ago proves nothing however recently it refreshed; signing in again on the
     * same client does.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARefreshDoesNotRenewTheSignIn(): void
    {
        $identity = self::seedChangeable();
        $session  = $this->sessions('web')->signIn('password', self::credentials(self::EMAIL))->session;

        self::assertNotNull($session);

        $this->moveTo($this->now->addSeconds(1000));

        self::assertNotNull(self::sessionsOf($this->freshGuard('web'))->refresh($session->tokens->refreshToken)->session);

        $refreshed = Device::query()->findOrFail($session->device->getKey());
        $check     = new RecentAuthentication($this->guardContext(), $this->app, 900, CarbonImmutable::now());

        self::assertSame(FailureReason::REAUTHENTICATION_REQUIRED, $check->refusal($identity, Reauthentication::device($refreshed), null));

        $again = $this->sessions('web')->signIn('password', self::credentials(self::EMAIL))->session;

        self::assertNotNull($again);
        self::assertNull($check->refusal($identity, Reauthentication::device($again->device), null));
    }

    /**
     * The identity's current password proves it, and gives back the sign-in
     * slots it took; a wrong one does not, and keeps them.
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
     * A guard whose audience does not allow the password method, one that signs
     * in only by code, takes no password as proof, even the right one: nothing
     * is counted, and a request is refused as needing reauthentication.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAGuardWithoutPasswordsTakesNoPassword(): void
    {
        config()->set('auth.guards.web.audience', ['methods' => ['email_code']]);

        $identity = self::seedChangeable();
        $check    = $this->check();

        self::assertSame(FailureReason::REAUTHENTICATION_REQUIRED, $check->refusal($identity, Reauthentication::password(self::PASSWORD), self::CLIENT_IP));
        self::assertSame(0, DB::table('rate_limits')->count());

        $this->recordEvents([AuthenticationFailed::class]);

        $request = $this->changes()->requestByCode($identity, 'email', self::NEW_EMAIL, Reauthentication::password(self::PASSWORD));

        self::assertSame(IdentifierChangeRequestStatus::REAUTHENTICATION_REQUIRED, $request->status);
        self::assertSame([AuthenticationFlow::IDENTIFIER_CHANGE, FailureReason::REAUTHENTICATION_REQUIRED], [$this->failures()[0]->flow, $this->failures()[0]->reason]);
    }

    /**
     * A password check takes the guard's whole credential timebox when the
     * password is wrong, and ends as soon as it is known to be right.
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
     * A failure while the password is checked, inside the credential timebox
     * and the request's transaction, leaves the password and the new identifier
     * out of every frame of its trace, the closures' captures included, even
     * with arguments recorded in traces.
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

        $exception = self::withArgumentsInTraces(\RuntimeException::class, fn (): mixed => $this->changes()->requestByCode($identity, 'email', self::NEW_EMAIL, $proof));

        self::assertSame('the limiter failed', $exception->getMessage());
        self::assertContains(Timebox::class, array_column($exception->getTrace(), 'class'));
        self::assertFalse(self::hasInTrace($exception, self::PASSWORD));
        self::assertFalse(self::hasInTrace($exception, self::NEW_EMAIL));
    }

    /**
     * The password is checked against the identity as stored: one whose
     * password changed, or that is gone, does not take the old one.
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
     * Once the account has no sign-in attempts left, its password is not
     * checked: the seconds until it may be are given instead, and a request
     * answers rate limited with them.
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

        $request = $this->changes()->requestByLink($identity, 'email', self::NEW_EMAIL, Reauthentication::password(self::PASSWORD), 'email.confirm');

        self::assertSame([IdentifierChangeRequestStatus::RATE_LIMITED, 300], [$request->status, $request->retryAfter]);
        $failure = $this->failures()[0];

        self::assertSame([AuthenticationFlow::IDENTIFIER_CHANGE, FailureReason::RATE_LIMITED, 300], [$failure->flow, $failure->reason, $failure->retryAfter]);
    }

    /**
     * A request without a recent authentication is refused and reported as
     * such, with the identifier as given, before anything is counted or
     * written.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARequestWithoutARecentAuthenticationIsRefused(): void
    {
        $identity = self::seedChangeable();

        $this->recordEvents([AuthenticationFailed::class]);

        $request = $this->changes()->requestByCode($identity, 'email', self::NEW_EMAIL, Reauthentication::confirmedAt($this->now->subHour()));

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
     * The check of the `web` guard, with the default window, now.
     *
     * @return \SineMacula\Laravel\Authentication\Sessions\RecentAuthentication
     */
    private function check(): RecentAuthentication
    {
        return new RecentAuthentication($this->guardContext(), $this->app, 900, $this->now);
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
