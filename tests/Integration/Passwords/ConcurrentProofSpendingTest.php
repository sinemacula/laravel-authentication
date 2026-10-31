<?php

declare(strict_types = 1);

namespace Tests\Integration\Passwords;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Codes\CodeBinding;
use SineMacula\Laravel\Authentication\Codes\IssuedCode;
use SineMacula\Laravel\Authentication\Codes\OneTimeCodes;
use SineMacula\Laravel\Authentication\Database\IdentityLock;
use SineMacula\Laravel\Authentication\Devices\DeviceLookup;
use SineMacula\Laravel\Authentication\Events\Enums\RevocationReason;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\IdentifierChanges\ChangeRequests;
use SineMacula\Laravel\Authentication\IdentifierChanges\IdentifierChangeService;
use SineMacula\Laravel\Authentication\Passwords\Enums\PasswordFlow;
use SineMacula\Laravel\Authentication\Passwords\ResetSubmissions;
use SineMacula\Laravel\Authentication\Sessions\DeviceRevocations;
use SineMacula\Laravel\Authentication\Sessions\Reauthentication;
use SineMacula\Laravel\Authentication\Sessions\RecentAuthentication;
use Tests\Concerns\ChangesIdentifiers;
use Tests\Concerns\DefinesPasswordChangeRoute;
use Tests\Integration\Fixtures\ChangeableIdentity;
use Tests\TestCase;

/**
 * Races, on PostgreSQL and MySQL, a password write against the flows that spend
 * or take a proof bound to the same identity (an identifier change request and
 * confirmation, a password reset), a bulk revocation against a confirmation and
 * a request, and a cancellation and a replacing request against a confirmation,
 * each in a process with a database connection of its own. The first is held
 * open right after the statement that would make the two lock their rows in
 * opposite orders, or let one act on what the other is about to undo; the
 * second, started meanwhile, waits for it on the identity's row (see
 * `IdentityLock`) or the device's, so both answer a result, neither throws, and
 * the second sees what the first left.
 *
 * Skipped on SQLite, whose in-memory database each process would have to
 * itself, and where `pcntl` is not available.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(IdentityLock::class)]
#[CoversClass(IdentifierChangeService::class)]
#[CoversClass(ResetSubmissions::class)]
#[CoversClass(DeviceRevocations::class)]
#[CoversClass(ChangeRequests::class)]
#[CoversClass(RecentAuthentication::class)]
#[CoversClass(DeviceLookup::class)]
final class ConcurrentProofSpendingTest extends TestCase
{
    use ChangesIdentifiers, DefinesPasswordChangeRoute;

    /** @var int How long the first operation is held after its statement once the second has started, in microseconds. */
    private const int HOLD_MICROSECONDS = 1000000;

    /** @var float The least time, in seconds, the second operation must have waited to show it waited on the first. */
    private const float LEAST_WAIT_SECONDS = 0.5;

    /** @var int How long the second operation waits to be started before giving up, in seconds. */
    private const int START_TIMEOUT_SECONDS = 10;

    /** @var string The new password the racing writes set. */
    private const string NEW_PASSWORD = 'a brand new long passphrase';

    /** @var string Directory the second operation reports its outcome in. */
    private string $outcomes;

    /**
     * Skip where processes cannot share the database, and start from a known
     * moment with the fakes bound and the route links point at.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        if (DB::connection()->getDriverName() === 'sqlite' || !function_exists('pcntl_fork')) {
            self::markTestSkipped('Racing processes need a shared database server and pcntl.');
        }

        $this->startChanging();

        Route::get('/email/confirm', static fn (): string => 'ok')->name('email.confirm');

        $this->outcomes = sys_get_temp_dir() . '/proof-race-' . bin2hex(random_bytes(8));

        mkdir($this->outcomes);
    }

    /**
     * Remove the outcomes, drop the table and release the clock.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        foreach (glob(($this->outcomes ?? sys_get_temp_dir() . '/none') . '/*') ?: [] as $file) {
            unlink($file);
        }

        if (isset($this->outcomes) && is_dir($this->outcomes)) {
            rmdir($this->outcomes);

            $this->stopChanging();
        }

        parent::tearDown();
    }

    /**
     * A password change racing a confirmation held after it deleted the pending
     * change waits for it: the change is made, then the password set.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPasswordChangeWaitsForAConfirmation(): void
    {
        $identity = self::seedChangeable();
        $link     = $this->requestByLink($identity);

        [$first, $second] = $this->race(
            'delete from',
            'identifier_changes',
            fn (): string => $this->changes()->confirmByLink(Request::create($link))->value,
            static fn (): string => Auth::passwords('web')->set(self::reloaded($identity), self::NEW_PASSWORD, PasswordFlow::CHANGE)->isSet() ? 'set' : 'rejected',
        );

        self::assertSame(['changed', 'set'], [$first, $second['result']]);
        self::assertGreaterThanOrEqual(self::LEAST_WAIT_SECONDS, $second['waited']);
        self::assertSame(self::NEW_EMAIL, self::reloaded($identity)->email);
    }

    /**
     * A password change racing a confirmation held after it invalidated the old
     * address's live reset link waits for it as well.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPasswordChangeWaitsForAConfirmationThatOutdatedAResetLink(): void
    {
        $identity = self::seedChangeable();
        $link     = $this->requestByLink($identity);

        self::resetToken();

        [$first, $second] = $this->race(
            'delete from',
            'one_time_codes',
            fn (): string => $this->changes()->confirmByLink(Request::create($link))->value,
            static fn (): string => Auth::passwords('web')->set(self::reloaded($identity), self::NEW_PASSWORD, PasswordFlow::CHANGE)->isSet() ? 'set' : 'rejected',
        );

        self::assertSame(['changed', 'set'], [$first, $second['result']]);
        self::assertGreaterThanOrEqual(self::LEAST_WAIT_SECONDS, $second['waited']);
    }

    /**
     * A reset with the old address's link racing a confirmation waits for it,
     * then finds the link outdated by the change: `invalid`.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAResetWaitsForAConfirmationAndFindsItsLinkOutdated(): void
    {
        $identity = self::seedChangeable();
        $link     = $this->requestByLink($identity);
        $token    = self::resetToken();

        [$first, $second] = $this->race(
            'delete from',
            'identifier_changes',
            fn (): string => $this->changes()->confirmByLink(Request::create($link))->value,
            static fn (): string => Auth::passwords('web')->reset(['email' => self::EMAIL, 'token' => $token, 'password' => self::NEW_PASSWORD])->status->value,
        );

        self::assertSame(['changed', 'invalid'], [$first, $second['result']]);
        self::assertGreaterThanOrEqual(self::LEAST_WAIT_SECONDS, $second['waited']);
    }

    /**
     * A password change racing a reset held after it spent its token waits for
     * it: the reset sets its password, then the change sets its own.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPasswordChangeWaitsForAReset(): void
    {
        $identity = self::seedChangeable();
        $token    = self::resetToken();

        [$first, $second] = $this->race(
            'update',
            'one_time_codes',
            static fn (): string => Auth::passwords('web')->reset(['email' => self::EMAIL, 'token' => $token, 'password' => 'the reset passphrase'])->status->value,
            static fn (): string => Auth::passwords('web')->set(self::reloaded($identity), self::NEW_PASSWORD, PasswordFlow::CHANGE)->isSet() ? 'set' : 'rejected',
        );

        self::assertSame(['reset', 'set'], [$first, $second['result']]);
        self::assertGreaterThanOrEqual(self::LEAST_WAIT_SECONDS, $second['waited']);
        self::assertTrue(Auth::guard('web')->getProvider()->validateCredentials(self::reloaded($identity), ['password' => self::NEW_PASSWORD]));
    }

    /**
     * A confirmation racing a revocation of every device held after it
     * cancelled the pending change waits for it, then finds the change gone.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAConfirmationWaitsForABulkRevocationAndFindsTheChangeCancelled(): void
    {
        $identity = self::seedChangeable();
        $link     = $this->requestByLink($identity);

        self::seedDevice($identity);

        [$first, $second] = $this->race(
            'delete from',
            'identifier_changes',
            static fn (): string => (string) Auth::sessions('web')->revokeDevices(self::reloaded($identity), RevocationReason::REVOKED),
            fn (): string => $this->changes()->confirmByLink(Request::create($link))->value,
        );

        self::assertSame(['1', 'invalid'], [$first, $second['result']]);
        self::assertGreaterThanOrEqual(self::LEAST_WAIT_SECONDS, $second['waited']);
        self::assertSame(self::EMAIL, self::reloaded($identity)->email);
    }

    /**
     * A password change racing a request proven by the password, held once it
     * locked the identity's row, waits for it, then cancels the change it
     * wrote: its link confirms nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPasswordChangeWaitsForARequestProvenByThePasswordAndCancelsIt(): void
    {
        $identity = self::seedChangeable();
        $link     = null;

        [$first, $second] = $this->race(
            'select',
            'changeable_identities',
            function () use ($identity, &$link): string {
                $request = $this->changes()->requestByLink($identity, 'email', self::NEW_EMAIL, Reauthentication::password(self::PASSWORD), 'email.confirm');
                $link    = $request->link();

                return $request->status->value;
            },
            static fn (): string => Auth::passwords('web')->set(self::reloaded($identity), self::NEW_PASSWORD, PasswordFlow::CHANGE)->isSet() ? 'set' : 'rejected',
            'for update',
        );

        self::assertSame(['sent', 'set'], [$first, $second['result']]);
        self::assertGreaterThanOrEqual(self::LEAST_WAIT_SECONDS, $second['waited']);
        self::assertSame(0, DB::table('identifier_changes')->count());
        self::assertIsString($link);
        self::assertSame('invalid', $this->changes()->confirmByLink(Request::create($link))->value);
        self::assertSame(self::EMAIL, self::reloaded($identity)->email);
    }

    /**
     * A request proven by the old password racing a password change held after
     * it wrote the new one waits for it, then checks the password against the
     * new one: reauthentication is required, and nothing is written.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARequestProvenByTheOldPasswordWaitsForAPasswordChangeAndIsRefused(): void
    {
        $identity = self::seedChangeable();
        $proof    = Reauthentication::password(self::PASSWORD);

        [$first, $second] = $this->race(
            'update',
            'changeable_identities',
            static fn (): string => Auth::passwords('web')->set(self::reloaded($identity), self::NEW_PASSWORD, PasswordFlow::CHANGE)->isSet() ? 'set' : 'rejected',
            fn (): string => $this->changes()->requestByLink(self::reloaded($identity), 'email', self::NEW_EMAIL, $proof, 'email.confirm')->status->value,
        );

        self::assertSame(['set', 'reauthentication_required'], [$first, $second['result']]);
        self::assertGreaterThanOrEqual(self::LEAST_WAIT_SECONDS, $second['waited']);
        self::assertSame(0, DB::table('identifier_changes')->count());
    }

    /**
     * A revocation of every device racing a request proven by one of them, held
     * once it locked that device's row, waits for it, then cancels the change
     * it wrote.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testABulkRevocationWaitsForARequestProvenByItsDeviceAndCancelsIt(): void
    {
        $identity = self::seedChangeable();
        $device   = self::seedDevice($identity);

        [$first, $second] = $this->race(
            'select',
            'devices',
            fn (): string => $this->changes()->requestByLink($identity, 'email', self::NEW_EMAIL, Reauthentication::device($device), 'email.confirm')->status->value,
            static fn (): string => (string) Auth::sessions('web')->revokeDevices(self::reloaded($identity), RevocationReason::REVOKED),
            'for update',
        );

        self::assertSame(['sent', '1'], [$first, $second['result']]);
        self::assertGreaterThanOrEqual(self::LEAST_WAIT_SECONDS, $second['waited']);
        self::assertSame(0, DB::table('identifier_changes')->count());
    }

    /**
     * A password change made while a request proven by the old password is held
     * after the password was checked, before its transaction, is found under
     * the lock: reauthentication is required, nothing is written, and the
     * `identifier_change` slots are given back.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPasswordChangeAfterARequestsCheckIsFoundUnderItsLock(): void
    {
        $identity = self::seedChangeable();

        [$first, $second] = $this->race(
            'update',
            'rate_limits',
            fn (): string => $this->changes()->requestByLink($identity, 'email', self::NEW_EMAIL, Reauthentication::password(self::PASSWORD), 'email.confirm')->status->value,
            static fn (): string => Auth::passwords('web')->set(self::reloaded($identity), self::NEW_PASSWORD, PasswordFlow::CHANGE)->isSet() ? 'set' : 'rejected',
            '- 1',
        );

        self::assertSame(['reauthentication_required', 'set'], [$first, $second['result']]);
        self::assertSame(0, DB::table('identifier_changes')->count());
        self::assertEverySlotGivenBack();
    }

    /**
     * A revocation of every device made while a request proven by one of them
     * is held after it read the device, before its transaction, is found under
     * the lock: reauthentication is required, nothing is written, and the
     * `identifier_change` slots are given back.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testABulkRevocationAfterARequestsCheckIsFoundUnderItsLock(): void
    {
        $identity = self::seedChangeable();
        $device   = self::seedDevice($identity);

        [$first, $second] = $this->race(
            'select',
            'devices',
            fn (): string => $this->changes()->requestByLink($identity, 'email', self::NEW_EMAIL, Reauthentication::device($device), 'email.confirm')->status->value,
            static fn (): string => (string) Auth::sessions('web')->revokeDevices(self::reloaded($identity), RevocationReason::REVOKED),
        );

        self::assertSame(['reauthentication_required', '1'], [$first, $second['result']]);
        self::assertSame(0, DB::table('identifier_changes')->count());
        self::assertEverySlotGivenBack();
    }

    /**
     * Requests for two identities, none of whose counters, codes or pending
     * changes exist yet, the first held right after its first limiter
     * statement, both go through, the second while the first is still held: the
     * limits are counted before the transaction, so neither holds a lock on the
     * counters' index that the other's insert would wait for (MySQL deadlocks
     * two transactions that each update a missing key, then insert into the
     * gap).
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRequestsForTwoIdentitiesCreatingTheirCountersDoNotDeadlock(): void
    {
        $ada   = self::seedChangeable();
        $grace = self::seedChangeable('grace@example.test');
        $proof = Reauthentication::confirmedAt($this->now);

        [$first, $second] = $this->race(
            'update',
            'rate_limits',
            fn (): string => $this->changes()->requestByCode($ada, 'email', self::NEW_EMAIL, $proof)->status->value,
            fn (): string => $this->changes()->requestByCode($grace, 'email', 'grace@new.example.test', $proof)->status->value,
            untilSecondEnds: true,
        );

        self::assertSame(['sent', 'sent'], [$first, $second['result']]);
        self::assertTrue($second['overlapped']);
        self::assertSame(2, DB::table('identifier_changes')->count());
        self::assertSame(2, DB::table('one_time_codes')->count());
    }

    /**
     * Requests for two identities made inside transactions of their callers,
     * none of whose counters exist yet, the first held right after its first
     * limiter statement, both go through once the counters live on a connection
     * of their own, as the passwords guide tells callers on MySQL to do: on the
     * callers' connection, the counters' missing keys would keep their gaps
     * locked until each caller commits. The second finishes while the first is
     * still held.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRequestsInCallerTransactionsWithCountersOnTheirOwnConnectionDoNotDeadlock(): void
    {
        $connection = DB::getDefaultConnection();

        config()->set('database.connections.counters', config("database.connections.{$connection}"));
        config()->set('authentication.rate_limits.connection', 'counters');

        $ada   = self::seedChangeable();
        $grace = self::seedChangeable('grace@example.test');
        $proof = Reauthentication::confirmedAt($this->now);

        [$first, $second] = $this->race(
            'update',
            'rate_limits',
            fn (): string => DB::transaction(fn (): string => $this->changes()->requestByCode($ada, 'email', self::NEW_EMAIL, $proof)->status->value),
            fn (): string => DB::transaction(fn (): string => $this->changes()->requestByCode($grace, 'email', 'grace@new.example.test', $proof)->status->value),
            untilSecondEnds: true,
        );

        self::assertSame(['sent', 'sent'], [$first, $second['result']]);
        self::assertTrue($second['overlapped']);
        self::assertSame(2, DB::table('identifier_changes')->count());
    }

    /**
     * A request held inside its transaction once it wrote its code and its
     * pending change does not hold up a request for another identity: the
     * second creates its own counters, code and pending change and finishes
     * while the first is still held, as neither holds a lock the other's
     * request waits on.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARequestHeldAfterItsWritesDoesNotHoldUpAnotherIdentitysRequest(): void
    {
        $ada   = self::seedChangeable();
        $grace = self::seedChangeable('grace@example.test');
        $proof = Reauthentication::confirmedAt($this->now);

        [$first, $second] = $this->race(
            'insert',
            'identifier_changes',
            fn (): string => $this->changes()->requestByCode($ada, 'email', self::NEW_EMAIL, $proof)->status->value,
            fn (): string => $this->changes()->requestByCode($grace, 'email', 'grace@new.example.test', $proof)->status->value,
            untilSecondEnds: true,
        );

        self::assertSame(['sent', 'sent'], [$first, $second['result']]);
        self::assertTrue($second['overlapped']);
        self::assertSame(2, DB::table('identifier_changes')->count());
    }

    /**
     * A cancellation racing a confirmation by code, held once it counted the
     * code's attempt, waits for it on the identity's row instead of deadlocking
     * over the pending change and the code, then finds nothing to cancel.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACancellationWaitsForAConfirmationByCode(): void
    {
        $identity = self::seedChangeable();

        self::assertTrue($this->changes()->requestByCode($identity, 'email', self::NEW_EMAIL, Reauthentication::confirmedAt($this->now))->isSent());

        [$first, $second] = $this->race(
            'update',
            'one_time_codes',
            fn (): string => $this->changes()->confirmByCode($identity, 'email', self::CODE)->value,
            fn (): string => $this->changes()->cancel(self::reloaded($identity), 'email') ? 'cancelled' : 'none',
        );

        self::assertSame(['changed', 'none'], [$first, $second['result']]);
        self::assertGreaterThanOrEqual(self::LEAST_WAIT_SECONDS, $second['waited']);
        self::assertSame(self::NEW_EMAIL, self::reloaded($identity)->email);
    }

    /**
     * A request replacing the change a confirmation by code is making, held
     * once it counted the code's attempt, waits for it on the identity's row
     * instead of deadlocking over the pending change and the code: the change
     * is made, then the new request is pending.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAReplacingRequestWaitsForAConfirmationByCode(): void
    {
        $identity = self::seedChangeable();

        $proof = Reauthentication::confirmedAt($this->now);

        self::assertTrue($this->changes()->requestByCode($identity, 'email', self::NEW_EMAIL, $proof)->isSent());

        [$first, $second] = $this->race(
            'update',
            'one_time_codes',
            fn (): string => $this->changes()->confirmByCode($identity, 'email', self::CODE)->value,
            fn (): string => $this->changes()->requestByLink(self::reloaded($identity), 'email', 'ada@later.example.test', $proof, 'email.confirm')->status->value,
        );

        self::assertSame(['changed', 'sent'], [$first, $second['result']]);
        self::assertGreaterThanOrEqual(self::LEAST_WAIT_SECONDS, $second['waited']);
        self::assertSame(self::NEW_EMAIL, self::reloaded($identity)->email);
        self::assertSame(['ada@later.example.test', self::NEW_EMAIL], [DB::table('identifier_changes')->value('identifier'), DB::table('identifier_changes')->value('previous')]);
    }

    /**
     * The documented password change, made over HTTP with the old password
     * while a reset is held after it wrote the owner's new one, waits for the
     * reset on the identity's row before it checks the current password, which
     * is then wrong: the reset's password stays.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheDocumentedPasswordChangeWaitsForAResetAndFindsTheOldPasswordWrong(): void
    {
        $identity = self::seedChangeable();
        $access   = $this->passwordChangeAccess();
        $token    = self::resetToken();

        [$first, $second] = $this->race(
            'update',
            'changeable_identities',
            static fn (): string => Auth::passwords('web')->reset(['email' => self::EMAIL, 'token' => $token, 'password' => 'the reset passphrase'])->status->value,
            fn (): string => $this->changePassword($access),
        );

        self::assertSame(['reset', '422'], [$first, $second['result']]);
        self::assertGreaterThanOrEqual(self::LEAST_WAIT_SECONDS, $second['waited']);
        self::assertTrue(Auth::guard('web')->getProvider()->validateCredentials(self::reloaded($identity), ['password' => 'the reset passphrase']));
    }

    /**
     * A reset racing the documented password change, held once it locked the
     * identity's row, waits until the change has set its password, then finds
     * its token outdated by it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAResetWaitsForTheDocumentedPasswordChange(): void
    {
        $identity = self::seedChangeable();
        $access   = $this->passwordChangeAccess();
        $token    = self::resetToken();

        [$first, $second] = $this->race(
            'select',
            'changeable_identities',
            fn (): string => $this->changePassword($access),
            static fn (): string => Auth::passwords('web')->reset(['email' => self::EMAIL, 'token' => $token, 'password' => 'the reset passphrase'])->status->value,
            'for update',
        );

        self::assertSame(['204', 'invalid'], [$first, $second['result']]);
        self::assertGreaterThanOrEqual(self::LEAST_WAIT_SECONDS, $second['waited']);
        self::assertTrue(Auth::guard('web')->getProvider()->validateCredentials(self::reloaded($identity), ['password' => self::NEW_PASSWORD]));
    }

    /**
     * Register the guards the tests change identifiers and passwords through.
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
     * Request a change of the identity's address, proven by link, and return
     * the link.
     *
     * @param  \Tests\Integration\Fixtures\ChangeableIdentity  $identity
     * @return string
     *
     * @throws \Throwable
     */
    private function requestByLink(ChangeableIdentity $identity): string
    {
        $link = $this->changes()->requestByLink($identity, 'email', self::NEW_EMAIL, Reauthentication::confirmedAt($this->now), 'email.confirm')->link();

        self::assertIsString($link);

        return $link;
    }

    /**
     * Sign in through the `web` guard with the password, define the documented
     * password change route, and return the access token.
     *
     * @return string
     *
     * @throws \Throwable
     */
    private function passwordChangeAccess(): string
    {
        $session = Auth::sessions('web')->signIn('password', ['email' => self::EMAIL, 'password' => self::PASSWORD])->session;

        self::assertNotNull($session);

        Auth::forgetGuards();

        self::definePasswordChangeRoute('web');

        return $session->tokens->accessToken;
    }

    /**
     * Change the password through the documented route, with the access token
     * and the current password, and return the response's status.
     *
     * @param  string  $access
     * @return string
     */
    private function changePassword(string $access): string
    {
        return (string) $this->withToken($access)->putJson('/password', ['current_password' => self::PASSWORD, 'password' => self::NEW_PASSWORD])->baseResponse->getStatusCode();
    }

    /**
     * Issue a live reset link's token for the identity's current address
     * through the `web` guard, and return it.
     *
     * @return string
     *
     * @throws \Throwable
     */
    private static function resetToken(): string
    {
        $issued = app(OneTimeCodes::class)->issueToken(CodeBinding::passwordResetLink('web', 'email', self::EMAIL), CarbonImmutable::now()->startOfSecond(), 3600);

        self::assertInstanceOf(IssuedCode::class, $issued);

        return $issued->code;
    }

    /**
     * Assert that the counters the request wrote hold no attempt: each slot it
     * took was given back.
     *
     * @return void
     */
    private static function assertEverySlotGivenBack(): void
    {
        self::assertGreaterThan(0, DB::table('rate_limits')->count());
        self::assertSame(0, (int) DB::table('rate_limits')->sum('hits'));
    }

    /**
     * The identity as stored now.
     *
     * @param  \Tests\Integration\Fixtures\ChangeableIdentity  $identity
     * @return \Tests\Integration\Fixtures\ChangeableIdentity
     */
    private static function reloaded(ChangeableIdentity $identity): ChangeableIdentity
    {
        return ChangeableIdentity::query()->whereKey($identity->getKey())->firstOrFail();
    }

    /**
     * Run the first operation here, hold it open right after its first
     * statement of the verb on the table (that also holds the marker, given
     * one), start the second in another process meanwhile, then let the first
     * finish, and return both outcomes. The first is held for a fixed time, or,
     * when the second must not wait for it, until the second has finished (at
     * most as long as the second may take to start); the outcome then says
     * whether it finished while the first was held.
     *
     * @param  string  $verb
     * @param  string  $table
     * @param  \Closure(): string  $first
     * @param  \Closure(): string  $second
     * @param  string  $marker
     * @param  bool  $untilSecondEnds
     * @return array{0: string, 1: array{result: string, waited: float, overlapped: bool}}
     *
     * @throws \Throwable
     */
    private function race(string $verb, string $table, \Closure $first, \Closure $second, string $marker = '', bool $untilSecondEnds = false): array
    {
        DB::disconnect();

        $pid = pcntl_fork();

        if ($pid === 0) {
            $this->runInChild($second);
        }

        $held       = false;
        $overlapped = false;
        $outcomes   = $this->outcomes;

        DB::listen(static function (QueryExecuted $query) use (&$held, &$overlapped, $verb, $table, $marker, $outcomes, $untilSecondEnds): void {
            if ($held || !str_starts_with(strtolower($query->sql), $verb) || !str_contains($query->sql, $table) || !str_contains($query->sql, $marker)) {
                return;
            }

            $held       = true;
            $overlapped = self::hasSecondFinishedWhileHeld($outcomes, $untilSecondEnds);
        });

        try {
            $result = $first();
        } finally {
            pcntl_waitpid($pid, $status);
        }

        $outcome = json_decode((string) file_get_contents("{$this->outcomes}/outcome"), true, flags: JSON_THROW_ON_ERROR);

        self::assertTrue($held);
        self::assertIsArray($outcome);
        self::assertArrayNotHasKey('error', $outcome, is_string($outcome['error'] ?? null) ? $outcome['error'] : '');

        /** @var array{result: string, waited: float} $outcome */
        return [$result, [...$outcome, 'overlapped' => $overlapped]];
    }

    /**
     * Start the second operation and hold the first, for a fixed time or until
     * the second has finished (at most as long as it may take to start), and
     * say whether the second had finished by the time the first is released.
     *
     * @param  string  $outcomes
     * @param  bool  $untilSecondEnds
     * @return bool
     */
    private static function hasSecondFinishedWhileHeld(string $outcomes, bool $untilSecondEnds): bool
    {
        touch("{$outcomes}/start");

        $deadline = microtime(true) + self::START_TIMEOUT_SECONDS;

        while ($untilSecondEnds && !is_file("{$outcomes}/outcome") && microtime(true) < $deadline) {
            usleep(5000);
        }

        if (!$untilSecondEnds) {
            usleep(self::HOLD_MICROSECONDS);
        }

        return is_file("{$outcomes}/outcome");
    }

    /**
     * In the forked process: wait to be started, run the operation on a
     * connection of its own, report the outcome or the exception (one that was
     * never started reports that, and runs nothing), and end without running
     * the parent's shutdown. The outcome is renamed into place whole, so the
     * parent never reads it half written.
     *
     * @param  \Closure(): string  $operation
     * @return never
     */
    private function runInChild(\Closure $operation): never
    {
        try {
            $deadline = microtime(true) + self::START_TIMEOUT_SECONDS;

            while (!is_file("{$this->outcomes}/start") && microtime(true) < $deadline) {
                usleep(5000);
            }

            $started = microtime(true);
            $outcome = is_file("{$this->outcomes}/start")
                ? ['result' => $operation(), 'waited' => microtime(true) - $started]
                : ['error' => 'The second operation was never started.'];
        } catch (\Throwable $e) {
            $outcome = ['error' => $e::class . ': ' . $e->getMessage()];
        }

        file_put_contents("{$this->outcomes}/outcome.tmp", json_encode($outcome));
        rename("{$this->outcomes}/outcome.tmp", "{$this->outcomes}/outcome");

        posix_kill(posix_getpid(), SIGKILL);

        exit(1);
    }
}
