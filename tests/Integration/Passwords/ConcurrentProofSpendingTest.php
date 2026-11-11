<?php

declare(strict_types = 1);

namespace Tests\Integration\Passwords;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\DeadlockException;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Codes\CodeBinding;
use SineMacula\Laravel\Authentication\Codes\IssuedCode;
use SineMacula\Laravel\Authentication\Codes\OneTimeCodes;
use SineMacula\Laravel\Authentication\Database\IdentityLock;
use SineMacula\Laravel\Authentication\Events\Enums\RevocationReason;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Http\SignedLink;
use SineMacula\Laravel\Authentication\IdentifierChanges\ChangeRequests;
use SineMacula\Laravel\Authentication\IdentifierChanges\IdentifierChangeService;
use SineMacula\Laravel\Authentication\Models\Session;
use SineMacula\Laravel\Authentication\Passwords\Enums\PasswordFlow;
use SineMacula\Laravel\Authentication\Passwords\PasswordChanges;
use SineMacula\Laravel\Authentication\Passwords\PasswordResult;
use SineMacula\Laravel\Authentication\Passwords\ResetSubmissions;
use SineMacula\Laravel\Authentication\Proofs\Channel;
use SineMacula\Laravel\Authentication\Proofs\Enums\ChannelKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\Purpose;
use SineMacula\Laravel\Authentication\Proofs\Evaluation;
use SineMacula\Laravel\Authentication\Proofs\NewProof;
use SineMacula\Laravel\Authentication\Proofs\ObservedProperties;
use SineMacula\Laravel\Authentication\Proofs\ProofWriter;
use SineMacula\Laravel\Authentication\SessionRecords\SessionLookup;
use SineMacula\Laravel\Authentication\Sessions\Reauthentication;
use SineMacula\Laravel\Authentication\Sessions\RecentAuthentication;
use SineMacula\Laravel\Authentication\Sessions\RevocationWriter;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use Tests\Concerns\ChangesIdentifiers;
use Tests\Concerns\DefinesPasswordChangeRoute;
use Tests\Concerns\InteractsWithIsolationLevels;
use Tests\Fixtures\Proofs\UndescribedFirstFactor;
use Tests\Integration\Fixtures\ChangeableIdentity;
use Tests\TestCase;

/**
 * Races password writes against the flows that spend or take a proof bound to
 * the same identity, in separate processes on PostgreSQL and MySQL.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(IdentityLock::class)]
#[CoversClass(IdentifierChangeService::class)]
#[CoversClass(ResetSubmissions::class)]
#[CoversClass(RevocationWriter::class)]
#[CoversClass(ChangeRequests::class)]
#[CoversClass(RecentAuthentication::class)]
#[CoversClass(SessionLookup::class)]
#[CoversClass(PasswordChanges::class)]
final class ConcurrentProofSpendingTest extends TestCase
{
    use ChangesIdentifiers, DefinesPasswordChangeRoute, InteractsWithIsolationLevels;

    /** @var int How long the first operation is held after its statement once the second has started, in microseconds. */
    private const int HOLD_MICROSECONDS = 1000000;

    /** @var float The least time, in seconds, the second operation must have waited to show it waited on the first. */
    private const float LEAST_WAIT_SECONDS = 0.5;

    /** @var int How long the second operation waits to be started before giving up, in seconds. */
    private const int START_TIMEOUT_SECONDS = 10;

    /** @var int How long the forked side waits on the blocked establishment before recording its proof, in microseconds. */
    private const int CROSS_MICROSECONDS = 300000;

    /** @var string The new password the racing writes set. */
    private const string NEW_PASSWORD = 'a brand new long passphrase';

    /** @var string Directory the second operation reports its outcome in. */
    private string $outcomes;

    /**
     * Skip where processes cannot share the database, and start from a known
     * moment with the fakes bound.
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
     * A password change waits for a confirmation, then sets the password.
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
            fn (): string => $this->changes()->confirmByLink(SignedLink::fromRequest(Request::create($link)), self::requestClient(Request::create($link)))->outcome->value,
            static fn (): string => Auth::passwords('web')->set(
                self::reloaded($identity),
                self::NEW_PASSWORD,
                PasswordFlow::CHANGE,
                self::requestClient(),
            )->isSet() ? 'set' : 'rejected',
        );

        self::assertSame(['changed', 'set'], [$first, $second['result']]);
        self::assertGreaterThanOrEqual(self::LEAST_WAIT_SECONDS, $second['waited']);
        self::assertSame(self::NEW_EMAIL, self::reloaded($identity)->email);
    }

    /**
     * A password change waits for a confirmation that outdated a reset link.
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
            'update',
            'one_time_codes',
            fn (): string => $this->changes()->confirmByLink(SignedLink::fromRequest(Request::create($link)), self::requestClient(Request::create($link)))->outcome->value,
            static fn (): string => Auth::passwords('web')->set(
                self::reloaded($identity),
                self::NEW_PASSWORD,
                PasswordFlow::CHANGE,
                self::requestClient(),
            )->isSet() ? 'set' : 'rejected',
        );

        self::assertSame(['changed', 'set'], [$first, $second['result']]);
        self::assertGreaterThanOrEqual(self::LEAST_WAIT_SECONDS, $second['waited']);
    }

    /**
     * A reset waits for a confirmation, then finds its link outdated.
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
            fn (): string => $this->changes()->confirmByLink(SignedLink::fromRequest(Request::create($link)), self::requestClient(Request::create($link)))->outcome->value,
            static fn (): string => Auth::passwords('web')->reset(
                ['email' => self::EMAIL, 'token' => $token, 'password' => self::NEW_PASSWORD],
                self::requestClient(),
            )->status->value,
        );

        self::assertSame(['changed', 'invalid'], [$first, $second['result']]);
        self::assertGreaterThanOrEqual(self::LEAST_WAIT_SECONDS, $second['waited']);
    }

    /**
     * A password change waits for a reset, then sets its own password.
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
            static fn (): string => Auth::passwords('web')->reset(
                ['email' => self::EMAIL, 'token' => $token, 'password' => 'the reset passphrase'],
                self::requestClient(),
            )->status->value,
            static fn (): string => Auth::passwords('web')->set(
                self::reloaded($identity),
                self::NEW_PASSWORD,
                PasswordFlow::CHANGE,
                self::requestClient(),
            )->isSet() ? 'set' : 'rejected',
        );

        self::assertSame(['reset', 'set'], [$first, $second['result']]);
        self::assertGreaterThanOrEqual(self::LEAST_WAIT_SECONDS, $second['waited']);
        self::assertTrue(Auth::guard('web')->getProvider()->validateCredentials(self::reloaded($identity), ['password' => self::NEW_PASSWORD]));
    }

    /**
     * A confirmation waits for a bulk revocation, then finds the change
     * cancelled.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAConfirmationWaitsForABulkRevocationAndFindsTheChangeCanceled(): void
    {
        $identity = self::seedChangeable();
        $link     = $this->requestByLink($identity);

        [$first, $second] = $this->race(
            'delete from',
            'identifier_changes',
            static fn (): string => (string) Auth::sessions('web')->revokeSessions(self::reloaded($identity), RevocationReason::REVOKED),
            fn (): string => $this->changes()->confirmByLink(SignedLink::fromRequest(Request::create($link)), self::requestClient(Request::create($link)))->outcome->value,
        );

        self::assertSame(['1', 'invalid'], [$first, $second['result']]);
        self::assertGreaterThanOrEqual(self::LEAST_WAIT_SECONDS, $second['waited']);
        self::assertSame(self::EMAIL, self::reloaded($identity)->email);
    }

    /**
     * A password change waits for a request proven by the password, then
     * cancels it.
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
                $request = $this->changes()->requestByLink($identity, 'email', self::NEW_EMAIL, Reauthentication::password(self::PASSWORD), 'email.confirm', self::requestClient());
                $link    = $request->link()?->reveal();

                return $request->status->value;
            },
            static fn (): string => Auth::passwords('web')->set(
                self::reloaded($identity),
                self::NEW_PASSWORD,
                PasswordFlow::CHANGE,
                self::requestClient(),
            )->isSet() ? 'set' : 'rejected',
            'for update',
        );

        self::assertSame(['sent', 'set'], [$first, $second['result']]);
        self::assertGreaterThanOrEqual(self::LEAST_WAIT_SECONDS, $second['waited']);
        self::assertSame(0, DB::table('identifier_changes')->count());
        self::assertIsString($link);
        self::assertSame('invalid', $this->changes()->confirmByLink(SignedLink::fromRequest(Request::create($link)), self::requestClient(Request::create($link)))->outcome->value);
        self::assertSame(self::EMAIL, self::reloaded($identity)->email);
    }

    /**
     * A request proven by the old password waits for a password change and is
     * refused.
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
            static fn (): string => Auth::passwords('web')->set(
                self::reloaded($identity),
                self::NEW_PASSWORD,
                PasswordFlow::CHANGE,
                self::requestClient(),
            )->isSet() ? 'set' : 'rejected',
            fn (): string => $this->changes()->requestByLink(self::reloaded($identity), 'email', self::NEW_EMAIL, $proof, 'email.confirm', self::requestClient())->status->value,
        );

        self::assertSame(['set', 'reauthentication_required'], [$first, $second['result']]);
        self::assertGreaterThanOrEqual(self::LEAST_WAIT_SECONDS, $second['waited']);
        self::assertSame(0, DB::table('identifier_changes')->count());
    }

    /**
     * A bulk revocation waits for a request proven by one of its sessions, then
     * cancels it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testABulkRevocationWaitsForARequestProvenByItsSessionAndCancelsIt(): void
    {
        $identity = self::seedChangeable();
        $record   = self::seedSession($identity);

        [$first, $second] = $this->race(
            'select',
            'authentication_sessions',
            fn (): string => $this->changes()->requestByLink(
                $identity,
                'email',
                self::NEW_EMAIL,
                Reauthentication::session($record),
                'email.confirm',
                self::requestClient(),
            )->status->value,
            static fn (): string => (string) Auth::sessions('web')->revokeSessions(self::reloaded($identity), RevocationReason::REVOKED),
            'for update',
        );

        self::assertSame(['sent', '1'], [$first, $second['result']]);
        self::assertGreaterThanOrEqual(self::LEAST_WAIT_SECONDS, $second['waited']);
        self::assertSame(0, DB::table('identifier_changes')->count());
    }

    /**
     * A password change after a request's check is found under its lock and the
     * slots are given back.
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
            fn (): string => $this->changes()->requestByLink(
                $identity,
                'email',
                self::NEW_EMAIL,
                Reauthentication::password(self::PASSWORD),
                'email.confirm',
                self::requestClient(),
            )->status->value,
            static fn (): string => Auth::passwords('web')->set(
                self::reloaded($identity),
                self::NEW_PASSWORD,
                PasswordFlow::CHANGE,
                self::requestClient(),
            )->isSet() ? 'set' : 'rejected',
            '- 1',
        );

        self::assertSame(['reauthentication_required', 'set'], [$first, $second['result']]);
        self::assertSame(0, DB::table('identifier_changes')->count());
        self::assertEverySlotGivenBack();
    }

    /**
     * A bulk revocation after a request's check is found under its lock and the
     * slots are given back.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testABulkRevocationAfterARequestsCheckIsFoundUnderItsLock(): void
    {
        $identity = self::seedChangeable();
        $record   = self::seedSession($identity);

        [$first, $second] = $this->race(
            'update',
            'rate_limits',
            fn (): string => $this->changes()->requestByLink(
                $identity,
                'email',
                self::NEW_EMAIL,
                Reauthentication::session($record),
                'email.confirm',
                self::requestClient(),
            )->status->value,
            static fn (): string => (string) Auth::sessions('web')->revokeSessions(self::reloaded($identity), RevocationReason::REVOKED),
        );

        self::assertSame(['reauthentication_required', '1'], [$first, $second['result']]);
        self::assertSame(0, DB::table('identifier_changes')->count());
        self::assertEverySlotGivenBack();
    }

    /**
     * Requests for two identities creating their counters do not deadlock.
     *
     * MySQL deadlocks two updates of a missing key followed by inserts.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRequestsForTwoIdentitiesCreatingTheirCountersDoNotDeadlock(): void
    {
        $ada        = self::seedChangeable();
        $grace      = self::seedChangeable('grace@example.test');
        $adaProof   = self::freshSession($ada);
        $graceProof = self::freshSession($grace);

        [$first, $second] = $this->race(
            'update',
            'rate_limits',
            fn (): string => $this->changes()->requestByCode($ada, 'email', self::NEW_EMAIL, $adaProof, self::requestClient())->status->value,
            fn (): string => $this->changes()->requestByCode($grace, 'email', 'grace@new.example.test', $graceProof, self::requestClient())->status->value,
            untilSecondEnds: true,
        );

        self::assertSame(['sent', 'sent'], [$first, $second['result']]);
        self::assertTrue($second['overlapped']);
        self::assertSame(2, DB::table('identifier_changes')->count());
        self::assertSame(2, DB::table('one_time_codes')->count());
    }

    /**
     * Requests in callers' transactions do not deadlock once the counters have
     * a connection of their own.
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

        $ada        = self::seedChangeable();
        $grace      = self::seedChangeable('grace@example.test');
        $adaProof   = self::freshSession($ada);
        $graceProof = self::freshSession($grace);

        [$first, $second] = $this->race(
            'update',
            'rate_limits',
            fn (): string => DB::transaction(fn (): string => $this->changes()->requestByCode($ada, 'email', self::NEW_EMAIL, $adaProof, self::requestClient())->status->value),
            fn (): string => DB::transaction(
                fn (): string => $this->changes()->requestByCode($grace, 'email', 'grace@new.example.test', $graceProof, self::requestClient())->status->value,
            ),
            untilSecondEnds: true,
        );

        self::assertSame(['sent', 'sent'], [$first, $second['result']]);
        self::assertTrue($second['overlapped']);
        self::assertSame(2, DB::table('identifier_changes')->count());
    }

    /**
     * A request held after its writes does not hold up another identity's
     * request.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARequestHeldAfterItsWritesDoesNotHoldUpAnotherIdentitysRequest(): void
    {
        $ada        = self::seedChangeable();
        $grace      = self::seedChangeable('grace@example.test');
        $adaProof   = self::freshSession($ada);
        $graceProof = self::freshSession($grace);

        [$first, $second] = $this->race(
            'insert',
            'identifier_changes',
            fn (): string => $this->changes()->requestByCode($ada, 'email', self::NEW_EMAIL, $adaProof, self::requestClient())->status->value,
            fn (): string => $this->changes()->requestByCode($grace, 'email', 'grace@new.example.test', $graceProof, self::requestClient())->status->value,
            untilSecondEnds: true,
        );

        self::assertSame(['sent', 'sent'], [$first, $second['result']]);
        self::assertTrue($second['overlapped']);
        self::assertSame(2, DB::table('identifier_changes')->count());
    }

    /**
     * A cancellation waits for a confirmation by code, then finds nothing to
     * cancel.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACancellationWaitsForAConfirmationByCode(): void
    {
        $identity = self::seedChangeable();

        self::assertTrue($this->changes()->requestByCode($identity, 'email', self::NEW_EMAIL, self::freshSession($identity), self::requestClient())->isSent());

        [$first, $second] = $this->race(
            'update',
            'one_time_codes',
            fn (): string => $this->changes()->confirmByCode($identity, 'email', self::changeChallenge($identity, 'email'), self::CODE, self::requestClient())->outcome->value,
            fn (): string => $this->changes()->cancel(self::reloaded($identity), 'email') ? 'canceled' : 'none',
        );

        self::assertSame(['changed', 'none'], [$first, $second['result']]);
        self::assertGreaterThanOrEqual(self::LEAST_WAIT_SECONDS, $second['waited']);
        self::assertSame(self::NEW_EMAIL, self::reloaded($identity)->email);
    }

    /**
     * A replacing request waits for a confirmation by code, then is pending.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAReplacingRequestWaitsForAConfirmationByCode(): void
    {
        $identity = self::seedChangeable();

        $proof = self::freshSession($identity);

        self::assertTrue($this->changes()->requestByCode($identity, 'email', self::NEW_EMAIL, $proof, self::requestClient())->isSent());

        [$first, $second] = $this->race(
            'update',
            'one_time_codes',
            fn (): string => $this->changes()->confirmByCode($identity, 'email', self::changeChallenge($identity, 'email'), self::CODE, self::requestClient())->outcome->value,
            fn (): string => $this->changes()->requestByLink(
                self::reloaded($identity),
                'email',
                'ada@later.example.test',
                $proof,
                'email.confirm',
                self::requestClient(),
            )->status->value,
        );

        self::assertSame(['changed', 'sent'], [$first, $second['result']]);
        self::assertGreaterThanOrEqual(self::LEAST_WAIT_SECONDS, $second['waited']);
        self::assertSame(self::NEW_EMAIL, self::reloaded($identity)->email);
        self::assertSame(['ada@later.example.test', self::NEW_EMAIL], [DB::table('identifier_changes')->value('identifier'), DB::table('identifier_changes')->value('previous')]);
    }

    /**
     * The documented password change waits for a reset and finds the old
     * password wrong.
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
            static fn (): string => Auth::passwords('web')->reset(
                ['email' => self::EMAIL, 'token' => $token, 'password' => 'the reset passphrase'],
                self::requestClient(),
            )->status->value,
            fn (): string => $this->changePassword($access),
        );

        self::assertSame(['reset', '422'], [$first, $second['result']]);
        self::assertGreaterThanOrEqual(self::LEAST_WAIT_SECONDS, $second['waited']);
        self::assertTrue(Auth::guard('web')->getProvider()->validateCredentials(self::reloaded($identity), ['password' => 'the reset passphrase']));
    }

    /**
     * A reset waits for the documented password change, then finds its token
     * outdated.
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
            static fn (): string => Auth::passwords('web')->reset(
                ['email' => self::EMAIL, 'token' => $token, 'password' => 'the reset passphrase'],
                self::requestClient(),
            )->status->value,
            'for update',
        );

        self::assertSame(['204', 'invalid'], [$first, $second['result']]);
        self::assertGreaterThanOrEqual(self::LEAST_WAIT_SECONDS, $second['waited']);
        self::assertTrue(Auth::guard('web')->getProvider()->validateCredentials(self::reloaded($identity), ['password' => self::NEW_PASSWORD]));
    }

    /**
     * An establishment waits for another, then finds a password set.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnEstablishmentWaitsForAnotherAndFindsAPasswordSet(): void
    {
        $identity = self::seedPasswordless();
        $session  = self::startedSession($identity);

        [$first, $second] = $this->race(
            'update',
            'changeable_identities',
            static fn (): string => self::outcomeOf(Auth::passwords('web')->establish($session, self::NEW_PASSWORD, self::requestClient())),
            static fn (): string => self::outcomeOf(Auth::passwords('web')->establish($session, 'another long passphrase', self::requestClient())),
        );

        self::assertSame(['set', 'password_already_set'], [$first, $second['result']]);
        self::assertGreaterThanOrEqual(self::LEAST_WAIT_SECONDS, $second['waited']);
        self::assertTrue(Auth::guard('web')->getProvider()->validateCredentials(self::reloaded($identity), ['password' => self::NEW_PASSWORD]));
    }

    /**
     * A reset waits for an establishment, then finds its token outdated.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAResetWaitsForAnEstablishmentAndFindsItsTokenOutdated(): void
    {
        $identity = self::seedPasswordless();
        $session  = self::startedSession($identity);
        $token    = self::resetToken();

        [$first, $second] = $this->race(
            'update',
            'changeable_identities',
            static fn (): string => self::outcomeOf(Auth::passwords('web')->establish($session, self::NEW_PASSWORD, self::requestClient())),
            static fn (): string => Auth::passwords('web')->reset(
                ['email' => self::EMAIL, 'token' => $token, 'password' => 'the reset passphrase'],
                self::requestClient(),
            )->status->value,
        );

        self::assertSame(['set', 'invalid'], [$first, $second['result']]);
        self::assertGreaterThanOrEqual(self::LEAST_WAIT_SECONDS, $second['waited']);
        self::assertTrue(Auth::guard('web')->getProvider()->validateCredentials(self::reloaded($identity), ['password' => self::NEW_PASSWORD]));
    }

    /**
     * An establishment crossing a neighbour's proof fails as a deadlock, or
     * waits, by isolation level.
     *
     * @param  string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideIsolationLevels')]
    public function testAnEstablishmentCrossingANeighboursProofFailsAsADeadlockOrWaits(string $level): void
    {
        $identity = self::seedPasswordless();
        $sessions = [self::startedSession($identity), self::startedSession($identity)];

        $key = static fn (Session $session): string => (string) IdentifierCoercion::stringify($session->getKey());

        usort($sessions, static fn (Session $one, Session $other): int => strcmp($key($one), $key($other)));

        [$judged, $neighbour] = $sessions;

        $proofs = DB::table('authentication_proofs')->where('session_id', $judged->getKey())->orderBy('id')->get()->all();

        DB::disconnect();

        $pid = pcntl_fork();

        if ($pid < 0) {
            self::fail('The second side could not be forked.');
        }

        if ($pid === 0) {
            $this->crossInChild($neighbour);
        }

        $this->awaitHeld($pid);

        self::beginTransactionAt($level);

        try {
            $thrown = Auth::passwords('web')->establish($judged, self::NEW_PASSWORD, self::requestClient());
        } catch (\Throwable $exception) {
            $thrown = $exception;
        }

        $nested = DB::transactionLevel();

        $thrown instanceof \Throwable ? DB::rollBack() : DB::commit();

        pcntl_waitpid($pid, $status);

        self::assertSame(['crossed' => true], json_decode((string) file_get_contents("{$this->outcomes}/outcome"), true, flags: JSON_THROW_ON_ERROR));
        self::assertSame(1, $nested);
        self::assertSame(0, DB::transactionLevel());
        self::assertSame(1, DB::table('authentication_proofs')->where('session_id', $neighbour->getKey())->where('kind', 'additional_factor')->count());

        $deadlocks = DB::connection()->getDriverName() === 'mysql' && $level === 'repeatable read';

        self::assertSame($deadlocks || self::readsASnapshot($level), $thrown instanceof \Throwable);

        if ($thrown instanceof \Throwable) {
            self::assertInstanceOf(DeadlockException::class, $thrown);

            $cause = $thrown;

            while ($cause instanceof DeadlockException && $cause->getPrevious() instanceof \Throwable) {
                $cause = $cause->getPrevious();
            }

            self::assertSame('40001', (string) $cause->getCode());
            self::assertNull(self::reloaded($identity)->password);
            self::assertSame(0, DB::table('authentication_sessions')->whereNotNull('revoked_at')->count());
            self::assertEquals($proofs, DB::table('authentication_proofs')->where('session_id', $judged->getKey())->orderBy('id')->get()->all());

            $thrown = DB::transaction(static fn (): PasswordResult => Auth::passwords('web')->establish($judged, self::NEW_PASSWORD, self::requestClient()));
        }

        self::assertSame([true, 1], [$thrown->isSet(), $thrown->revoked]);
        self::assertSame('password_established', DB::table('authentication_sessions')->where('id', $neighbour->getKey())->value('revoked_reason'));
    }

    /**
     * A password change waits for a revocation of its session and is refused.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPasswordChangeWaitsForARevocationOfItsSessionAndIsRefused(): void
    {
        $identity = self::seedChangeable();
        $session  = self::startedSession($identity);

        [$first, $second] = $this->race(
            'update',
            'authentication_sessions',
            static fn (): string => DB::transaction(
                static fn (): bool => Auth::sessions('web')->revokeSession($identity, $session->getKey(), RevocationReason::SIGNED_OUT),
            ) ? 'revoked' : 'kept',
            static fn (): string => self::outcomeOf(Auth::passwords('web')->change($session, self::PASSWORD, self::NEW_PASSWORD, self::requestClient())),
        );

        self::assertSame(['revoked', 'session_revoked'], [$first, $second['result']]);
        self::assertGreaterThanOrEqual(self::LEAST_WAIT_SECONDS, $second['waited']);
        self::assertTrue(Auth::guard('web')->getProvider()->validateCredentials(self::reloaded($identity), ['password' => self::PASSWORD]));
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
        $link = $this->changes()->requestByLink($identity, 'email', self::NEW_EMAIL, self::freshSession($identity), 'email.confirm', self::requestClient())->link()?->reveal();

        self::assertIsString($link);

        return $link;
    }

    /**
     * Sign in through the `web` guard, define the documented password change
     * route, and return the access token.
     *
     * @return string
     *
     * @throws \Throwable
     */
    private function passwordChangeAccess(): string
    {
        $session = Auth::sessions('web')->signIn('password', ['email' => self::EMAIL, 'password' => self::PASSWORD], self::requestContext())->session;

        self::assertNotNull($session);

        Auth::forgetGuards();

        self::definePasswordChangeRoute('web');

        return $session->tokens->accessToken->reveal();
    }

    /**
     * Change the password through the documented route and return the
     * response's status.
     *
     * @param  string  $access
     * @return string
     */
    private function changePassword(string $access): string
    {
        return (string) $this->withToken($access)->putJson('/password', ['current_password' => self::PASSWORD, 'password' => self::NEW_PASSWORD])->baseResponse->getStatusCode();
    }

    /**
     * Issue a live reset token for the identity's current address.
     *
     * @return string
     *
     * @throws \Throwable
     */
    private static function resetToken(): string
    {
        $issued = app(OneTimeCodes::class)->issueToken(CodeBinding::passwordResetLink('web', 'email', self::EMAIL), CarbonImmutable::now()->startOfSecond(), 3600);

        self::assertInstanceOf(IssuedCode::class, $issued);

        return $issued->code();
    }

    /**
     * Persist an identity as `seedChangeable()` does, but with no password.
     *
     * @return \Tests\Integration\Fixtures\ChangeableIdentity
     */
    private static function seedPasswordless(): ChangeableIdentity
    {
        $identity = self::seedChangeable();

        $identity->forceFill(['password' => null])->save();

        return $identity;
    }

    /**
     * A session of the identity on the `web` guard with a fresh first factor.
     *
     * @param  \Tests\Integration\Fixtures\ChangeableIdentity  $identity
     * @return \SineMacula\Laravel\Authentication\Models\Session
     *
     * @throws \Throwable
     */
    private static function startedSession(ChangeableIdentity $identity): Session
    {
        $record = Auth::sessions('web')->start(UndescribedFirstFactor::of($identity), null, 'password', self::requestContext())->session?->record;

        self::assertInstanceOf(Session::class, $record);

        return $record;
    }

    /**
     * Wait until the forked side holds the neighbour's row, failing when it
     * never does.
     *
     * @param  int  $pid
     * @return void
     */
    private function awaitHeld(int $pid): void
    {
        $deadline = microtime(true) + self::START_TIMEOUT_SECONDS;

        while (!is_file("{$this->outcomes}/held") && microtime(true) < $deadline) {
            usleep(5000);
        }

        if (is_file("{$this->outcomes}/held")) {
            return;
        }

        posix_kill($pid, SIGKILL);
        pcntl_waitpid($pid, $status);

        self::fail('The forked side never held the neighbouring session.');
    }

    /**
     * In the forked process, hold the neighbour's row until the establishment
     * waits on it, then record a proof for it.
     *
     * Written many times so MySQL makes the other side the deadlock victim.
     *
     * @param  \SineMacula\Laravel\Authentication\Models\Session  $neighbour
     * @return never
     */
    private function crossInChild(Session $neighbour): never
    {
        try {
            DB::beginTransaction();

            foreach (range(1, 50) as $ignored) {
                DB::table('authentication_sessions')->where('id', $neighbour->getKey())->increment('issuance_sequence');
            }

            touch("{$this->outcomes}/held");

            self::awaitAWaiter();

            usleep(self::CROSS_MICROSECONDS);

            $row = SessionLookup::find($neighbour->getKey());

            self::assertNotNull($row);

            ProofWriter::record($row, 'web', new NewProof(
                ProofKind::ADDITIONAL_FACTOR,
                Purpose::STEP_UP,
                'totp',
                new Channel(ChannelKind::AUTHENTICATOR_APP),
                'factor-1',
                new ObservedProperties,
                new Evaluation(true, true),
                ['otp'],
                CarbonImmutable::now(),
            ));

            DB::commit();

            $outcome = ['crossed' => true];
        } catch (\Throwable $e) {
            $outcome = ['error' => $e->getMessage()];
        }

        file_put_contents("{$this->outcomes}/outcome", json_encode($outcome));

        posix_kill(posix_getpid(), SIGKILL);

        exit(1);
    }

    /**
     * Wait until another connection waits on a lock this connection's
     * transaction holds.
     *
     * @return void
     *
     * @throws \RuntimeException
     */
    private static function awaitAWaiter(): void
    {
        $deadline = microtime(true) + self::START_TIMEOUT_SECONDS;

        while (!self::isWaitedOn()) {
            if (microtime(true) >= $deadline) {
                throw new \RuntimeException('Nothing waited on the locks this side holds.');
            }

            usleep(5000);
        }
    }

    /**
     * Whether another connection waits on a lock this transaction holds.
     *
     * PostgreSQL reads `pg_locks`; `pg_stat_activity` keeps a stale snapshot.
     *
     * @return bool
     */
    private static function isWaitedOn(): bool
    {
        return DB::connection()->getDriverName() === 'pgsql'
            ? DB::table('pg_locks')
                ->where('granted', false)
                ->whereRaw('pg_backend_pid() = any(pg_blocking_pids(pid))')
                ->exists()
            : DB::table('performance_schema.data_lock_waits as waits')
                ->join('performance_schema.threads as threads', 'threads.THREAD_ID', '=', 'waits.BLOCKING_THREAD_ID')
                ->whereRaw('threads.PROCESSLIST_ID = connection_id()')
                ->exists();
    }

    /**
     * A password write's outcome: `set`, or the reason it was refused.
     *
     * @param  \SineMacula\Laravel\Authentication\Passwords\PasswordResult  $result
     * @return string
     */
    private static function outcomeOf(PasswordResult $result): string
    {
        return $result->isSet() ? 'set' : (string) $result->reason?->value;
    }

    /**
     * Assert that every slot the request took was given back.
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
     * Run the first operation, hold it after its first matching statement while
     * the second runs in another process, and return both outcomes.
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
     * Start the second operation, hold the first, and say whether the second
     * finished meanwhile.
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
     * Run the operation in the forked process, report its outcome and exit
     * without the parent's shutdown.
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
