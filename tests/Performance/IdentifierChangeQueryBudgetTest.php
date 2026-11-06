<?php

declare(strict_types = 1);

namespace Tests\Performance;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Routing\Router;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Queue;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\IdentifierChanges\ChangeConfirmation;
use SineMacula\Laravel\Authentication\IdentifierChanges\ChangeRequests;
use SineMacula\Laravel\Authentication\IdentifierChanges\Enums\IdentifierChangeOutcome;
use SineMacula\Laravel\Authentication\IdentifierChanges\Enums\IdentifierChangeRequestStatus;
use SineMacula\Laravel\Authentication\IdentifierChanges\IdentifierChangeRequest;
use SineMacula\Laravel\Authentication\IdentifierChanges\IdentifierChangeService;
use SineMacula\Laravel\Authentication\Passwords\Enums\PasswordFlow;
use SineMacula\Laravel\Authentication\Passwords\OutdatedProofs;
use SineMacula\Laravel\Authentication\Passwords\PasswordResult;
use SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind;
use SineMacula\Laravel\Authentication\Proofs\Evaluation;
use SineMacula\Laravel\Authentication\Sessions\Reauthentication;
use SineMacula\Laravel\Authentication\Sessions\RecentAuthentication;
use SineMacula\Laravel\Authentication\Testing\FakeIdentifierChangeNotifier;
use SineMacula\Laravel\Authentication\Testing\FakeOneTimeCodeSender;
use Tests\Concerns\InteractsWithChangeableIdentities;
use Tests\Concerns\InteractsWithProofs;

/**
 * Query-budget contracts for changing identifiers: a request and a confirmation
 * each cost a fixed number of statements for each proof (a confirmation time,
 * the session, the password, right, wrong or rate limited, the last two waiting
 * out the credential timebox), and a new password cancels every pending change
 * in one.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(IdentifierChangeService::class)]
#[CoversClass(ChangeRequests::class)]
#[CoversClass(ChangeConfirmation::class)]
#[CoversClass(OutdatedProofs::class)]
#[CoversClass(RecentAuthentication::class)]
final class IdentifierChangeQueryBudgetTest extends PerformanceContractTestCase
{
    use InteractsWithChangeableIdentities, InteractsWithProofs;

    /** @var int Timebox for the timing contracts, in microseconds. */
    private const int TIMEBOX_MICROSECONDS = 200000;

    /**
     * Create the identities table, fake the notifier, the code sender and the
     * queue, and issue a known code.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        self::createChangeableIdentitiesTable();
        self::issueCodes(['135790']);

        config()->set('queue.default', 'database');
        config()->set('queue.connections.database', ['driver' => 'database']);

        Queue::fake();
        FakeIdentifierChangeNotifier::fake($this->app);
        FakeOneTimeCodeSender::fake($this->app);
    }

    /**
     * Drop the identities table.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        self::dropChangeableIdentitiesTable();

        parent::tearDown();
    }

    /**
     * A first request proven by the session it is made from reads the
     * identity's row, reads the session (for its owner), then the freshness
     * policy reads it again and its freshest proof, and counts the limits (an
     * update, then an insert, for each of the identifier, the identity and the
     * IP address); then, in its transaction, it locks the row, locks the
     * session and has the policy read it and its freshest proof again, issues
     * the code (an insert), reads the pending change it would replace, and
     * inserts its own.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARequestByCodeHasAFixedBudget(): void
    {
        $identity = self::seedChangeable();
        $changes  = Auth::identifierChanges('web');

        $proof   = self::freshSession($identity);
        $request = $this->assertQueryBudget(
            9,
            8,
            static fn (): IdentifierChangeRequest => $changes->requestByCode($identity, 'email', self::NEW_EMAIL, $proof, self::requestClient()),
        );

        self::assertTrue($request->isSent());
    }

    /**
     * A request by link that replaces another issues no code and counts on the
     * existing identity and IP address counters; it updates the pending change
     * in place and invalidates the code of the one it replaced.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAReplacingRequestByLinkHasAFixedBudget(): void
    {
        $identity = self::seedChangeable();
        $changes  = Auth::identifierChanges('web');
        $proof    = self::freshSession($identity);

        $changes->requestByLink($identity, 'email', 'ada@first.example.test', $proof, 'confirm', self::requestClient());

        $request = $this->assertQueryBudget(
            9,
            6,
            static fn (): IdentifierChangeRequest => $changes->requestByLink($identity, 'email', self::NEW_EMAIL, $proof, 'confirm', self::requestClient()),
        );

        self::assertTrue($request->isSent());
    }

    /**
     * A request proven by a session that signed in long ago and was stepped up
     * many times since costs what one proven by a session just signed in does:
     * the freshness policy reads the one freshest proof, however many the
     * session holds.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARequestProvenByASessionWithManyProofsHasTheSameBudget(): void
    {
        $identity = self::seedChangeable();
        $session  = self::seedSession($identity, 'web', now()->subDays(30));

        foreach (range(1, 50) as $minutes) {
            self::recordProof($session, ProofKind::ADDITIONAL_FACTOR, now()->subMinutes($minutes), ['otp'], new Evaluation(true, true));
        }

        $proof   = Reauthentication::session($session);
        $changes = Auth::identifierChanges('web');

        $request = $this->assertQueryBudget(
            9,
            8,
            static fn (): IdentifierChangeRequest => $changes->requestByCode($identity, 'email', self::NEW_EMAIL, $proof, self::requestClient()),
        );

        self::assertTrue($request->isSent());
    }

    /**
     * A request a revoked session cannot prove stops at the session's row:
     * nothing is counted or written.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARequestItsSessionCannotProveStopsAtTheSession(): void
    {
        $identity = self::seedChangeable();
        $session  = self::seedSession($identity);

        $session->forceFill(['revoked_at' => now()])->save();

        $proof   = Reauthentication::session($session);
        $changes = Auth::identifierChanges('web');
        $request = $this->assertQueryBudget(
            2,
            0,
            static fn (): IdentifierChangeRequest => $changes->requestByCode($identity, 'email', self::NEW_EMAIL, $proof, self::requestClient()),
        );

        self::assertSame(IdentifierChangeRequestStatus::REAUTHENTICATION_REQUIRED, $request->status);
    }

    /**
     * A request proven by the identity's password takes a sign-in slot of the
     * account and of the IP address (an update, then an insert, each), reads
     * the identity again through the provider, and gives the two slots back,
     * besides what the request itself runs (the identity's row read, then
     * locked, the pending change read, and the code and change written); it
     * returns as soon as the password is known to be right.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARequestProvenByThePasswordHasAFixedBudget(): void
    {
        config()->set('authentication.timebox.credentials_microseconds', self::TIMEBOX_MICROSECONDS);

        $identity = self::seedChangeable();
        $proof    = Reauthentication::password(self::PASSWORD);
        $changes  = Auth::identifierChanges('web');
        $started  = hrtime(true);
        $request  = $this->assertQueryBudget(
            4,
            14,
            static fn (): IdentifierChangeRequest => $changes->requestByCode($identity, 'email', self::NEW_EMAIL, $proof, self::requestClient()),
        );
        $elapsed = hrtime(true) - $started;

        self::assertTrue($request->isSent());
        self::assertLessThan(self::TIMEBOX_MICROSECONDS * 1000, $elapsed);
    }

    /**
     * A request with a wrong password takes the sign-in slots and reads the
     * identity, keeps the slots, writes nothing else, and waits out the
     * credential timebox.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARequestWithAWrongPasswordHasAFixedBudgetAndWaitsOutTheTimebox(): void
    {
        config()->set('authentication.timebox.credentials_microseconds', self::TIMEBOX_MICROSECONDS);

        $identity = self::seedChangeable();
        $proof    = Reauthentication::password('not the password');
        $changes  = Auth::identifierChanges('web');
        $started  = hrtime(true);
        $request  = $this->assertQueryBudget(
            2,
            4,
            static fn (): IdentifierChangeRequest => $changes->requestByCode($identity, 'email', self::NEW_EMAIL, $proof, self::requestClient()),
        );
        $elapsed = hrtime(true) - $started;

        self::assertSame(IdentifierChangeRequestStatus::REAUTHENTICATION_REQUIRED, $request->status);
        self::assertGreaterThanOrEqual(self::TIMEBOX_MICROSECONDS * 1000, $elapsed);
    }

    /**
     * Once the account has no sign-in slot left, a request with a password
     * stops at the limiter, which tries its counters and reads how long to
     * wait, without reading the identity or checking the password, and still
     * waits out the credential timebox.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARateLimitedPasswordStopsAtTheLimiterAndWaitsOutTheTimebox(): void
    {
        $identity = self::seedChangeable();
        $changes  = Auth::identifierChanges('web');

        foreach (range(1, 5) as $attempt) {
            $changes->requestByCode($identity, 'email', self::NEW_EMAIL, Reauthentication::password("wrong {$attempt}"), self::requestClient());
        }

        config()->set('authentication.timebox.credentials_microseconds', self::TIMEBOX_MICROSECONDS);

        $proof   = Reauthentication::password(self::PASSWORD);
        $started = hrtime(true);
        $request = $this->assertQueryBudget(
            2,
            3,
            static fn (): IdentifierChangeRequest => $changes->requestByCode($identity, 'email', self::NEW_EMAIL, $proof, self::requestClient()),
        );
        $elapsed = hrtime(true) - $started;

        self::assertSame(IdentifierChangeRequestStatus::RATE_LIMITED, $request->status);
        self::assertGreaterThanOrEqual(self::TIMEBOX_MICROSECONDS * 1000, $elapsed);
        self::assertSame(0, DB::table('identifier_changes')->count());
    }

    /**
     * A confirmation by code counts against the identity's account and the IP
     * address, locks the identity's row first, then reads the pending change,
     * the code and the holder of the new identifier and the row under its
     * lock; it counts the attempt, uses the code up, deletes the change,
     * invalidates the outdated proofs, writes the identifier and gives the two
     * counts back.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAConfirmationByCodeHasAFixedBudget(): void
    {
        $identity = self::seedChangeable();
        $changes  = Auth::identifierChanges('web');

        $changes->requestByCode($identity, 'email', self::NEW_EMAIL, Reauthentication::password(self::PASSWORD), self::requestClient());

        $challenge = self::changeChallenge($identity, 'email');
        $outcome   = $this->assertQueryBudget(
            5,
            9,
            static fn (): IdentifierChangeOutcome => $changes->confirmByCode($identity, 'email', $challenge, '135790', self::requestClient())->outcome,
        );

        self::assertSame(IdentifierChangeOutcome::CHANGED, $outcome);
    }

    /**
     * A confirmation by link adds the identity's load through the guard's
     * provider, and checks no code.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAConfirmationByLinkHasAFixedBudget(): void
    {
        $identity = self::seedChangeable();
        $changes  = Auth::identifierChanges('web');
        $link     = (string) $changes->requestByLink(
            $identity,
            'email',
            self::NEW_EMAIL,
            Reauthentication::password(self::PASSWORD),
            'confirm',
            self::requestClient(),
        )->link()?->reveal();

        $outcome = $this->assertQueryBudget(5, 3, static fn (): IdentifierChangeOutcome => $changes->confirmByLink(Request::create($link))->outcome);

        self::assertSame(IdentifierChangeOutcome::CHANGED, $outcome);
    }

    /**
     * A change of password of an identity whose identifiers can change, with
     * two changes pending, cancels them both in one `DELETE`, beside the
     * password's `UPDATE`, the read of its row, the `UPDATE` that ends the
     * codes it outdates and the read of its sessions.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testANewPasswordCancelsThePendingChangesInOneStatement(): void
    {
        $identity = self::seedChangeable(self::EMAIL, self::PHONE);
        $changes  = Auth::identifierChanges('web');

        $changes->requestByLink($identity, 'email', self::NEW_EMAIL, Reauthentication::password(self::PASSWORD), 'confirm', self::requestClient());
        $changes->requestByLink($identity, 'phone', self::NEW_PHONE, Reauthentication::password(self::PASSWORD), 'confirm', self::requestClient());

        $passwords = Auth::passwords('web');
        $result    = $this->assertQueryBudget(
            2,
            3,
            static fn (): PasswordResult => $passwords->set($identity, 'a brand new passphrase', PasswordFlow::CHANGE, self::requestClient()),
        );

        self::assertTrue($result->isSet());
        self::assertSame(0, DB::table('identifier_changes')->count());
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

        self::configureChangeGuards($app->make(ConfigRepository::class));
    }

    /**
     * Define the route change links point at.
     *
     * @param  mixed  $router
     * @return void
     */
    #[\Override]
    protected function defineRoutes(mixed $router): void
    {
        assert($router instanceof Router);

        $router->get('/confirm', static fn (): string => 'ok')->name('confirm');
    }
}
