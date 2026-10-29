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
use SineMacula\Laravel\Authentication\IdentifierChanges\IdentifierChangeRequest;
use SineMacula\Laravel\Authentication\IdentifierChanges\IdentifierChangeService;
use SineMacula\Laravel\Authentication\Passwords\Enums\PasswordFlow;
use SineMacula\Laravel\Authentication\Passwords\OutdatedProofs;
use SineMacula\Laravel\Authentication\Passwords\PasswordResult;
use SineMacula\Laravel\Authentication\Sessions\Reauthentication;
use SineMacula\Laravel\Authentication\Testing\FakeIdentifierChangeNotifier;
use SineMacula\Laravel\Authentication\Testing\FakeOneTimeCodeSender;
use Tests\Concerns\InteractsWithChangeableIdentities;

/**
 * Query-budget contracts for changing identifiers: a request and a confirmation
 * each cost a fixed number of statements, whatever proves them, and a new
 * password cancels every pending change in one.
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
final class IdentifierChangeQueryBudgetTest extends PerformanceContractTestCase
{
    use InteractsWithChangeableIdentities;

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
     * A first request proven by a confirmation time reads the identifier from
     * the identity in hand, counts the limits (an update, then an insert, for
     * each of the identifier, the identity and the IP address), issues the code
     * (an update, then an insert), reads the pending change it would replace,
     * and writes its own (an update, then an insert).
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARequestByCodeHasAFixedBudget(): void
    {
        $identity = self::seedChangeable();
        $changes  = Auth::identifierChanges('web');

        $proof   = Reauthentication::confirmedAt(now());
        $request = $this->assertQueryBudget(1, 10, static fn (): IdentifierChangeRequest => $changes->requestByCode($identity, 'email', self::NEW_EMAIL, $proof));

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
        $proof    = Reauthentication::confirmedAt(now());

        $changes->requestByLink($identity, 'email', 'ada@first.example.test', $proof, 'confirm');

        $request = $this->assertQueryBudget(1, 6, static fn (): IdentifierChangeRequest => $changes->requestByLink($identity, 'email', self::NEW_EMAIL, $proof, 'confirm'));

        self::assertTrue($request->isSent());
    }

    /**
     * A confirmation by code locks the identity's row first, then reads the
     * pending change, the code and the holder of the new identifier and the row
     * under its lock; it counts the attempt, uses the code up, deletes the
     * change, invalidates the outdated proofs and writes the identifier.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAConfirmationByCodeHasAFixedBudget(): void
    {
        $identity = self::seedChangeable();
        $changes  = Auth::identifierChanges('web');

        $changes->requestByCode($identity, 'email', self::NEW_EMAIL, Reauthentication::confirmedAt(now()));

        $outcome = $this->assertQueryBudget(5, 5, static fn (): IdentifierChangeOutcome => $changes->confirmByCode($identity, 'email', '135790'));

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
        $link     = (string) $changes->requestByLink($identity, 'email', self::NEW_EMAIL, Reauthentication::confirmedAt(now()), 'confirm')->link();

        $outcome = $this->assertQueryBudget(5, 3, static fn (): IdentifierChangeOutcome => $changes->confirmByLink(Request::create($link)));

        self::assertSame(IdentifierChangeOutcome::CHANGED, $outcome);
    }

    /**
     * A change of password of an identity whose identifiers can change, with
     * two changes pending, cancels them both in one `DELETE`, beside the
     * password's `UPDATE`, the read of its row, the `DELETE` of the codes it
     * outdates, the read of its devices and the end of its pending sign-ins.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testANewPasswordCancelsThePendingChangesInOneStatement(): void
    {
        $identity = self::seedChangeable(self::EMAIL, self::PHONE);
        $changes  = Auth::identifierChanges('web');

        $changes->requestByLink($identity, 'email', self::NEW_EMAIL, Reauthentication::confirmedAt(now()), 'confirm');
        $changes->requestByLink($identity, 'phone', self::NEW_PHONE, Reauthentication::confirmedAt(now()), 'confirm');

        $passwords = Auth::passwords('web');
        $result    = $this->assertQueryBudget(2, 4, static fn (): PasswordResult => $passwords->set($identity, 'a brand new passphrase', PasswordFlow::CHANGE));

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
