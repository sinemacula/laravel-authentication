<?php

declare(strict_types = 1);

namespace Tests\Feature\IdentifierChanges;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Events\Dispatcher;
use Illuminate\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Queue;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\URL;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Codes\CodeBinding;
use SineMacula\Laravel\Authentication\Codes\OneTimeCodes;
use SineMacula\Laravel\Authentication\Contracts\IdentifierChangeNotifier;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\Enums\AuthenticationFlow;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\IdentifierChanged;
use SineMacula\Laravel\Authentication\Events\IdentifierChangeRequested;
use SineMacula\Laravel\Authentication\Events\IdentifierVerified;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Http\SignedLink;
use SineMacula\Laravel\Authentication\IdentifierChanges\ChangeConfirmation;
use SineMacula\Laravel\Authentication\IdentifierChanges\ChangeLinks;
use SineMacula\Laravel\Authentication\IdentifierChanges\ChangeRefused;
use SineMacula\Laravel\Authentication\IdentifierChanges\Enums\IdentifierChangeOutcome;
use SineMacula\Laravel\Authentication\IdentifierChanges\IdentifierChangeNotice;
use SineMacula\Laravel\Authentication\IdentifierChanges\IdentifierChangeService;
use SineMacula\Laravel\Authentication\IdentifierChanges\PendingChanges;
use SineMacula\Laravel\Authentication\IdentifierChanges\PresentedChangeLink;
use SineMacula\Laravel\Authentication\IdentifierChanges\SendIdentifierChangeNotice;
use SineMacula\Laravel\Authentication\Passwords\Enums\PasswordFlow;
use SineMacula\Laravel\Authentication\Passwords\OutdatedProofs;
use SineMacula\Laravel\Authentication\Verification\Enums\VerificationLinkOutcome;
use SineMacula\Laravel\Authentication\Verification\VerificationLinks;
use Tests\Concerns\ChangesIdentifiers;
use Tests\Concerns\InspectsTraces;
use Tests\Fixtures\Events\EventContextAssertions;
use Tests\Integration\Fixtures\ChangeableIdentity;
use Tests\Integration\Fixtures\SuspendableChangeableIdentity;
use Tests\TestCase;

/**
 * Feature tests for confirming a change of identifier by code and by signed
 * link.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(IdentifierChangeService::class)]
#[CoversClass(ChangeConfirmation::class)]
#[CoversClass(ChangeLinks::class)]
#[CoversClass(ChangeRefused::class)]
#[CoversClass(PendingChanges::class)]
#[CoversClass(PresentedChangeLink::class)]
#[CoversClass(SendIdentifierChangeNotice::class)]
#[CoversClass(IdentifierChangeNotice::class)]
#[CoversClass(OutdatedProofs::class)]
final class IdentifierChangeConfirmationTest extends TestCase
{
    use ChangesIdentifiers, InspectsTraces;

    /**
     * Freeze the clock and bind the fakes and the routes links point at.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->startChanging();

        Route::get('/email/confirm', static fn (): string => 'ok')->name('email.confirm');
        Route::get('/email/verify', static fn (): string => 'ok')->name('email.verify');
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
     * The right code replaces the identifier, uses the code up, reports the
     * change and notifies the old one.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheRightCodeMakesTheChange(): void
    {
        $identity = $this->requestedByCode();

        $this->recordEvents([IdentifierChanged::class, IdentifierVerified::class, AuthenticationFailed::class]);
        $this->moveTo($this->now->addMinute());

        self::assertSame(
            IdentifierChangeOutcome::CHANGED,
            $this->changes()->confirmByCode($identity, 'email', self::changeChallenge($identity, 'email'), self::CODE, self::requestClient())->outcome,
        );

        $row = (array) DB::table('changeable_identities')->first();

        self::assertSame([self::NEW_EMAIL, '2026-04-06 12:01:00', '2026-04-06 12:01:00'], [$row['email'], $row['email_verified_at'], $row['updated_at']]);
        self::assertSame(self::NEW_EMAIL, $identity->email);
        self::assertSame(0, DB::table('identifier_changes')->count());
        self::assertNotNull(DB::table('one_time_codes')->value('consumed_at'));
        self::assertSame([IdentifierChanged::class], $this->recordedClasses());

        $event = $this->recordedEvent(IdentifierChanged::class);

        self::assertSame(['web', 'email'], [$event->context->guard, $event->type]);
        EventContextAssertions::assertIdentity($identity, $event->context);
        self::assertSame([self::EMAIL, self::NEW_EMAIL], [$event->previous, $event->identifier]);
        self::assertTrue($this->now->addMinute()->equalTo($event->changedAt));

        Queue::assertPushed(SendIdentifierChangeNotice::class, 1);

        $this->runQueued(SendIdentifierChangeNotice::class);

        $notices = $this->notifier->noticesFor($identity);

        self::assertCount(1, $notices);
        $notice = $notices[0];

        self::assertSame(['web', 'email', self::EMAIL, true, self::NEW_EMAIL], [$notice->guard, $notice->type, $notice->previous, $notice->previousVerified, $notice->identifier]);
        self::assertTrue($this->now->addMinute()->equalTo($notice->changedAt));
    }

    /**
     * The notice says whether the old identifier was verified when the change
     * was requested.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheNoticeSaysWhetherTheOldIdentifierWasVerified(): void
    {
        $identity = self::seedChangeable(self::EMAIL, self::PHONE);

        DB::table('changeable_identities')->update(['phone_verified_at' => null]);

        $identity->refresh();

        self::assertTrue($this->changes()->requestByCode($identity, 'phone', self::NEW_PHONE, self::freshSession($identity), self::requestClient())->isSent());
        self::assertSame([false], DB::table('identifier_changes')->pluck('previous_verified')->map(static fn (mixed $value): bool => (bool) $value)->all());
        self::assertSame(
            IdentifierChangeOutcome::CHANGED,
            $this->changes()->confirmByCode($identity, 'phone', self::changeChallenge($identity, 'phone'), self::CODE, self::requestClient())->outcome,
        );

        $this->runQueued(SendIdentifierChangeNotice::class);

        $notices = $this->notifier->noticesFor($identity);

        self::assertCount(1, $notices);
        self::assertSame([self::PHONE, false, self::NEW_PHONE], [$notices[0]->previous, $notices[0]->previousVerified, $notices[0]->identifier]);
    }

    /**
     * A wrong code is refused and its attempt kept, while a malformed one
     * counts none.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAWrongCodeIsRefusedAndCounted(): void
    {
        $identity = $this->requestedByCode();

        $this->recordEvents([AuthenticationFailed::class]);

        self::assertSame(
            IdentifierChangeOutcome::INVALID,
            $this->changes()->confirmByCode($identity, 'email', self::changeChallenge($identity, 'email'), '000000', self::requestClient())->outcome,
        );
        self::assertSame(
            IdentifierChangeOutcome::INVALID,
            $this->changes()->confirmByCode($identity, 'email', self::changeChallenge($identity, 'email'), '12345', self::requestClient())->outcome,
        );
        self::assertSame(1, self::codeAttempts());
        self::assertSame(1, DB::table('identifier_changes')->count());
        self::assertSame(self::EMAIL, $identity->fresh()?->email);
        self::assertSame(
            [[AuthenticationFlow::IDENTIFIER_CHANGE, FailureReason::INVALID_CREDENTIALS, null], [AuthenticationFlow::IDENTIFIER_CHANGE, FailureReason::INVALID_CREDENTIALS, null]],
            array_map(static fn (AuthenticationFailed $event): array => [$event->flow, $event->reason, $event->identifier], $this->failures()),
        );
        self::assertSame(array_fill(0, 2, self::changeChallenge($identity, 'email')), $this->failedChallenges());
        EventContextAssertions::assertIdentity($identity, $this->failures()[0]->context);
        self::assertSame(
            IdentifierChangeOutcome::CHANGED,
            $this->changes()->confirmByCode($identity, 'email', self::changeChallenge($identity, 'email'), self::CODE, self::requestClient())->outcome,
        );
    }

    /**
     * A confirmation names its challenge, and another challenge's id spends no
     * attempt on the live one.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAConfirmationNamesItsChallenge(): void
    {
        $identity  = self::seedChangeable(self::EMAIL, self::PHONE);
        $challenge = $this->changes()->requestByCode($identity, 'email', self::NEW_EMAIL, self::freshSession($identity), self::requestClient())->challengeId;

        self::assertIsString($challenge);
        self::assertSame($challenge, self::changeChallenge($identity, 'email'));

        $hits = (int) DB::table('rate_limits')->sum('hits');

        $this->recordEvents([AuthenticationFailed::class]);

        self::assertSame(IdentifierChangeOutcome::INVALID, $this->changes()->confirmByCode($identity, 'email', strtoupper($challenge), self::CODE, self::requestClient())->outcome);
        self::assertSame($hits + 2, (int) DB::table('rate_limits')->sum('hits'));
        self::assertSame(IdentifierChangeOutcome::INVALID, $this->changes()->confirmByCode($identity, 'email', self::NO_CHALLENGE, self::CODE, self::requestClient())->outcome);
        self::assertSame(0, self::codeAttempts());
        self::assertSame([null, self::NO_CHALLENGE], $this->failedChallenges());
        self::assertSame(IdentifierChangeOutcome::CHANGED, $this->changes()->confirmByCode($identity, 'email', $challenge, self::CODE, self::requestClient())->outcome);
    }

    /**
     * Confirmations are limited per identity and IP address, and a confirmed
     * change gives its slots back.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testConfirmationsAreLimitedPerIdentityAndIp(): void
    {
        $identity  = $this->requestedByCode();
        $challenge = self::changeChallenge($identity, 'email');
        $hits      = (int) DB::table('rate_limits')->sum('hits');

        self::assertSame(IdentifierChangeOutcome::INVALID, $this->changes()->confirmByCode($identity, 'email', $challenge, '000000', self::requestClient())->outcome);
        self::assertSame($hits + 2, (int) DB::table('rate_limits')->sum('hits'));
        self::assertSame(IdentifierChangeOutcome::CHANGED, $this->changes()->confirmByCode($identity, 'email', $challenge, self::CODE, self::requestClient())->outcome);
        self::assertSame($hits + 2, (int) DB::table('rate_limits')->sum('hits'));

        config()->set('authentication.rate_limits.identifier_change.per_identifier', ['max' => 1, 'decay_seconds' => 3600]);

        $this->recordEvents([AuthenticationFailed::class]);

        self::assertSame(IdentifierChangeOutcome::RATE_LIMITED, $this->changes()->confirmByCode($identity, 'email', $challenge, self::CODE, self::requestClient())->outcome);
        self::assertSame(
            [[AuthenticationFlow::IDENTIFIER_CHANGE, FailureReason::RATE_LIMITED]],
            array_map(static fn (AuthenticationFailed $event): array => [$event->flow, $event->reason], $this->failures()),
        );
        self::assertGreaterThan(0, $this->failures()[0]->retryAfter);
        self::assertSame($challenge, $this->failures()[0]->challengeId);
    }

    /**
     * Exhausted and expired codes, and an expired change, are refused as such.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testExhaustedAndExpiredProofsAreRefused(): void
    {
        config()->set('authentication.codes.max_attempts', 1);

        $identity = $this->requestedByCode();

        $this->recordEvents([AuthenticationFailed::class]);

        $this->changes()->confirmByCode($identity, 'email', self::changeChallenge($identity, 'email'), '000000', self::requestClient());

        self::assertSame(
            IdentifierChangeOutcome::EXHAUSTED,
            $this->changes()->confirmByCode($identity, 'email', self::changeChallenge($identity, 'email'), self::CODE, self::requestClient())->outcome,
        );

        DB::table('one_time_codes')->update(['attempts' => 0, 'expires_at' => '2026-04-06 12:00:00']);

        self::assertSame(
            IdentifierChangeOutcome::EXPIRED,
            $this->changes()->confirmByCode($identity, 'email', self::changeChallenge($identity, 'email'), self::CODE, self::requestClient())->outcome,
        );

        DB::table('one_time_codes')->update(['expires_at' => '2026-04-06 12:10:00']);

        $this->moveTo($this->now->addSeconds(600));

        self::assertSame(
            IdentifierChangeOutcome::EXPIRED,
            $this->changes()->confirmByCode($identity, 'email', self::changeChallenge($identity, 'email'), self::CODE, self::requestClient())->outcome,
        );
        self::assertSame(
            [FailureReason::INVALID_CREDENTIALS, FailureReason::CODE_EXHAUSTED, FailureReason::CODE_EXPIRED, FailureReason::CODE_EXPIRED],
            array_map(static fn (AuthenticationFailed $event): FailureReason => $event->reason, $this->failures()),
        );
        self::assertSame(array_fill(0, 4, self::changeChallenge($identity, 'email')), $this->failedChallenges());
        self::assertSame(self::EMAIL, $identity->fresh()?->email);
    }

    /**
     * Only the newest request's code confirms the change.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnEarlierRequestsCodeConfirmsNothing(): void
    {
        $identity = $this->requestedByCode();

        $this->changes()->requestByCode($identity, 'email', 'ada@third.example.test', self::freshSession($identity), self::requestClient());

        self::assertSame(
            IdentifierChangeOutcome::INVALID,
            $this->changes()->confirmByCode($identity, 'email', self::changeChallenge($identity, 'email'), self::CODE, self::requestClient())->outcome,
        );
        self::assertSame(
            IdentifierChangeOutcome::CHANGED,
            $this->changes()->confirmByCode($identity, 'email', self::changeChallenge($identity, 'email'), '246802', self::requestClient())->outcome,
        );
        self::assertSame('ada@third.example.test', $identity->email);
    }

    /**
     * A change pending through another guard is not confirmed through this one.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnotherGuardsChangeIsNotConfirmed(): void
    {
        $identity = $this->requestedByCode();

        self::assertSame(
            IdentifierChangeOutcome::INVALID,
            $this->changes('admin')->confirmByCode($identity, 'email', self::changeChallenge($identity, 'email'), self::CODE, self::requestClient())->outcome,
        );
        self::assertSame([1, 0], [self::rows('identifier_changes'), self::codeAttempts()]);
        self::assertSame(
            IdentifierChangeOutcome::INVALID,
            $this->changes()->confirmByCode($identity, 'phone', self::changeChallenge($identity, 'phone'), self::CODE, self::requestClient())->outcome,
        );
    }

    /**
     * A change is confirmed once: a second confirmation finds nothing pending.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAChangeIsConfirmedOnce(): void
    {
        $identity = $this->requestedByCode();

        self::assertSame(
            IdentifierChangeOutcome::CHANGED,
            $this->changes()->confirmByCode($identity, 'email', self::changeChallenge($identity, 'email'), self::CODE, self::requestClient())->outcome,
        );
        self::assertSame(
            IdentifierChangeOutcome::INVALID,
            $this->changes()->confirmByCode($identity, 'email', self::changeChallenge($identity, 'email'), self::CODE, self::requestClient())->outcome,
        );
    }

    /**
     * A newer request landing during the confirmation wins, and the
     * confirmation rolls back unspent.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testANewerRequestLandingDuringTheConfirmationWins(): void
    {
        $identity = $this->requestedByCode();
        $raced    = false;

        DB::connection()->beforeExecuting(static function (string $query) use (&$raced): void {
            if ($raced || preg_match('/^delete from [`"]identifier_changes[`"]/', $query) !== 1) {
                return;
            }

            $raced = true;

            DB::table('identifier_changes')->update(['request_id' => '0195f4a2-7b1c-4000-8000-000000000001']);
        });

        self::assertSame(
            IdentifierChangeOutcome::INVALID,
            $this->changes()->confirmByCode($identity, 'email', self::changeChallenge($identity, 'email'), self::CODE, self::requestClient())->outcome,
        );
        self::assertTrue($raced);
        self::assertSame(self::EMAIL, $identity->fresh()?->email);
        self::assertSame([1, null], [DB::table('identifier_changes')->count(), DB::table('one_time_codes')->value('consumed_at')]);
    }

    /**
     * An identifier another identity holds is taken, and the proof is not
     * spent.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnIdentifierAnotherIdentityHoldsIsTaken(): void
    {
        $identity = $this->requestedByCode();
        $holder   = self::seedChangeable(self::NEW_EMAIL);

        $this->recordEvents([AuthenticationFailed::class, IdentifierChanged::class]);

        self::assertSame(
            IdentifierChangeOutcome::TAKEN,
            $this->changes()->confirmByCode($identity, 'email', self::changeChallenge($identity, 'email'), self::CODE, self::requestClient())->outcome,
        );
        self::assertSame([AuthenticationFailed::class], $this->recordedClasses());
        self::assertSame(FailureReason::IDENTIFIER_TAKEN, $this->recordedEvent(AuthenticationFailed::class)->reason);
        self::assertSame([1, 0], [self::rows('identifier_changes'), self::codeAttempts()]);
        self::assertNull(DB::table('one_time_codes')->value('consumed_at'));
        self::assertSame(self::EMAIL, $identity->fresh()?->email);
        Queue::assertNotPushed(SendIdentifierChangeNotice::class);

        DB::table('changeable_identities')->where('id', $holder->getKey())->update(['email' => 'moved@example.test']);

        self::assertSame(
            IdentifierChangeOutcome::CHANGED,
            $this->changes()->confirmByCode($identity, 'email', self::changeChallenge($identity, 'email'), self::CODE, self::requestClient())->outcome,
        );
    }

    /**
     * Without a unique index the provider's check alone refuses an identifier
     * another identity holds.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheProvidersCheckRefusesAHolderWithoutAUniqueIndex(): void
    {
        self::dropChangeableIdentitiesTable();
        self::createChangeableIdentitiesTable(unique: false);

        $identity = $this->requestedByCode();

        self::seedChangeable(self::NEW_EMAIL);

        self::assertSame(
            IdentifierChangeOutcome::TAKEN,
            $this->changes()->confirmByCode($identity, 'email', self::changeChallenge($identity, 'email'), self::CODE, self::requestClient())->outcome,
        );
        self::assertSame(1, DB::table('changeable_identities')->where('email', self::NEW_EMAIL)->count());
    }

    /**
     * An identity that already holds its new identifier makes the change
     * invalid, not taken.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheIdentityItselfHoldingTheIdentifierIsNotTaken(): void
    {
        $identity = $this->requestedByCode();

        DB::table('changeable_identities')->update(['email' => self::NEW_EMAIL]);

        $this->recordEvents([AuthenticationFailed::class]);

        self::assertSame(
            IdentifierChangeOutcome::INVALID,
            $this->changes()->confirmByCode($identity, 'email', self::changeChallenge($identity, 'email'), self::CODE, self::requestClient())->outcome,
        );
        self::assertSame(FailureReason::INVALID_CREDENTIALS, $this->failures()[0]->reason);
    }

    /**
     * The unique index decides a race for the identifier, rolling the change
     * back whole.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheUniqueIndexDecidesARaceForTheIdentifier(): void
    {
        $identity = $this->requestedByCode();
        $raced    = false;

        DB::connection()->beforeExecuting(static function (string $query) use (&$raced): void {
            if ($raced || preg_match('/^select [`"]email[`"] from [`"]changeable_identities[`"]/', $query) !== 1) {
                return;
            }

            $raced = true;

            DB::table('changeable_identities')->insert(['email' => self::NEW_EMAIL, 'password' => 'unused']);
        });

        DB::beginTransaction();

        try {
            self::assertSame(
                IdentifierChangeOutcome::TAKEN,
                $this->changes()->confirmByCode($identity, 'email', self::changeChallenge($identity, 'email'), self::CODE, self::requestClient())->outcome,
            );
            self::assertSame(1, DB::table('identifier_changes')->count());
        } finally {
            DB::rollBack();
        }

        self::assertTrue($raced);
        self::assertSame(self::EMAIL, $identity->fresh()?->email);
        self::assertNull(DB::table('one_time_codes')->value('consumed_at'));
    }

    /**
     * An identifier changed by another path since the request is kept, and the
     * proof is not spent.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnIdentifierChangedMeanwhileIsKept(): void
    {
        $identity = $this->requestedByCode();

        DB::table('changeable_identities')->update(['email' => 'support@example.test']);

        self::assertSame(
            IdentifierChangeOutcome::INVALID,
            $this->changes()->confirmByCode($identity, 'email', self::changeChallenge($identity, 'email'), self::CODE, self::requestClient())->outcome,
        );
        self::assertSame('support@example.test', DB::table('changeable_identities')->value('email'));
        self::assertSame([1, null], [DB::table('identifier_changes')->count(), DB::table('one_time_codes')->value('consumed_at')]);
    }

    /**
     * A confirmation inside a transaction the caller rolls back changes,
     * reports and notifies nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACallerRollbackUndoesTheChange(): void
    {
        $identity = $this->requestedByCode();

        $this->recordEvents([IdentifierChanged::class]);

        DB::beginTransaction();

        self::assertSame(
            IdentifierChangeOutcome::CHANGED,
            $this->changes()->confirmByCode($identity, 'email', self::changeChallenge($identity, 'email'), self::CODE, self::requestClient())->outcome,
        );

        DB::rollBack();

        self::assertSame([], $this->recorded);
        Queue::assertNotPushed(SendIdentifierChangeNotice::class);
        self::assertSame(self::EMAIL, DB::table('changeable_identities')->value('email'));
        self::assertSame(1, DB::table('identifier_changes')->count());
    }

    /**
     * Every event reaches the dispatcher the guard has when the commit runs.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testEveryReportReachesTheDispatcherBoundAtTheCommit(): void
    {
        $identity = self::seedChangeable(self::EMAIL, self::PHONE);
        $guard    = $this->freshGuard('web');
        $changes  = Auth::manager()->identifierChanges('web');
        $swapped  = new Dispatcher(app());
        $last     = new Dispatcher(app());
        $received = ['swapped' => [], 'last' => []];

        foreach (['swapped' => $swapped, 'last' => $last] as $name => $dispatcher) {
            $dispatcher->listen([IdentifierChangeRequested::class, IdentifierChanged::class], static function (object $event) use (&$received, $name): void {
                $received[$name][] = $event::class;
            });
        }

        $this->recordEvents([IdentifierChangeRequested::class, IdentifierChanged::class]);

        DB::transaction(function () use ($identity, $changes, $guard, $swapped, $last): void {
            self::assertTrue($changes->requestByCode($identity, 'email', self::NEW_EMAIL, self::freshSession($identity), self::requestClient())->isSent());

            $guard->setDispatcher($swapped);

            self::assertSame(
                IdentifierChangeOutcome::CHANGED,
                $changes->confirmByCode($identity, 'email', self::changeChallenge($identity, 'email'), self::CODE, self::requestClient())->outcome,
            );

            $guard->setDispatcher($last);
        });

        self::assertSame([], $this->recordedClasses());
        self::assertSame(['swapped' => [], 'last' => [IdentifierChangeRequested::class, IdentifierChanged::class]], $received);
    }

    /**
     * A service handed out before a dispatcher rebind reports to the dispatcher
     * bound now.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAServiceHandedOutBeforeARebindFollowsIt(): void
    {
        $identity = $this->requestedByCode();
        $guard    = $this->freshGuard('web');
        $changes  = Auth::manager()->identifierChanges('web');
        $swapped  = new Dispatcher(app());
        $received = [];

        $swapped->listen(AuthenticationFailed::class, static function (AuthenticationFailed $event) use (&$received): void {
            $received[] = $event;
        });

        $this->recordEvents([AuthenticationFailed::class]);

        $guard->setDispatcher($swapped);
        $guard->setRequest(Request::create('/', server: ['REMOTE_ADDR' => '198.51.100.9']));

        self::assertSame(
            IdentifierChangeOutcome::INVALID,
            $changes->confirmByCode($identity, 'email', self::changeChallenge($identity, 'email'), '000000', new ClientContext('198.51.100.7', null))->outcome,
        );
        self::assertSame([], $this->recorded);
        self::assertCount(1, $received);
        self::assertSame([AuthenticationFlow::IDENTIFIER_CHANGE, '198.51.100.7'], [$received[0]->flow, $received[0]->context->client->ip]);
    }

    /**
     * A confirmed change invalidates the codes of both identifiers in every jwt
     * guard over the identity's table.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAChangeInvalidatesTheProofsItOutdates(): void
    {
        $guards = config('auth.guards');

        self::assertIsArray($guards);

        config()->set('auth.guards', ['session' => ['driver' => 'session', 'provider' => 'changeables'], ...$guards, '2024' => $guards['web']]);

        $identity = $this->requestedByCode();
        $codes    = new OneTimeCodes(app(ConfigRepository::class));
        $outdated = [
            CodeBinding::signIn('web', 'email', self::EMAIL),
            CodeBinding::signIn('admin', 'email', self::NEW_EMAIL),
            CodeBinding::passwordReset('web', 'email', self::EMAIL),
            CodeBinding::passwordResetLink('admin', 'email', self::NEW_EMAIL),
            CodeBinding::verification('web', 'email', self::EMAIL, $identity),
            CodeBinding::verification('machines', 'email', self::NEW_EMAIL, $identity),
            CodeBinding::signIn('2024', 'email', self::EMAIL),
        ];
        $kept = [
            CodeBinding::signIn('web', 'email', 'other@example.test'),
            CodeBinding::signIn('web', 'phone', self::PHONE),
            CodeBinding::signIn('verifiable', 'email', self::NEW_EMAIL),
            CodeBinding::passwordResetLink('verifiable', 'email', self::EMAIL),
        ];

        foreach ([...$outdated, ...$kept] as $binding) {
            $codes->issue($binding, $this->now);
        }

        self::assertSame(
            IdentifierChangeOutcome::CHANGED,
            $this->changes()->confirmByCode($identity, 'email', self::changeChallenge($identity, 'email'), self::CODE, self::requestClient())->outcome,
        );

        $left = DB::table('one_time_codes')->whereNull('consumed_at')->pluck('id')->all();

        foreach ($outdated as $binding) {
            self::assertNotContains(self::bindingDigest($binding), $left);
        }

        foreach ($kept as $binding) {
            self::assertContains(self::bindingDigest($binding), $left);
        }

        self::assertCount(4, $left);
    }

    /**
     * An inactive identity confirms nothing by link or by code, reported as
     * `identity_inactive`.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnInactiveIdentityConfirmsNothing(): void
    {
        config()->set('auth.providers.suspendables', ['driver' => 'model', 'model' => SuspendableChangeableIdentity::class]);
        config()->set('auth.guards.suspendable', ['driver' => 'jwt', 'provider' => 'suspendables', 'application' => ['methods' => ['password', 'phone_code']]]);

        self::seedChangeable(self::EMAIL, self::PHONE);

        $identity = SuspendableChangeableIdentity::query()->sole();
        $link     = $this->changes('suspendable')->requestByLink(
            $identity,
            'email',
            self::NEW_EMAIL,
            self::freshSession($identity, 'suspendable'),
            'email.confirm',
            self::requestClient(),
        )->link()?->reveal();

        self::assertIsString($link);
        self::assertTrue(
            $this->changes('suspendable')->requestByCode($identity, 'phone', self::NEW_PHONE, self::freshSession($identity, 'suspendable'), self::requestClient())->isSent(),
        );

        DB::table('changeable_identities')->update(['is_active' => false]);

        $this->recordEvents([AuthenticationFailed::class]);

        self::assertSame(
            IdentifierChangeOutcome::INVALID,
            $this->changes('suspendable')->confirmByLink(SignedLink::fromRequest(Request::create($link)), self::requestClient(Request::create($link)))->outcome,
        );
        self::assertSame(
            IdentifierChangeOutcome::INVALID,
            $this->changes('suspendable')->confirmByCode($identity->refresh(), 'phone', self::changeChallenge($identity, 'phone'), self::CODE, self::requestClient())->outcome,
        );
        $reasons = array_map(static fn (AuthenticationFailed $event): FailureReason => $event->reason, $this->failures());

        self::assertSame([FailureReason::IDENTITY_INACTIVE, FailureReason::IDENTITY_INACTIVE], $reasons);
        self::assertSame([self::EMAIL, self::PHONE, 0, 2], [$identity->refresh()->email, $identity->phone, self::codeAttempts(), self::rows('identifier_changes')]);

        DB::table('changeable_identities')->update(['is_active' => true]);

        self::assertSame(
            IdentifierChangeOutcome::CHANGED,
            $this->changes('suspendable')->confirmByLink(SignedLink::fromRequest(Request::create($link)), self::requestClient(Request::create($link)))->outcome,
        );
        self::assertSame(
            IdentifierChangeOutcome::CHANGED,
            $this->changes('suspendable')->confirmByCode($identity->refresh(), 'phone', self::changeChallenge($identity, 'phone'), self::CODE, self::requestClient())->outcome,
        );
    }

    /**
     * The old address stored in another case loses the proofs issued for its
     * normal form.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheOldAddressStoredInAnotherCaseLosesItsProofs(): void
    {
        self::seedChangeable();

        DB::table('changeable_identities')->update(['email' => 'Ada@Example.test']);

        $identity = ChangeableIdentity::query()->sole();
        $codes    = new OneTimeCodes(app(ConfigRepository::class));
        $proofs   = [CodeBinding::signIn('web', 'email', self::EMAIL), CodeBinding::passwordResetLink('web', 'email', self::EMAIL)];

        $codes->issue($proofs[0], $this->now);
        $codes->issueToken($proofs[1], $this->now, 900);

        $live = static fn (): int => DB::table('one_time_codes')->whereIn('id', array_map(self::bindingDigest(...), $proofs))->whereNull('consumed_at')->count();

        self::assertTrue($this->changes()->requestByCode($identity, 'email', self::NEW_EMAIL, self::freshSession($identity), self::requestClient())->isSent());
        self::assertSame(2, $live());
        self::assertSame(
            IdentifierChangeOutcome::CHANGED,
            $this->changes()->confirmByCode($identity, 'email', self::changeChallenge($identity, 'email'), self::CODE, self::requestClient())->outcome,
        );
        self::assertSame(0, $live());
    }

    /**
     * An identity deactivated after it was loaded confirms nothing, read from
     * its locked row.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnIdentityDeactivatedAfterItWasLoadedConfirmsNothing(): void
    {
        config()->set('auth.providers.suspendables', ['driver' => 'model', 'model' => SuspendableChangeableIdentity::class]);
        config()->set('auth.guards.suspendable', ['driver' => 'jwt', 'provider' => 'suspendables', 'application' => ['methods' => ['password', 'phone_code']]]);

        self::seedChangeable(self::EMAIL, self::PHONE);

        $identity = SuspendableChangeableIdentity::query()->sole();
        $link     = $this->changes('suspendable')->requestByLink(
            $identity,
            'email',
            self::NEW_EMAIL,
            self::freshSession($identity, 'suspendable'),
            'email.confirm',
            self::requestClient(),
        )->link()?->reveal();

        self::assertIsString($link);
        self::assertTrue(
            $this->changes('suspendable')->requestByCode($identity, 'phone', self::NEW_PHONE, self::freshSession($identity, 'suspendable'), self::requestClient())->isSent(),
        );

        $this->recordEvents([AuthenticationFailed::class]);

        DB::table('changeable_identities')->update(['is_active' => false]);

        self::assertTrue($identity->isActive());
        self::assertSame(
            IdentifierChangeOutcome::INVALID,
            $this->changes('suspendable')->confirmByCode($identity, 'phone', self::changeChallenge($identity, 'phone'), self::CODE, self::requestClient())->outcome,
        );

        DB::table('changeable_identities')->update(['is_active' => true]);

        $deactivated = false;

        DB::listen(static function (QueryExecuted $query) use (&$deactivated): void {
            if ($deactivated || !str_starts_with($query->sql, 'select') || !str_contains($query->sql, 'changeable_identities')) {
                return;
            }

            $deactivated = true;

            DB::table('changeable_identities')->update(['is_active' => false]);
        });

        self::assertSame(
            IdentifierChangeOutcome::INVALID,
            $this->changes('suspendable')->confirmByLink(SignedLink::fromRequest(Request::create($link)), self::requestClient(Request::create($link)))->outcome,
        );
        self::assertTrue($deactivated);

        $reasons = array_map(static fn (AuthenticationFailed $event): FailureReason => $event->reason, $this->failures());

        self::assertSame([FailureReason::IDENTITY_INACTIVE, FailureReason::IDENTITY_INACTIVE], $reasons);
        self::assertSame([self::EMAIL, self::PHONE, 0, 2], [$identity->refresh()->email, $identity->phone, self::codeAttempts(), self::rows('identifier_changes')]);
    }

    /**
     * A failed confirmation leaves the code out of every frame of its trace.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFailedConfirmationLeavesTheCodeOutOfTheTrace(): void
    {
        $identity  = $this->requestedByCode();
        $challenge = self::changeChallenge($identity, 'email');

        DB::listen(static function (QueryExecuted $query): void {
            if (str_starts_with($query->sql, 'update') && str_contains($query->sql, 'one_time_codes')) {
                throw new \RuntimeException('the store failed');
            }
        });

        $exception = self::withArgumentsInTraces(
            \RuntimeException::class,
            fn (): mixed => $this->changes()->confirmByCode($identity, 'email', $challenge, self::CODE, self::requestClient())->outcome,
        );

        self::assertSame('the store failed', $exception->getMessage());
        self::assertFalse(self::hasInTrace($exception, self::CODE));
        self::assertSame([self::EMAIL, 1], [$identity->refresh()->email, self::rows('identifier_changes')]);
    }

    /**
     * An identity no longer stored confirms nothing, with no attempt counted.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnIdentityNoLongerStoredConfirmsNothing(): void
    {
        $identity = $this->requestedByCode();

        DB::table('changeable_identities')->delete();

        $this->recordEvents([AuthenticationFailed::class]);

        self::assertSame(
            IdentifierChangeOutcome::INVALID,
            $this->changes()->confirmByCode($identity, 'email', self::changeChallenge($identity, 'email'), self::CODE, self::requestClient())->outcome,
        );
        self::assertSame([FailureReason::INVALID_CREDENTIALS], array_map(static fn (AuthenticationFailed $event): FailureReason => $event->reason, $this->failures()));
        self::assertSame([0, 1], [self::codeAttempts(), self::rows('identifier_changes')]);
    }

    /**
     * The new password flows that end the identity's sessions.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Authentication\Passwords\Enums\PasswordFlow}>
     */
    public static function provideSecurityChanges(): iterable
    {
        yield from [
            'change' => [PasswordFlow::CHANGE],
            'reset'  => [PasswordFlow::RESET],
        ];
    }

    /**
     * A new password cancels every identifier change the identity has pending.
     *
     * @param  \SineMacula\Laravel\Authentication\Passwords\Enums\PasswordFlow  $flow
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideSecurityChanges')]
    public function testANewPasswordCancelsEveryPendingChange(PasswordFlow $flow): void
    {
        $identity = self::seedChangeable(self::EMAIL, self::PHONE);
        $other    = self::seedChangeable('grace@example.test');
        $link     = $this->changes()->requestByLink($identity, 'email', self::NEW_EMAIL, self::freshSession($identity), 'email.confirm', self::requestClient())->link()?->reveal();

        self::assertIsString($link);
        self::assertTrue($this->changes('admin')->requestByCode($identity, 'phone', self::NEW_PHONE, self::freshSession($identity, 'admin'), self::requestClient())->isSent());
        self::assertTrue($this->changes()->requestByCode($other, 'email', 'grace@new.example.test', self::freshSession($other), self::requestClient())->isSent());

        self::assertTrue(Auth::passwords('web')->set($identity, 'a brand new passphrase', $flow, self::requestClient())->set);
        self::assertSame(1, self::rows('identifier_changes'));

        self::assertSame(
            IdentifierChangeOutcome::INVALID,
            $this->changes()->confirmByLink(SignedLink::fromRequest(Request::create($link)), self::requestClient(Request::create($link)))->outcome,
        );
        self::assertSame(
            IdentifierChangeOutcome::INVALID,
            $this->changes('admin')->confirmByCode($identity, 'phone', self::changeChallenge($identity, 'phone'), self::CODE, self::requestClient())->outcome,
        );
        self::assertSame([self::EMAIL, self::PHONE], [$identity->fresh()?->email, $identity->fresh()?->phone]);
        self::assertSame(
            IdentifierChangeOutcome::CHANGED,
            $this->changes()->confirmByCode($other, 'email', self::changeChallenge($other, 'email'), '246802', self::requestClient())->outcome,
        );
    }

    /**
     * A registration ends no session, so it keeps the pending change.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARegistrationKeepsThePendingChange(): void
    {
        [$identity, $link] = $this->requestedByLink();

        DB::table('changeable_identities')->update(['password' => null]);

        self::assertTrue(Auth::passwords('web')->set($identity->fresh() ?? $identity, 'a brand new passphrase', PasswordFlow::REGISTRATION, self::requestClient())->set);
        self::assertSame(
            IdentifierChangeOutcome::CHANGED,
            $this->changes()->confirmByLink(SignedLink::fromRequest(Request::create($link)), self::requestClient(Request::create($link)))->outcome,
        );
    }

    /**
     * A verification link signed for the old identifier verifies nothing once
     * it is replaced.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAVerificationLinkForTheOldIdentifierIsDead(): void
    {
        $identity = $this->requestedByCode();
        $link     = app(VerificationLinks::class)->create('web', $identity, 'email', 'email.verify')->reveal();

        DB::table('changeable_identities')->update(['email_verified_at' => null]);

        self::assertSame(
            IdentifierChangeOutcome::CHANGED,
            $this->changes()->confirmByCode($identity, 'email', self::changeChallenge($identity, 'email'), self::CODE, self::requestClient())->outcome,
        );
        self::assertSame(
            VerificationLinkOutcome::INVALID,
            app(VerificationLinks::class)->consume(SignedLink::fromRequest(Request::create($link)), self::requestClient(Request::create($link))),
        );
    }

    /**
     * A first identifier of its type is set with no notice.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFirstIdentifierIsSetWithoutANotice(): void
    {
        $identity = self::seedChangeable(self::EMAIL, null);

        $this->recordEvents([IdentifierChanged::class]);

        $this->changes()->requestByCode($identity, 'phone', self::NEW_PHONE, self::freshSession($identity), self::requestClient());

        self::assertSame(
            IdentifierChangeOutcome::CHANGED,
            $this->changes()->confirmByCode($identity, 'phone', self::changeChallenge($identity, 'phone'), self::CODE, self::requestClient())->outcome,
        );
        self::assertSame(self::NEW_PHONE, $identity->fresh()?->phone);
        self::assertNull($this->recordedEvent(IdentifierChanged::class)->previous);
        Queue::assertNotPushed(SendIdentifierChangeNotice::class);
    }

    /**
     * A failing notifier fails its job while the change stands.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFailingNoticeLeavesTheChange(): void
    {
        $identity = $this->requestedByCode();

        $this->changes()->confirmByCode($identity, 'email', self::changeChallenge($identity, 'email'), self::CODE, self::requestClient());

        app()->instance(IdentifierChangeNotifier::class, new class implements IdentifierChangeNotifier {
            /**
             * Fail as an unreachable mail service would.
             *
             * @param  \SineMacula\Laravel\Authentication\IdentifierChanges\IdentifierChangeNotice  $notice
             * @return void
             *
             * @throws \RuntimeException
             */
            #[\Override]
            public function notify(IdentifierChangeNotice $notice): void
            {
                throw new \RuntimeException('Mail service unavailable.');
            }
        });

        try {
            $this->runQueued(SendIdentifierChangeNotice::class);
            self::fail('Expected the notice to fail.');
        } catch (\RuntimeException $e) {
            self::assertSame('Mail service unavailable.', $e->getMessage());
        }

        self::assertSame(self::NEW_EMAIL, DB::table('changeable_identities')->value('email'));
    }

    /**
     * A link confirms its change through the guard that signed it and reports
     * the client that followed it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testALinkMakesTheChange(): void
    {
        [$identity, $link] = $this->requestedByLink();

        $this->recordEvents([IdentifierChanged::class]);

        $request = Request::create($link, server: ['REMOTE_ADDR' => '198.51.100.4']);

        self::assertSame(IdentifierChangeOutcome::CHANGED, $this->changes()->confirmByLink(SignedLink::fromRequest($request), self::requestClient($request))->outcome);
        self::assertSame(self::NEW_EMAIL, DB::table('changeable_identities')->value('email'));
        self::assertSame('198.51.100.4', $this->recordedEvent(IdentifierChanged::class)->context->client->ip);
        EventContextAssertions::assertIdentity($identity, $this->recordedEvent(IdentifierChanged::class)->context);
        self::assertSame(IdentifierChangeOutcome::INVALID, $this->changes()->confirmByLink(SignedLink::fromRequest($request), self::requestClient($request))->outcome);
    }

    /**
     * A link that does not prove the change is invalid, and one past its time
     * is expired.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testLinksThatDoNotProveTheChangeAreRefused(): void
    {
        [$identity, $link] = $this->requestedByLink();

        $query    = self::linkFields($link);
        $signed   = fn (array $fields): string => URL::temporarySignedRoute('email.confirm', $this->now->addHour(), $fields);
        $refusals = [
            $link . 'x',
            str_replace('purpose=change_identifier', 'purpose=verify_identifier', $link),
            $signed(['guard' => 'web']),
            $signed([...$query, 'purpose' => 'verify_identifier']),
            $signed([...$query, 'type' => 'Email']),
            $signed([...$query, 'guard' => 'admin']),
            $signed([...$query, 'request' => '0195f4a2-7b1c-4000-8000-000000000001']),
            $signed([...$query, 'hash' => hash('sha256', 'ada@third.example.test')]),
            $signed([...$query, 'identity' => '999']),
        ];

        $this->recordEvents([AuthenticationFailed::class]);

        foreach ($refusals as $refused) {
            self::assertSame(
                IdentifierChangeOutcome::INVALID,
                $this->changes()->confirmByLink(SignedLink::fromRequest(Request::create($refused)), self::requestClient(Request::create($refused)))->outcome,
                $refused,
            );
        }

        $reasons = array_map(static fn (AuthenticationFailed $event): FailureReason => $event->reason, $this->failures());

        self::assertSame(array_fill(0, count($refusals), FailureReason::INVALID_CREDENTIALS), $reasons);
        self::assertSame(1, DB::table('identifier_changes')->count());

        $this->recordEvents([AuthenticationFailed::class]);
        $this->moveTo($this->now->addSeconds(3601));

        self::assertSame(
            IdentifierChangeOutcome::EXPIRED,
            $this->changes()->confirmByLink(SignedLink::fromRequest(Request::create($link)), self::requestClient(Request::create($link)))->outcome,
        );
        self::assertSame(FailureReason::LINK_EXPIRED, $this->recordedEvent(AuthenticationFailed::class)->reason);
        self::assertSame(self::EMAIL, $identity->fresh()?->email);
    }

    /**
     * A link is expired at the second its change expires, even while its
     * signature holds.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testALinkAtItsChangesExpiryIsExpired(): void
    {
        [, $link] = $this->requestedByLink();

        $this->recordEvents([AuthenticationFailed::class]);
        $this->moveTo($this->now->addSeconds(3600));

        self::assertSame(
            IdentifierChangeOutcome::EXPIRED,
            $this->changes()->confirmByLink(SignedLink::fromRequest(Request::create($link)), self::requestClient(Request::create($link)))->outcome,
        );
        self::assertSame(FailureReason::LINK_EXPIRED, $this->recordedEvent(AuthenticationFailed::class)->reason);
    }

    /**
     * A link of another guard or of a replaced request confirms nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testALinkOfAnotherGuardOrAReplacedRequestConfirmsNothing(): void
    {
        [$identity, $link] = $this->requestedByLink();

        self::assertSame(
            IdentifierChangeOutcome::INVALID,
            $this->changes('admin')->confirmByLink(SignedLink::fromRequest(Request::create($link)), self::requestClient(Request::create($link)))->outcome,
        );

        $this->changes()->requestByLink($identity, 'email', 'ada@third.example.test', self::freshSession($identity), 'email.confirm', self::requestClient());

        self::assertSame(
            IdentifierChangeOutcome::INVALID,
            $this->changes()->confirmByLink(SignedLink::fromRequest(Request::create($link)), self::requestClient(Request::create($link)))->outcome,
        );
        self::assertSame(self::EMAIL, $identity->fresh()?->email);
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
     * Seed an identity and request an email change proven by the engine's first
     * code.
     *
     * @return \Tests\Integration\Fixtures\ChangeableIdentity
     *
     * @throws \Throwable
     */
    private function requestedByCode(): ChangeableIdentity
    {
        $identity = self::seedChangeable(self::EMAIL, self::PHONE);

        self::assertTrue($this->changes()->requestByCode($identity, 'email', self::NEW_EMAIL, self::freshSession($identity), self::requestClient())->isSent());

        return $identity;
    }

    /**
     * Seed an identity and request an email change proven by a link.
     *
     * @return array{0: \Tests\Integration\Fixtures\ChangeableIdentity, 1: string}
     *
     * @throws \Throwable
     */
    private function requestedByLink(): array
    {
        $identity = self::seedChangeable();
        $link     = $this->changes()->requestByLink($identity, 'email', self::NEW_EMAIL, self::freshSession($identity), 'email.confirm', self::requestClient())->link()?->reveal();

        self::assertIsString($link);

        return [$identity, $link];
    }

    /**
     * The fields of a link's query, without its signature and expiry.
     *
     * @param  string  $link
     * @return array<array-key, mixed>
     */
    private static function linkFields(string $link): array
    {
        parse_str((string) parse_url($link, PHP_URL_QUERY), $query);

        unset($query['signature'], $query['expires']);

        return $query;
    }

    /**
     * The challenge id each failure recorded so far names.
     *
     * @return list<?string>
     */
    private function failedChallenges(): array
    {
        return array_map(static fn (AuthenticationFailed $event): ?string => $event->challengeId, $this->failures());
    }
}
