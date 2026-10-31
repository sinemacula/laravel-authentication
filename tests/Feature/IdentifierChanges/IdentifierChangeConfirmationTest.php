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
use SineMacula\Laravel\Authentication\Sessions\Reauthentication;
use SineMacula\Laravel\Authentication\Verification\Enums\VerificationLinkOutcome;
use SineMacula\Laravel\Authentication\Verification\VerificationLinks;
use Tests\Concerns\ChangesIdentifiers;
use Tests\Concerns\InspectsTraces;
use Tests\Integration\Fixtures\ChangeableIdentity;
use Tests\Integration\Fixtures\SuspendableChangeableIdentity;
use Tests\TestCase;

/**
 * Feature tests for confirming a change of identifier through
 * `Auth::identifierChanges($guard)`: by the code sent to the new identifier and
 * by the signed link, what a confirmed change writes, invalidates, reports and
 * notifies, and every way a confirmation is refused, with the proof spent only
 * together with the change.
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
     * Start every test from a known moment, with the fakes bound and the routes
     * links point at.
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
     * The right code replaces the identifier with the new one, recorded as
     * verified, deletes the pending change and uses the code up; once
     * committed, `IdentifierChanged` reports both identifiers and the notice to
     * the old one is queued, which the notifier then receives.
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

        self::assertSame(IdentifierChangeOutcome::CHANGED, $this->changes()->confirmByCode($identity, 'email', self::CODE));

        $row = (array) DB::table('changeable_identities')->first();

        self::assertSame([self::NEW_EMAIL, '2026-04-06 12:01:00', '2026-04-06 12:01:00'], [$row['email'], $row['email_verified_at'], $row['updated_at']]);
        self::assertSame(self::NEW_EMAIL, $identity->email);
        self::assertSame(0, DB::table('identifier_changes')->count());
        self::assertNotNull(DB::table('one_time_codes')->value('consumed_at'));
        self::assertSame([IdentifierChanged::class], $this->recordedClasses());

        $event = $this->recordedEvent(IdentifierChanged::class);

        self::assertSame(['web', $identity, 'email'], [$event->context->guard, $event->context->identity, $event->type]);
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
     * was requested, as the pending change recorded it then: one never verified
     * may be a stranger's, for the notifier to decide what to tell. The notice
     * is queued either way.
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

        self::assertTrue($this->changes()->requestByCode($identity, 'phone', self::NEW_PHONE, Reauthentication::confirmedAt($this->now))->isSent());
        self::assertSame([false], DB::table('identifier_changes')->pluck('previous_verified')->map(static fn (mixed $value): bool => (bool) $value)->all());
        self::assertSame(IdentifierChangeOutcome::CHANGED, $this->changes()->confirmByCode($identity, 'phone', self::CODE));

        $this->runQueued(SendIdentifierChangeNotice::class);

        $notices = $this->notifier->noticesFor($identity);

        self::assertCount(1, $notices);
        self::assertSame([self::PHONE, false, self::NEW_PHONE], [$notices[0]->previous, $notices[0]->previousVerified, $notices[0]->identifier]);
    }

    /**
     * A wrong code is refused and its attempt kept; the change still waits and
     * the right code makes it. A malformed one counts no attempt.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAWrongCodeIsRefusedAndCounted(): void
    {
        $identity = $this->requestedByCode();

        $this->recordEvents([AuthenticationFailed::class]);

        self::assertSame(IdentifierChangeOutcome::INVALID, $this->changes()->confirmByCode($identity, 'email', '000000'));
        self::assertSame(IdentifierChangeOutcome::INVALID, $this->changes()->confirmByCode($identity, 'email', '12345'));
        self::assertSame(1, self::codeAttempts());
        self::assertSame(1, DB::table('identifier_changes')->count());
        self::assertSame(self::EMAIL, $identity->fresh()?->email);
        self::assertSame(
            [[AuthenticationFlow::IDENTIFIER_CHANGE, FailureReason::INVALID_CREDENTIALS, null], [AuthenticationFlow::IDENTIFIER_CHANGE, FailureReason::INVALID_CREDENTIALS, null]],
            array_map(static fn (AuthenticationFailed $event): array => [$event->flow, $event->reason, $event->identifier], $this->failures()),
        );
        self::assertSame($identity, $this->failures()[0]->context->identity);
        self::assertSame(IdentifierChangeOutcome::CHANGED, $this->changes()->confirmByCode($identity, 'email', self::CODE));
    }

    /**
     * A code that used up its attempts is exhausted, one that expired is
     * expired, and a change past its own expiry is expired, each saying so on
     * the event.
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

        $this->changes()->confirmByCode($identity, 'email', '000000');

        self::assertSame(IdentifierChangeOutcome::EXHAUSTED, $this->changes()->confirmByCode($identity, 'email', self::CODE));

        DB::table('one_time_codes')->update(['attempts' => 0, 'expires_at' => '2026-04-06 12:00:00']);

        self::assertSame(IdentifierChangeOutcome::EXPIRED, $this->changes()->confirmByCode($identity, 'email', self::CODE));

        DB::table('one_time_codes')->update(['expires_at' => '2026-04-06 12:10:00']);

        $this->moveTo($this->now->addSeconds(600));

        self::assertSame(IdentifierChangeOutcome::EXPIRED, $this->changes()->confirmByCode($identity, 'email', self::CODE));
        self::assertSame(
            [FailureReason::INVALID_CREDENTIALS, FailureReason::CODE_EXHAUSTED, FailureReason::CODE_EXPIRED, FailureReason::CODE_EXPIRED],
            array_map(static fn (AuthenticationFailed $event): FailureReason => $event->reason, $this->failures()),
        );
        self::assertSame(self::EMAIL, $identity->fresh()?->email);
    }

    /**
     * Only the newest request's code confirms the change: an earlier one's is
     * invalidated when it is replaced.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnEarlierRequestsCodeConfirmsNothing(): void
    {
        $identity = $this->requestedByCode();

        $this->changes()->requestByCode($identity, 'email', 'ada@third.example.test', Reauthentication::confirmedAt($this->now));

        self::assertSame(IdentifierChangeOutcome::INVALID, $this->changes()->confirmByCode($identity, 'email', self::CODE));
        self::assertSame(IdentifierChangeOutcome::CHANGED, $this->changes()->confirmByCode($identity, 'email', '246802'));
        self::assertSame('ada@third.example.test', $identity->email);
    }

    /**
     * A change pending through another guard is not confirmed through this one,
     * and is left waiting.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnotherGuardsChangeIsNotConfirmed(): void
    {
        $identity = $this->requestedByCode();

        self::assertSame(IdentifierChangeOutcome::INVALID, $this->changes('admin')->confirmByCode($identity, 'email', self::CODE));
        self::assertSame([1, 0], [self::rows('identifier_changes'), self::codeAttempts()]);
        self::assertSame(IdentifierChangeOutcome::INVALID, $this->changes()->confirmByCode($identity, 'phone', self::CODE));
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

        self::assertSame(IdentifierChangeOutcome::CHANGED, $this->changes()->confirmByCode($identity, 'email', self::CODE));
        self::assertSame(IdentifierChangeOutcome::INVALID, $this->changes()->confirmByCode($identity, 'email', self::CODE));
    }

    /**
     * A newer request that lands after this confirmation read the pending
     * change, and before it deleted it, wins: the confirmation finds its
     * request gone, and rolls back, its code unspent.
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

        self::assertSame(IdentifierChangeOutcome::INVALID, $this->changes()->confirmByCode($identity, 'email', self::CODE));
        self::assertTrue($raced);
        self::assertSame(self::EMAIL, $identity->fresh()?->email);
        self::assertSame([1, null], [DB::table('identifier_changes')->count(), DB::table('one_time_codes')->value('consumed_at')]);
    }

    /**
     * A new identifier the guard's provider finds on another identity is taken:
     * nothing is written and the proof is not spent, so once the other identity
     * gives it up, the same code makes the change.
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

        self::assertSame(IdentifierChangeOutcome::TAKEN, $this->changes()->confirmByCode($identity, 'email', self::CODE));
        self::assertSame([AuthenticationFailed::class], $this->recordedClasses());
        self::assertSame(FailureReason::IDENTIFIER_TAKEN, $this->recordedEvent(AuthenticationFailed::class)->reason);
        self::assertSame([1, 0], [self::rows('identifier_changes'), self::codeAttempts()]);
        self::assertNull(DB::table('one_time_codes')->value('consumed_at'));
        self::assertSame(self::EMAIL, $identity->fresh()?->email);
        Queue::assertNotPushed(SendIdentifierChangeNotice::class);

        DB::table('changeable_identities')->where('id', $holder->getKey())->update(['email' => 'moved@example.test']);

        self::assertSame(IdentifierChangeOutcome::CHANGED, $this->changes()->confirmByCode($identity, 'email', self::CODE));
    }

    /**
     * Without a unique index on the column, the provider's check is all that
     * stops a change to an identifier another identity holds.
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

        self::assertSame(IdentifierChangeOutcome::TAKEN, $this->changes()->confirmByCode($identity, 'email', self::CODE));
        self::assertSame(1, DB::table('changeable_identities')->where('email', self::NEW_EMAIL)->count());
    }

    /**
     * An identity that took the new identifier by another path is not a holder
     * of its own change: the identifier it was requested against is gone, so
     * the change is invalid, not taken.
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

        self::assertSame(IdentifierChangeOutcome::INVALID, $this->changes()->confirmByCode($identity, 'email', self::CODE));
        self::assertSame(FailureReason::INVALID_CREDENTIALS, $this->failures()[0]->reason);
    }

    /**
     * When another identity takes the identifier after the provider looked (the
     * race the application's unique index decides), the index refuses the
     * write: the change is taken and rolled back whole, inside a transaction
     * the caller holds open, which stays usable.
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
            self::assertSame(IdentifierChangeOutcome::TAKEN, $this->changes()->confirmByCode($identity, 'email', self::CODE));
            self::assertSame(1, DB::table('identifier_changes')->count());
        } finally {
            DB::rollBack();
        }

        self::assertTrue($raced);
        self::assertSame(self::EMAIL, $identity->fresh()?->email);
        self::assertNull(DB::table('one_time_codes')->value('consumed_at'));
    }

    /**
     * An identifier changed by another path since the change was requested is
     * kept: the replacement is conditional on the identifier the change was
     * requested against, and the proof is not spent.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnIdentifierChangedMeanwhileIsKept(): void
    {
        $identity = $this->requestedByCode();

        DB::table('changeable_identities')->update(['email' => 'support@example.test']);

        self::assertSame(IdentifierChangeOutcome::INVALID, $this->changes()->confirmByCode($identity, 'email', self::CODE));
        self::assertSame('support@example.test', DB::table('changeable_identities')->value('email'));
        self::assertSame([1, null], [DB::table('identifier_changes')->count(), DB::table('one_time_codes')->value('consumed_at')]);
    }

    /**
     * A confirmation inside a transaction the caller rolls back changes nothing
     * and reports and notifies nothing.
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

        self::assertSame(IdentifierChangeOutcome::CHANGED, $this->changes()->confirmByCode($identity, 'email', self::CODE));

        DB::rollBack();

        self::assertSame([], $this->recorded);
        Queue::assertNotPushed(SendIdentifierChangeNotice::class);
        self::assertSame(self::EMAIL, DB::table('changeable_identities')->value('email'));
        self::assertSame(1, DB::table('identifier_changes')->count());
    }

    /**
     * Every event goes, once committed, to the dispatcher the guard has when
     * the commit runs it: the request's `IdentifierChangeRequested` and the
     * confirmation's `IdentifierChanged` both reach the one swapped in after
     * the confirmation, and neither the dispatcher of the request nor the one
     * swapped in between receives either.
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
            self::assertTrue($changes->requestByCode($identity, 'email', self::NEW_EMAIL, Reauthentication::confirmedAt($this->now))->isSent());

            $guard->setDispatcher($swapped);

            self::assertSame(IdentifierChangeOutcome::CHANGED, $changes->confirmByCode($identity, 'email', self::CODE));

            $guard->setDispatcher($last);
        });

        self::assertSame([], $this->recordedClasses());
        self::assertSame(['swapped' => [], 'last' => [IdentifierChangeRequested::class, IdentifierChanged::class]], $received);
    }

    /**
     * A service handed out before the guard's dispatcher and request were
     * rebound reports a refusal to the dispatcher bound now, with the client of
     * the request bound now.
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
        $guard->setRequest(Request::create('/', server: ['REMOTE_ADDR' => '198.51.100.7']));

        self::assertSame(IdentifierChangeOutcome::INVALID, $changes->confirmByCode($identity, 'email', '000000'));
        self::assertSame([], $this->recorded);
        self::assertCount(1, $received);
        self::assertSame([AuthenticationFlow::IDENTIFIER_CHANGE, '198.51.100.7'], [$received[0]->flow, $received[0]->context->client->ip]);
    }

    /**
     * A confirmed change invalidates, in every jwt guard whose provider reads
     * the identity's table, the codes of both the replaced and the new
     * identifier: sign-in, password reset and reset link codes, and the
     * identity's verification codes, a guard named with digits and one over
     * another model of the same table included. Other identifiers' codes are
     * kept, and so are the codes of a guard over another table, which belong to
     * whoever holds the identifier there; a guard of another driver, wherever
     * it is listed, is passed over.
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

        self::assertSame(IdentifierChangeOutcome::CHANGED, $this->changes()->confirmByCode($identity, 'email', self::CODE));

        $left = DB::table('one_time_codes')->pluck('id')->all();

        foreach ($outdated as $binding) {
            self::assertNotContains(self::bindingDigest($binding), $left);
        }

        foreach ($kept as $binding) {
            self::assertContains(self::bindingDigest($binding), $left);
        }

        self::assertCount(5, $left);
    }

    /**
     * An identity deactivated after it requested a change confirms nothing, by
     * link (which needs no session, so no guard checked it) or by code:
     * `invalid`, reported as `identity_inactive`, before anything but its row
     * is read, counted or spent, so the change confirms once the identity is
     * active again: a deactivation that only clears the flag ends no session
     * (one through `identityDeactivated()` cancels the change too).
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnInactiveIdentityConfirmsNothing(): void
    {
        config()->set('auth.providers.suspendables', ['driver' => 'model', 'model' => SuspendableChangeableIdentity::class]);
        config()->set('auth.guards.suspendable', ['driver' => 'jwt', 'provider' => 'suspendables', 'audience' => ['methods' => ['password', 'phone_code']]]);

        self::seedChangeable(self::EMAIL, self::PHONE);

        $identity = SuspendableChangeableIdentity::query()->sole();
        $link     = $this->changes('suspendable')->requestByLink($identity, 'email', self::NEW_EMAIL, Reauthentication::confirmedAt($this->now), 'email.confirm')->link();

        self::assertIsString($link);
        self::assertTrue($this->changes('suspendable')->requestByCode($identity, 'phone', self::NEW_PHONE, Reauthentication::confirmedAt($this->now))->isSent());

        DB::table('changeable_identities')->update(['is_active' => false]);

        $this->recordEvents([AuthenticationFailed::class]);

        self::assertSame(IdentifierChangeOutcome::INVALID, $this->changes('suspendable')->confirmByLink(Request::create($link)));
        self::assertSame(IdentifierChangeOutcome::INVALID, $this->changes('suspendable')->confirmByCode($identity->refresh(), 'phone', self::CODE));
        $reasons = array_map(static fn (AuthenticationFailed $event): FailureReason => $event->reason, $this->failures());

        self::assertSame([FailureReason::IDENTITY_INACTIVE, FailureReason::IDENTITY_INACTIVE], $reasons);
        self::assertSame([self::EMAIL, self::PHONE, 0, 2], [$identity->refresh()->email, $identity->phone, self::codeAttempts(), self::rows('identifier_changes')]);

        DB::table('changeable_identities')->update(['is_active' => true]);

        self::assertSame(IdentifierChangeOutcome::CHANGED, $this->changes('suspendable')->confirmByLink(Request::create($link)));
        self::assertSame(IdentifierChangeOutcome::CHANGED, $this->changes('suspendable')->confirmByCode($identity->refresh(), 'phone', self::CODE));
    }

    /**
     * The proofs a change outdates are those of the old identifier in its
     * canonical form, so an address stored in another case (a legacy row
     * written past the cast) loses the sign-in code and the reset link issued
     * for it in normal form.
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

        $live = static fn (): int => DB::table('one_time_codes')->whereIn('id', array_map(self::bindingDigest(...), $proofs))->count();

        self::assertTrue($this->changes()->requestByCode($identity, 'email', self::NEW_EMAIL, Reauthentication::confirmedAt($this->now))->isSent());
        self::assertSame(2, $live());
        self::assertSame(IdentifierChangeOutcome::CHANGED, $this->changes()->confirmByCode($identity, 'email', self::CODE));
        self::assertSame(0, $live());
    }

    /**
     * Whether the identity is active is read from its row under the lock, not
     * from the instance given: one deactivated after the caller loaded it
     * confirms nothing by code, and one deactivated after a link loaded it,
     * before the lock, confirms nothing by link. Both are `invalid`, reported
     * as `identity_inactive`, with nothing counted or spent.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnIdentityDeactivatedAfterItWasLoadedConfirmsNothing(): void
    {
        config()->set('auth.providers.suspendables', ['driver' => 'model', 'model' => SuspendableChangeableIdentity::class]);
        config()->set('auth.guards.suspendable', ['driver' => 'jwt', 'provider' => 'suspendables', 'audience' => ['methods' => ['password', 'phone_code']]]);

        self::seedChangeable(self::EMAIL, self::PHONE);

        $identity = SuspendableChangeableIdentity::query()->sole();
        $link     = $this->changes('suspendable')->requestByLink($identity, 'email', self::NEW_EMAIL, Reauthentication::confirmedAt($this->now), 'email.confirm')->link();

        self::assertIsString($link);
        self::assertTrue($this->changes('suspendable')->requestByCode($identity, 'phone', self::NEW_PHONE, Reauthentication::confirmedAt($this->now))->isSent());

        $this->recordEvents([AuthenticationFailed::class]);

        DB::table('changeable_identities')->update(['is_active' => false]);

        self::assertTrue($identity->isActive());
        self::assertSame(IdentifierChangeOutcome::INVALID, $this->changes('suspendable')->confirmByCode($identity, 'phone', self::CODE));

        DB::table('changeable_identities')->update(['is_active' => true]);

        $deactivated = false;

        DB::listen(static function (QueryExecuted $query) use (&$deactivated): void {
            if ($deactivated || !str_starts_with($query->sql, 'select') || !str_contains($query->sql, 'changeable_identities')) {
                return;
            }

            $deactivated = true;

            DB::table('changeable_identities')->update(['is_active' => false]);
        });

        self::assertSame(IdentifierChangeOutcome::INVALID, $this->changes('suspendable')->confirmByLink(Request::create($link)));
        self::assertTrue($deactivated);

        $reasons = array_map(static fn (AuthenticationFailed $event): FailureReason => $event->reason, $this->failures());

        self::assertSame([FailureReason::IDENTITY_INACTIVE, FailureReason::IDENTITY_INACTIVE], $reasons);
        self::assertSame([self::EMAIL, self::PHONE, 0, 2], [$identity->refresh()->email, $identity->phone, self::codeAttempts(), self::rows('identifier_changes')]);
    }

    /**
     * A failure inside a confirmation's transaction leaves the code out of
     * every frame of its trace, the proof's closure and what it captured
     * included, even with arguments recorded in traces.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFailedConfirmationLeavesTheCodeOutOfTheTrace(): void
    {
        $identity = $this->requestedByCode();

        DB::listen(static function (QueryExecuted $query): void {
            if (str_starts_with($query->sql, 'update') && str_contains($query->sql, 'one_time_codes')) {
                throw new \RuntimeException('the store failed');
            }
        });

        $exception = self::withArgumentsInTraces(\RuntimeException::class, fn (): mixed => $this->changes()->confirmByCode($identity, 'email', self::CODE));

        self::assertSame('the store failed', $exception->getMessage());
        self::assertFalse(self::hasInTrace($exception, self::CODE));
        self::assertSame([self::EMAIL, 1], [$identity->refresh()->email, self::rows('identifier_changes')]);
    }

    /**
     * An identity no longer stored confirms nothing with the instance the
     * caller still holds: `invalid`, reported as `invalid_credentials`, with
     * its code's attempt not counted.
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

        self::assertSame(IdentifierChangeOutcome::INVALID, $this->changes()->confirmByCode($identity, 'email', self::CODE));
        self::assertSame([FailureReason::INVALID_CREDENTIALS], array_map(static fn (AuthenticationFailed $event): FailureReason => $event->reason, $this->failures()));
        self::assertSame([0, 1], [self::codeAttempts(), self::rows('identifier_changes')]);
    }

    /**
     * The flows of a new password that end the identity's sessions.
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
     * A change or a reset of the password cancels every identifier change the
     * identity has pending, of each type and through each guard: neither the
     * link nor the code of one requested from a session the new password ended
     * makes it, though a link needs no session. Another identity's pending
     * change is kept.
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
        $link     = $this->changes()->requestByLink($identity, 'email', self::NEW_EMAIL, Reauthentication::confirmedAt($this->now), 'email.confirm')->link();

        self::assertIsString($link);
        self::assertTrue($this->changes('admin')->requestByCode($identity, 'phone', self::NEW_PHONE, Reauthentication::confirmedAt($this->now))->isSent());
        self::assertTrue($this->changes()->requestByCode($other, 'email', 'grace@new.example.test', Reauthentication::confirmedAt($this->now))->isSent());

        self::assertTrue(Auth::passwords('web')->set($identity, 'a brand new passphrase', $flow)->set);
        self::assertSame(1, self::rows('identifier_changes'));

        self::assertSame(IdentifierChangeOutcome::INVALID, $this->changes()->confirmByLink(Request::create($link)));
        self::assertSame(IdentifierChangeOutcome::INVALID, $this->changes('admin')->confirmByCode($identity, 'phone', self::CODE));
        self::assertSame([self::EMAIL, self::PHONE], [$identity->fresh()?->email, $identity->fresh()?->phone]);
        self::assertSame(IdentifierChangeOutcome::CHANGED, $this->changes()->confirmByCode($other, 'email', '246802'));
    }

    /**
     * A registration ends no session, so it leaves the identity's pending
     * change, which its link still makes.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARegistrationKeepsThePendingChange(): void
    {
        [$identity, $link] = $this->requestedByLink();

        DB::table('changeable_identities')->update(['password' => null]);

        self::assertTrue(Auth::passwords('web')->set($identity->fresh() ?? $identity, 'a brand new passphrase', PasswordFlow::REGISTRATION)->set);
        self::assertSame(IdentifierChangeOutcome::CHANGED, $this->changes()->confirmByLink(Request::create($link)));
    }

    /**
     * A verification link signed for the old identifier no longer verifies
     * anything once it is replaced.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAVerificationLinkForTheOldIdentifierIsDead(): void
    {
        $identity = $this->requestedByCode();
        $link     = app(VerificationLinks::class)->create('web', $identity, 'email', 'email.verify');

        DB::table('changeable_identities')->update(['email_verified_at' => null]);

        self::assertSame(IdentifierChangeOutcome::CHANGED, $this->changes()->confirmByCode($identity, 'email', self::CODE));
        self::assertSame(VerificationLinkOutcome::INVALID, app(VerificationLinks::class)->consume(Request::create($link)));
    }

    /**
     * An identity that had no identifier of the type gets one with no notice,
     * since there is no one to tell; the event says there was none.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFirstIdentifierIsSetWithoutANotice(): void
    {
        $identity = self::seedChangeable(self::EMAIL, null);

        $this->recordEvents([IdentifierChanged::class]);

        $this->changes()->requestByCode($identity, 'phone', self::NEW_PHONE, Reauthentication::confirmedAt($this->now));

        self::assertSame(IdentifierChangeOutcome::CHANGED, $this->changes()->confirmByCode($identity, 'phone', self::CODE));
        self::assertSame(self::NEW_PHONE, $identity->fresh()?->phone);
        self::assertNull($this->recordedEvent(IdentifierChanged::class)->previous);
        Queue::assertNotPushed(SendIdentifierChangeNotice::class);
    }

    /**
     * A notifier that fails fails its job, for the queue to retry; the change
     * stands.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFailingNoticeLeavesTheChange(): void
    {
        $identity = $this->requestedByCode();

        $this->changes()->confirmByCode($identity, 'email', self::CODE);

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
     * A link confirms the change it was signed for, through the guard that
     * signed it, and reports the client that followed it.
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

        self::assertSame(IdentifierChangeOutcome::CHANGED, $this->changes()->confirmByLink($request));
        self::assertSame(self::NEW_EMAIL, DB::table('changeable_identities')->value('email'));
        self::assertSame('198.51.100.4', $this->recordedEvent(IdentifierChanged::class)->context->client->ip);
        self::assertTrue($identity->is($this->recordedEvent(IdentifierChanged::class)->context->identity));
        self::assertSame(IdentifierChangeOutcome::INVALID, $this->changes()->confirmByLink($request));
    }

    /**
     * A link whose signature, purpose or fields are not a change link's, or
     * that another guard signed, is invalid; one past its time is expired, on
     * the event as `link_expired`.
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
            self::assertSame(IdentifierChangeOutcome::INVALID, $this->changes()->confirmByLink(Request::create($refused)), $refused);
        }

        $reasons = array_map(static fn (AuthenticationFailed $event): FailureReason => $event->reason, $this->failures());

        self::assertSame(array_fill(0, count($refusals), FailureReason::INVALID_CREDENTIALS), $reasons);
        self::assertSame(1, DB::table('identifier_changes')->count());

        $this->recordEvents([AuthenticationFailed::class]);
        $this->moveTo($this->now->addSeconds(3601));

        self::assertSame(IdentifierChangeOutcome::EXPIRED, $this->changes()->confirmByLink(Request::create($link)));
        self::assertSame(FailureReason::LINK_EXPIRED, $this->recordedEvent(AuthenticationFailed::class)->reason);
        self::assertSame(self::EMAIL, $identity->fresh()?->email);
    }

    /**
     * At the second its change expires, a link whose own signature still holds
     * is expired: the change's expiry decides.
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

        self::assertSame(IdentifierChangeOutcome::EXPIRED, $this->changes()->confirmByLink(Request::create($link)));
        self::assertSame(FailureReason::LINK_EXPIRED, $this->recordedEvent(AuthenticationFailed::class)->reason);
    }

    /**
     * A link signed through another guard is not confirmed through this one,
     * and a link of a replaced request confirms nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testALinkOfAnotherGuardOrAReplacedRequestConfirmsNothing(): void
    {
        [$identity, $link] = $this->requestedByLink();

        self::assertSame(IdentifierChangeOutcome::INVALID, $this->changes('admin')->confirmByLink(Request::create($link)));

        $this->changes()->requestByLink($identity, 'email', 'ada@third.example.test', Reauthentication::confirmedAt($this->now), 'email.confirm');

        self::assertSame(IdentifierChangeOutcome::INVALID, $this->changes()->confirmByLink(Request::create($link)));
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
     * Seed an identity and request a change of its email address, proven by the
     * engine's first code.
     *
     * @return \Tests\Integration\Fixtures\ChangeableIdentity
     *
     * @throws \Throwable
     */
    private function requestedByCode(): ChangeableIdentity
    {
        $identity = self::seedChangeable(self::EMAIL, self::PHONE);

        self::assertTrue($this->changes()->requestByCode($identity, 'email', self::NEW_EMAIL, Reauthentication::confirmedAt($this->now))->isSent());

        return $identity;
    }

    /**
     * Seed an identity and request a change of its email address, proven by a
     * link: the identity and the link.
     *
     * @return array{0: \Tests\Integration\Fixtures\ChangeableIdentity, 1: string}
     *
     * @throws \Throwable
     */
    private function requestedByLink(): array
    {
        $identity = self::seedChangeable();
        $link     = $this->changes()->requestByLink($identity, 'email', self::NEW_EMAIL, Reauthentication::confirmedAt($this->now), 'email.confirm')->link();

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
}
