<?php

declare(strict_types = 1);

namespace Tests\Feature\IdentifierChanges;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Database\Events\TransactionBeginning;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Queue;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use Ramsey\Uuid\Uuid;
use Ramsey\Uuid\UuidInterface;
use SineMacula\Laravel\Authentication\AuthManager;
use SineMacula\Laravel\Authentication\Codes\CodeBinding;
use SineMacula\Laravel\Authentication\Codes\Enums\CodePurpose;
use SineMacula\Laravel\Authentication\Codes\OneTimeCodes;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\Enums\AuthenticationFlow;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\IdentifierChangeRequested;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\IdentifierChanges\ChangeLinks;
use SineMacula\Laravel\Authentication\IdentifierChanges\ChangeRequests;
use SineMacula\Laravel\Authentication\IdentifierChanges\Enums\IdentifierChangeRequestStatus;
use SineMacula\Laravel\Authentication\IdentifierChanges\IdentifierChangeRequest;
use SineMacula\Laravel\Authentication\IdentifierChanges\IdentifierChangeService;
use SineMacula\Laravel\Authentication\IdentifierChanges\PendingChanges;
use SineMacula\Laravel\Authentication\IdentifierChanges\PendingIdentifierChange;
use SineMacula\Laravel\Authentication\IdentifierChanges\RequestedChange;
use SineMacula\Laravel\Authentication\IdentifierChanges\SendIdentifierChangeCode;
use SineMacula\Laravel\Authentication\Sessions\Reauthentication;
use Tests\Concerns\ChangesIdentifiers;
use Tests\Concerns\InteractsWithRateLimits;
use Tests\Fixtures\Events\EventContextAssertions;
use Tests\Integration\Fixtures\ChangeableIdentity;
use Tests\TestCase;

/**
 * Feature tests for requesting, reading and cancelling a change of identifier.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(IdentifierChangeService::class)]
#[CoversClass(ChangeRequests::class)]
#[CoversClass(ChangeLinks::class)]
#[CoversClass(PendingChanges::class)]
#[CoversClass(RequestedChange::class)]
#[CoversClass(PendingIdentifierChange::class)]
#[CoversClass(AuthManager::class)]
final class IdentifierChangeRequestsTest extends TestCase
{
    use ChangesIdentifiers, InteractsWithRateLimits;

    /**
     * Freeze the clock and bind the fakes and a route for change links.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->startChanging();

        Route::get('/email/confirm', static fn (): string => 'ok')->name('email.confirm');
        Route::get('/{tenant}/email/confirm', static fn (): string => 'ok')->name('tenant.email.confirm');
        Route::get('/email/confirm/{request}', static fn (): string => 'ok')->name('placeholder.confirm');
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
     * A change by code writes the pending change and queues the code to the new
     * identifier.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACodeRequestQueuesTheCodeToTheNewIdentifier(): void
    {
        $identity = self::seedChangeable();

        Event::fake([IdentifierChangeRequested::class, AuthenticationFailed::class]);

        $request = $this->changes()->requestByCode($identity, 'email', ' ADA@New.Example.Test ', Reauthentication::session(self::seedSession($identity)), self::requestClient());
        $row     = (array) DB::table('identifier_changes')->first();

        self::assertSame([IdentifierChangeRequestStatus::SENT, null, null], [$request->status, $request->retryAfter, $request->link()]);
        self::assertEquals($this->now->addSeconds(600), $request->expiresAt);
        self::assertSame(PendingChanges::key($identity, 'email'), $row['id']);
        self::assertSame(['web', 'email', self::EMAIL, self::NEW_EMAIL], [$row['guard'], $row['type'], $row['previous'], $row['identifier']]);
        self::assertSame(['2026-04-06 12:00:00', '2026-04-06 12:10:00'], [$row['requested_at'], $row['expires_at']]);
        self::assertTrue(Str::isUuid($row['request_id']));
        self::assertSame(self::EMAIL, $identity->fresh()?->email);

        $binding = CodeBinding::identifierChange('web', 'email', self::NEW_EMAIL, $identity, $row['request_id']);

        $jobs = Queue::pushed(SendIdentifierChangeCode::class);

        self::assertCount(1, $jobs);
        self::assertInstanceOf(SendIdentifierChangeCode::class, $jobs[0]);
        self::assertSame(self::bindingDigest($binding), self::bindingDigest($jobs[0]->binding));
        self::assertSame([$row['request_id'], self::CODE], [$jobs[0]->requestId, $jobs[0]->issued->code()]);
        self::assertTrue($jobs[0]->identity->is($identity));

        self::assertSame(1, DB::table('one_time_codes')->where('id', self::bindingDigest($binding))->count());

        Event::assertDispatched(IdentifierChangeRequested::class, fn (IdentifierChangeRequested $event): bool => $event->context->guard === 'web'
            && EventContextAssertions::namesIdentity($identity, $event->context)
            && [$event->type, $event->identifier] === ['email', self::NEW_EMAIL]
            && $event->expiresAt->equalTo($this->now->addSeconds(600)));
        Event::assertNotDispatched(AuthenticationFailed::class);

        self::assertSame(1, $this->runQueued(SendIdentifierChangeCode::class));

        $message = $this->sender->sent()[0];

        self::assertSame(['web', CodePurpose::CHANGE_IDENTIFIER, 'email'], [$message->guard, $message->purpose, $message->type]);
        self::assertSame([self::NEW_EMAIL, self::CODE], [$message->identifier, $message->code->reveal()]);
        self::assertIsModel($identity, $message->identity);
    }

    /**
     * A change waits no longer than the configured lifetime when its code works
     * longer.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACodeRequestWaitsNoLongerThanTheConfiguredLifetime(): void
    {
        config()->set('authentication.identifier_changes.ttl_seconds', 300);

        $identity = self::seedChangeable();
        $request  = $this->changes()->requestByCode($identity, 'email', self::NEW_EMAIL, Reauthentication::password(self::PASSWORD), self::requestClient());

        self::assertEquals($this->now->addSeconds(300), $request->expiresAt);
        self::assertSame('2026-04-06 12:05:00', DB::table('identifier_changes')->value('expires_at'));
    }

    /**
     * A change by link signs a link to the application's route that expires
     * with the change.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testALinkRequestSignsALinkForTheRequest(): void
    {
        $identity = self::seedChangeable();
        $request  = $this->changes()->requestByLink(
            $identity,
            'email',
            self::NEW_EMAIL,
            self::freshSession($identity),
            'tenant.email.confirm',
            self::requestClient(),
            ['tenant' => 'acme', 'locale' => 'en'],
        );
        $link = (string) $request->link()?->reveal();

        parse_str((string) parse_url($link, PHP_URL_QUERY), $query);

        self::assertSame(IdentifierChangeRequestStatus::SENT, $request->status);
        self::assertEquals($this->now->addSeconds(3600), $request->expiresAt);
        self::assertStringStartsWith('http://localhost/acme/email/confirm?', $link);
        self::assertSame([
            'en',
            'web',
            (string) $identity->id,
            'email',
            'change_identifier',
            DB::table('identifier_changes')->value('request_id'),
            hash('sha256', self::NEW_EMAIL),
            (string) $this->now->addSeconds(3600)->getTimestamp(),
        ], [$query['locale'], $query['guard'], $query['identity'], $query['type'], $query['purpose'], $query['request'], $query['hash'], $query['expires']]);
        self::assertSame('2026-04-06 13:00:00', DB::table('identifier_changes')->value('expires_at'));
        self::assertSame(0, self::rows('one_time_codes'));
        Queue::assertNothingPushed();
    }

    /**
     * A newer request through any guard replaces the pending change of its type
     * and invalidates the old code.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testANewerRequestReplacesThePendingChange(): void
    {
        $identity = self::seedChangeable(self::EMAIL, self::PHONE);
        $proof    = self::freshSession($identity);

        $this->changes()->requestByCode($identity, 'email', self::NEW_EMAIL, $proof, self::requestClient());

        $first   = self::stored('identifier_changes', 'request_id');
        $binding = CodeBinding::identifierChange('web', 'email', self::NEW_EMAIL, $identity, $first);

        $this->moveTo($this->now->addMinute());

        $this->changes('admin')->requestByLink($identity, 'email', 'ada@third.example.test', self::freshSession($identity, 'admin'), 'email.confirm', self::requestClient());
        $this->changes()->requestByCode($identity, 'phone', self::NEW_PHONE, $proof, self::requestClient());

        $email = (array) DB::table('identifier_changes')->where('type', 'email')->first();

        self::assertSame(2, self::rows('identifier_changes'));
        self::assertNotSame($first, $email['request_id']);
        self::assertSame(['admin', self::EMAIL, 'ada@third.example.test'], [$email['guard'], $email['previous'], $email['identifier']]);
        self::assertSame('2026-04-06 12:01:00', $email['requested_at']);
        self::assertNotNull(DB::table('one_time_codes')->where('id', self::bindingDigest($binding))->value('consumed_at'));
        self::assertSame(1, DB::table('one_time_codes')->whereNull('consumed_at')->count());
    }

    /**
     * A request racing a first request writes over the change it inserted.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARequestRacingAFirstRequestWritesOverIt(): void
    {
        $identity = self::seedChangeable();
        $key      = PendingChanges::key($identity, 'email');
        $raced    = false;

        DB::listen(static function (QueryExecuted $query) use (&$raced, $key): void {
            if ($raced || !str_starts_with($query->sql, 'select') || !str_contains($query->sql, 'identifier_changes')) {
                return;
            }

            $raced = true;

            DB::table('identifier_changes')->insert([
                'id'           => $key,
                'guard'        => 'admin',
                'type'         => 'email',
                'previous'     => self::EMAIL,
                'identifier'   => 'racer@example.test',
                'request_id'   => (string) Str::uuid(),
                'requested_at' => '2026-04-06 12:00:00',
                'expires_at'   => '2026-04-06 13:00:00',
            ]);
        });

        $this->changes()->requestByLink($identity, 'email', self::NEW_EMAIL, self::freshSession($identity), 'email.confirm', self::requestClient());

        self::assertTrue($raced);
        self::assertSame(1, self::rows('identifier_changes'));
        self::assertSame(['web', self::NEW_EMAIL], [self::stored('identifier_changes', 'guard'), self::stored('identifier_changes', 'identifier')]);
    }

    /**
     * A first request inserts its change and a replacing one updates it in
     * place.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARequestInsertsANewChangeAndUpdatesAReplacedOneInPlace(): void
    {
        $identity = self::seedChangeable();
        $proof    = self::freshSession($identity);
        $writes   = [];

        DB::listen(static function (QueryExecuted $query) use (&$writes): void {
            if (!str_contains($query->sql, 'identifier_changes') || str_starts_with($query->sql, 'select')) {
                return;
            }

            $writes[] = strtok($query->sql, ' ');
        });

        $this->changes()->requestByLink($identity, 'email', 'ada@first.example.test', $proof, 'email.confirm', self::requestClient());
        $this->changes()->requestByLink($identity, 'email', self::NEW_EMAIL, $proof, 'email.confirm', self::requestClient());

        self::assertSame(['insert', 'update'], $writes);
        self::assertSame(self::NEW_EMAIL, self::stored('identifier_changes', 'identifier'));
    }

    /**
     * A request whose replaced change is deleted meanwhile inserts its own.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARequestWhoseReplacedChangeGoesMeanwhileInsertsItsOwn(): void
    {
        $identity = self::seedChangeable();
        $proof    = self::freshSession($identity);
        $raced    = false;

        $this->changes()->requestByLink($identity, 'email', 'ada@first.example.test', $proof, 'email.confirm', self::requestClient());

        DB::listen(static function (QueryExecuted $query) use (&$raced): void {
            if ($raced || !str_starts_with($query->sql, 'select') || !str_contains($query->sql, 'identifier_changes')) {
                return;
            }

            $raced = true;

            DB::table('identifier_changes')->delete();
        });

        self::assertTrue($this->changes()->requestByLink($identity, 'email', self::NEW_EMAIL, $proof, 'email.confirm', self::requestClient())->isSent());
        self::assertTrue($raced);
        self::assertSame(1, self::rows('identifier_changes'));
        self::assertSame(self::NEW_EMAIL, self::stored('identifier_changes', 'identifier'));
    }

    /**
     * A code request whose binding already has a live code is rate limited and
     * writes nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACodeTheEngineWillNotIssueIsRateLimited(): void
    {
        $identity  = self::seedChangeable();
        $requestId = '0195f4a2-7b1c-4000-8000-000000000001';

        Str::createUuidsUsing(static fn (): UuidInterface => Uuid::fromString($requestId));

        try {
            app(OneTimeCodes::class)->issue(CodeBinding::identifierChange('web', 'email', self::NEW_EMAIL, $identity, $requestId), $this->now);

            Event::fake([AuthenticationFailed::class]);

            $request = $this->changes()->requestByCode($identity, 'email', self::NEW_EMAIL, self::freshSession($identity), self::requestClient());
        } finally {
            Str::createUuidsNormally();
        }

        self::assertSame([IdentifierChangeRequestStatus::RATE_LIMITED, 60], [$request->status, $request->retryAfter]);
        self::assertSame(0, self::rows('identifier_changes'));
        Queue::assertNothingPushed();
        Event::assertDispatched(
            AuthenticationFailed::class,
            static fn (AuthenticationFailed $event): bool => $event->reason === FailureReason::RATE_LIMITED && $event->retryAfter === 60,
        );
    }

    /**
     * Invalid and unchanged identifiers are refused as given, with nothing
     * counted or written.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testInvalidAndUnchangedIdentifiersAreRefused(): void
    {
        $identity = self::seedChangeable(self::EMAIL, self::PHONE);
        $proof    = self::freshSession($identity);

        $this->recordEvents([AuthenticationFailed::class]);

        $invalid   = $this->changes()->requestByCode($identity, 'phone', '07700 900456', $proof, self::requestClient());
        $unchanged = $this->changes()->requestByCode($identity, 'email', ' Ada@Example.Test', $proof, self::requestClient());

        self::assertSame([IdentifierChangeRequestStatus::IDENTIFIER_INVALID, IdentifierChangeRequestStatus::IDENTIFIER_UNCHANGED], [$invalid->status, $unchanged->status]);
        self::assertSame(
            [
                [AuthenticationFlow::IDENTIFIER_CHANGE, FailureReason::INVALID_CREDENTIALS, '07700 900456'],
                [AuthenticationFlow::IDENTIFIER_CHANGE, FailureReason::INVALID_CREDENTIALS, ' Ada@Example.Test'],
            ],
            array_map(static fn (AuthenticationFailed $event): array => [$event->flow, $event->reason, $event->identifier], $this->failures()),
        );
        EventContextAssertions::assertIdentity($identity, $this->failures()[0]->context);
        self::assertSame(0, self::rows('rate_limits'));
        self::assertSame(0, self::rows('identifier_changes'));
    }

    /**
     * The proof is checked before the identifier.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheProofIsCheckedBeforeTheIdentifier(): void
    {
        $identity = self::seedChangeable();
        $stale    = Reauthentication::session(self::seedSession($identity, signedInAt: $this->now->subHour()));
        $request  = $this->changes()->requestByCode($identity, 'email', self::EMAIL, $stale, self::requestClient());

        self::assertSame(IdentifierChangeRequestStatus::REAUTHENTICATION_REQUIRED, $request->status);
    }

    /**
     * A request made with a stale instance is decided on the row as stored.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAStaleInstanceIsDecidedOnTheRowAsStored(): void
    {
        $identity = self::seedChangeable();
        $proof    = self::freshSession($identity);

        DB::table('changeable_identities')->update(['email' => 'moved@example.test', 'email_verified_at' => null]);

        $unchanged = $this->changes()->requestByLink($identity, 'email', 'moved@example.test', $proof, 'email.confirm', self::requestClient());

        self::assertSame(IdentifierChangeRequestStatus::IDENTIFIER_UNCHANGED, $unchanged->status);
        self::assertSame(0, self::rows('rate_limits'));

        self::assertTrue($this->changes()->requestByLink($identity, 'email', self::NEW_EMAIL, $proof, 'email.confirm', self::requestClient())->isSent());
        self::assertSame(['moved@example.test', false], [self::stored('identifier_changes', 'previous'), (bool) DB::table('identifier_changes')->value('previous_verified')]);
        self::assertSame(self::EMAIL, $identity->email);
    }

    /**
     * A stale instance is proven by the password the row holds.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAStaleInstanceIsProvenByThePasswordTheRowHolds(): void
    {
        $identity = self::seedChangeable();

        DB::table('changeable_identities')->update(['password' => app(Hasher::class)->make('another long passphrase')]);

        $request = $this->changes()->requestByLink(
            $identity,
            'email',
            self::NEW_EMAIL,
            Reauthentication::password('another long passphrase'),
            'email.confirm',
            self::requestClient(),
        );

        self::assertTrue($request->isSent());
        self::assertSame(1, self::rows('identifier_changes'));
    }

    /**
     * A password written before the lock refuses the request and gives every
     * slot back.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPasswordWrittenBeforeTheLockRefusesTheRequest(): void
    {
        $identity = self::seedChangeable();

        $this->recordEvents([AuthenticationFailed::class]);
        self::beforeTheLock(static fn (): int => DB::table('changeable_identities')->update(['password' => app(Hasher::class)->make('another long passphrase')]));

        $request = $this->changes()->requestByLink($identity, 'email', self::NEW_EMAIL, Reauthentication::password(self::PASSWORD), 'email.confirm', self::requestClient());

        self::assertSame(IdentifierChangeRequestStatus::REAUTHENTICATION_REQUIRED, $request->status);
        self::assertSame([FailureReason::REAUTHENTICATION_REQUIRED], array_map(static fn (AuthenticationFailed $event): FailureReason => $event->reason, $this->failures()));
        self::assertSame(0, self::rows('identifier_changes'));
        self::assertNoSlotKept();
    }

    /**
     * A session revoked before the lock refuses the request and gives the slots
     * back.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASessionRevokedBeforeTheLockRefusesTheRequest(): void
    {
        $identity = self::seedChangeable();
        $session  = self::seedSession($identity);

        self::beforeTheLock(static fn (): int => DB::table('authentication_sessions')->update(['revoked_at' => '2026-04-06 12:00:00']));

        $request = $this->changes()->requestByCode($identity, 'email', self::NEW_EMAIL, Reauthentication::session($session), self::requestClient());

        self::assertSame(IdentifierChangeRequestStatus::REAUTHENTICATION_REQUIRED, $request->status);
        self::assertSame(0, self::rows('identifier_changes'));
        self::assertSame(0, self::rows('one_time_codes'));
        self::assertNoSlotKept();
    }

    /**
     * An identifier confirmed before the lock is unchanged, and the slots are
     * given back.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnIdentifierConfirmedBeforeTheLockIsUnchanged(): void
    {
        $identity = self::seedChangeable();

        self::beforeTheLock(static fn (): int => DB::table('changeable_identities')->update(['email' => self::NEW_EMAIL]));

        $request = $this->changes()->requestByLink($identity, 'email', self::NEW_EMAIL, self::freshSession($identity), 'email.confirm', self::requestClient());

        self::assertSame(IdentifierChangeRequestStatus::IDENTIFIER_UNCHANGED, $request->status);
        self::assertSame(0, self::rows('identifier_changes'));
        self::assertNoSlotKept();
    }

    /**
     * An identity whose stored identifier its normaliser rejects may change it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testALegacyIdentifierCanBeChanged(): void
    {
        $identity = self::seedChangeable(self::EMAIL, null);

        DB::table('changeable_identities')->update(['phone' => '07700 900123']);

        $request = $this->changes()->requestByCode($identity->fresh() ?? $identity, 'phone', self::NEW_PHONE, self::freshSession($identity), self::requestClient());

        self::assertTrue($request->isSent());
        self::assertSame('07700 900123', DB::table('identifier_changes')->value('previous'));
    }

    /**
     * An address stored in another case is still the current one.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnAddressStoredInAnotherCaseIsTheCurrentOne(): void
    {
        self::seedChangeable();

        DB::table('changeable_identities')->update(['email' => 'Ada@Example.test']);

        $identity = ChangeableIdentity::query()->sole();
        $request  = $this->changes()->requestByCode($identity, 'email', self::EMAIL, self::freshSession($identity), self::requestClient());

        self::assertSame(IdentifierChangeRequestStatus::IDENTIFIER_UNCHANGED, $request->status);
        self::assertSame(0, self::rows('identifier_changes'));
    }

    /**
     * Requests are limited per new identifier, identity and IP address.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRequestsAreLimitedPerIdentifierAndIdentity(): void
    {
        $identity = self::seedChangeable();
        $proof    = self::freshSession($identity);

        foreach (range(1, 5) as $attempt) {
            self::assertTrue($this->changes()->requestByLink($identity, 'email', "ada+{$attempt}@example.test", $proof, 'email.confirm', self::requestClient())->isSent());
        }

        $this->recordEvents([AuthenticationFailed::class]);

        $refused = $this->changes()->requestByLink($identity, 'email', 'ada+6@example.test', $proof, 'email.confirm', self::requestClient());

        self::assertSame([IdentifierChangeRequestStatus::RATE_LIMITED, 3600], [$refused->status, $refused->retryAfter]);
        $failure = $this->failures()[0];

        self::assertSame([FailureReason::RATE_LIMITED, 3600, 'ada+6@example.test'], [$failure->reason, $failure->retryAfter, $failure->identifier]);
        self::assertSame('ada+5@example.test', DB::table('identifier_changes')->value('identifier'));
        self::assertSame(1, self::counterHits('web', 'identifier_change', 'per_identifier', 'ada+1@example.test'));
        self::assertSame(5, self::counterHits('web', 'identifier_change', 'per_ip', self::CLIENT_IP));
    }

    /**
     * The client the caller names is the one the events carry.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheClientGivenIsReported(): void
    {
        $identity = self::seedChangeable();

        $this->recordEvents([IdentifierChangeRequested::class]);

        $client = new ClientContext('198.51.100.4', 'Console/1.0');

        $this->changes()->requestByLink($identity, 'email', self::NEW_EMAIL, self::freshSession($identity), 'email.confirm', client: $client);

        $event = $this->recordedEvent(IdentifierChangeRequested::class);

        self::assertSame(['198.51.100.4', 'Console/1.0'], [$event->context->client->ip, $event->context->client->userAgent]);
        self::assertSame(1, self::counterHits('web', 'identifier_change', 'per_ip', '198.51.100.4'));
    }

    /**
     * Inside a caller's transaction the event and delivery wait for its commit.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARequestInsideACallerTransactionWaitsForItsCommit(): void
    {
        $identity = self::seedChangeable();
        $proof    = self::freshSession($identity);

        $this->recordEvents([IdentifierChangeRequested::class]);

        DB::beginTransaction();

        $this->changes()->requestByCode($identity, 'email', self::NEW_EMAIL, $proof, self::requestClient());

        self::assertSame([], $this->recorded);
        Queue::assertNothingPushed();

        DB::rollBack();

        self::assertSame([], $this->recorded);
        Queue::assertNothingPushed();
        self::assertSame(0, self::rows('identifier_changes'));

        DB::transaction(fn (): IdentifierChangeRequest => $this->changes()->requestByCode($identity, 'email', self::NEW_EMAIL, $proof, self::requestClient()));

        self::assertSame([IdentifierChangeRequested::class], $this->recordedClasses());
        Queue::assertPushed(SendIdentifierChangeCode::class, 1);
    }

    /**
     * `pending()` reports only this guard's live change, read on the write
     * connection.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testPendingReportsTheLiveChangeOfThisGuard(): void
    {
        $identity = self::seedChangeable();

        self::assertNull($this->changes()->pending($identity, 'email'));

        $this->changes()->requestByLink($identity, 'email', self::NEW_EMAIL, self::freshSession($identity), 'email.confirm', self::requestClient());

        $pending = $this->changes()->pending($identity, 'email');

        self::assertInstanceOf(PendingIdentifierChange::class, $pending);
        self::assertSame(['email', self::NEW_EMAIL], [$pending->type, $pending->identifier]);
        self::assertTrue($this->now->equalTo($pending->requestedAt));
        self::assertTrue($this->now->addHour()->equalTo($pending->expiresAt));
        self::assertNull($this->changes('admin')->pending($identity, 'email'));
        self::assertNull($this->changes()->pending($identity, 'phone'));

        $this->moveTo($this->now->addHour());

        self::assertNull($this->changes()->pending($identity, 'email'));
    }

    /**
     * `cancel()` removes this guard's pending change and ends its code.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testCancelRemovesThisGuardsChangeAndItsCode(): void
    {
        $identity = self::seedChangeable();

        $this->changes()->requestByCode($identity, 'email', self::NEW_EMAIL, self::freshSession($identity), self::requestClient());

        self::assertFalse($this->changes('admin')->cancel($identity, 'email'));
        self::assertSame(1, self::rows('identifier_changes'));
        self::assertTrue($this->changes()->cancel($identity, 'email'));
        self::assertSame([0, 0], [self::rows('identifier_changes'), DB::table('one_time_codes')->whereNull('consumed_at')->count()]);
        self::assertFalse($this->changes()->cancel($identity, 'email'));
        self::assertSame(1, $this->runQueued(SendIdentifierChangeCode::class));
        self::assertSame(0, $this->sender->count());
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
     * Run the change once as the request's transaction begins, between its
     * check and its lock.
     *
     * @param  \Closure(): mixed  $change
     * @return void
     */
    private static function beforeTheLock(\Closure $change): void
    {
        $done = false;

        Event::listen(TransactionBeginning::class, static function () use (&$done, $change): void {
            if ($done) {
                return;
            }

            $done = true;

            $change();
        });
    }

    /**
     * Assert that the counters the request wrote hold no attempt.
     *
     * @return void
     */
    private static function assertNoSlotKept(): void
    {
        self::assertGreaterThan(0, self::rows('rate_limits'));
        self::assertSame(0, (int) DB::table('rate_limits')->sum('hits'));
    }
}
