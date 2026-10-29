<?php

declare(strict_types = 1);

namespace Tests\Feature\IdentifierChanges;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Events\QueryExecuted;
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
use Tests\TestCase;

/**
 * Feature tests for requesting a change of identifier through
 * `Auth::identifierChanges($guard)`: what a request proven by code or by link
 * writes, queues and answers, how a newer request replaces an older one through
 * any guard, the limits it is held to, the refusals it reports, and the pending
 * change it leaves, which `pending()` reads and `cancel()` removes.
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
     * Start every test from a known moment, with the fakes bound and a route
     * for change links.
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
     * A change proven by code issues a code bound to the request, writes the
     * pending change, and queues the code's delivery to the new identifier;
     * the identity keeps its address. It waits as long as the code works, the
     * shorter of the two lifetimes, and `IdentifierChangeRequested` reports it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACodeRequestQueuesTheCodeToTheNewIdentifier(): void
    {
        $identity = self::seedChangeable();

        Event::fake([IdentifierChangeRequested::class, AuthenticationFailed::class]);

        $request = $this->changes()->requestByCode($identity, 'email', ' ADA@New.Example.Test ', Reauthentication::device(self::seedDevice($identity)));
        $row     = (array) DB::table('identifier_changes')->first();

        self::assertSame([IdentifierChangeRequestStatus::SENT, null, null], [$request->status, $request->retryAfter, $request->link()]);
        self::assertTrue($this->now->addSeconds(600)->equalTo($request->expiresAt));
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
        self::assertSame([$row['request_id'], self::CODE], [$jobs[0]->requestId, $jobs[0]->issued->code]);
        self::assertTrue($jobs[0]->identity->is($identity));

        self::assertSame(1, DB::table('one_time_codes')->where('id', self::bindingDigest($binding))->count());

        Event::assertDispatched(IdentifierChangeRequested::class, fn (IdentifierChangeRequested $event): bool => $event->context->guard === 'web'
            && $event->context->identity                                                                                                === $identity
            && [$event->type, $event->identifier]                                                                                       === ['email', self::NEW_EMAIL]
            && $event->expiresAt->equalTo($this->now->addSeconds(600)));
        Event::assertNotDispatched(AuthenticationFailed::class);

        self::assertSame(1, $this->runQueued(SendIdentifierChangeCode::class));

        $message = $this->sender->sent()[0];

        self::assertSame(['web', CodePurpose::CHANGE_IDENTIFIER, 'email'], [$message->guard, $message->purpose, $message->type]);
        self::assertSame([self::NEW_EMAIL, self::CODE], [$message->identifier, $message->code]);
        self::assertTrue($identity->is($message->identity));
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
        $request  = $this->changes()->requestByCode($identity, 'email', self::NEW_EMAIL, Reauthentication::password(self::PASSWORD));

        self::assertTrue($this->now->addSeconds(300)->equalTo($request->expiresAt));
        self::assertSame('2026-04-06 12:05:00', DB::table('identifier_changes')->value('expires_at'));
    }

    /**
     * A change proven by link signs a link to the application's route, keeping
     * its parameters, that names the guard, the identity, the type, the
     * purpose, the request and the new identifier's digest, and expires with
     * the change; no code is issued or queued.
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
            Reauthentication::confirmedAt($this->now),
            'tenant.email.confirm',
            ['tenant' => 'acme', 'locale' => 'en'],
        );
        $link = (string) $request->link();

        parse_str((string) parse_url($link, PHP_URL_QUERY), $query);

        self::assertSame(IdentifierChangeRequestStatus::SENT, $request->status);
        self::assertTrue($this->now->addSeconds(3600)->equalTo($request->expiresAt));
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
     * A newer request replaces the identity's pending change of the type,
     * through any guard: its request, guard, identifier and times are written
     * over the old ones, and the old request's code is invalidated. A change of
     * another type is a change of its own.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testANewerRequestReplacesThePendingChange(): void
    {
        $identity = self::seedChangeable(self::EMAIL, self::PHONE);
        $proof    = Reauthentication::confirmedAt($this->now);

        $this->changes()->requestByCode($identity, 'email', self::NEW_EMAIL, $proof);

        $first   = self::stored('identifier_changes', 'request_id');
        $binding = CodeBinding::identifierChange('web', 'email', self::NEW_EMAIL, $identity, $first);

        $this->moveTo($this->now->addMinute());

        $this->changes('admin')->requestByLink($identity, 'email', 'ada@third.example.test', $proof, 'email.confirm');
        $this->changes()->requestByCode($identity, 'phone', self::NEW_PHONE, $proof);

        $email = (array) DB::table('identifier_changes')->where('type', 'email')->first();

        self::assertSame(2, self::rows('identifier_changes'));
        self::assertNotSame($first, $email['request_id']);
        self::assertSame(['admin', self::EMAIL, 'ada@third.example.test'], [$email['guard'], $email['previous'], $email['identifier']]);
        self::assertSame('2026-04-06 12:01:00', $email['requested_at']);
        self::assertSame(0, DB::table('one_time_codes')->where('id', self::bindingDigest($binding))->count());
        self::assertSame(1, self::rows('one_time_codes'));
    }

    /**
     * A concurrent request that inserts the identity's pending change between
     * this request's update, which found no row, and its insert, which then
     * finds one, is written over: the newest request wins.
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
            if ($raced || !str_starts_with($query->sql, 'update') || !str_contains($query->sql, 'identifier_changes')) {
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

        $this->changes()->requestByLink($identity, 'email', self::NEW_EMAIL, Reauthentication::confirmedAt($this->now), 'email.confirm');

        self::assertTrue($raced);
        self::assertSame(1, self::rows('identifier_changes'));
        self::assertSame(['web', self::NEW_EMAIL], [self::stored('identifier_changes', 'guard'), self::stored('identifier_changes', 'identifier')]);
    }

    /**
     * A code request whose binding already has a live code (only a repeated
     * request id could) is rate limited for the cooldown, and writes nothing.
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

            $request = $this->changes()->requestByCode($identity, 'email', self::NEW_EMAIL, Reauthentication::confirmedAt($this->now));
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
     * A new identifier the type's normaliser rejects is invalid, and one that
     * is the identity's current one in its normal form is unchanged; each is
     * reported with the identifier as given, and nothing is counted or written.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testInvalidAndUnchangedIdentifiersAreRefused(): void
    {
        $identity = self::seedChangeable(self::EMAIL, self::PHONE);
        $proof    = Reauthentication::confirmedAt($this->now);

        $this->recordEvents([AuthenticationFailed::class]);

        $invalid   = $this->changes()->requestByCode($identity, 'phone', '07700 900456', $proof);
        $unchanged = $this->changes()->requestByCode($identity, 'email', ' Ada@Example.Test', $proof);

        self::assertSame([IdentifierChangeRequestStatus::IDENTIFIER_INVALID, IdentifierChangeRequestStatus::IDENTIFIER_UNCHANGED], [$invalid->status, $unchanged->status]);
        self::assertSame(
            [
                [AuthenticationFlow::IDENTIFIER_CHANGE, FailureReason::INVALID_CREDENTIALS, '07700 900456'],
                [AuthenticationFlow::IDENTIFIER_CHANGE, FailureReason::INVALID_CREDENTIALS, ' Ada@Example.Test'],
            ],
            array_map(static fn (AuthenticationFailed $event): array => [$event->flow, $event->reason, $event->identifier], $this->failures()),
        );
        self::assertSame($identity, $this->failures()[0]->context->identity);
        self::assertSame(0, self::rows('rate_limits'));
        self::assertSame(0, self::rows('identifier_changes'));
    }

    /**
     * A request without a recent authentication is refused for that before its
     * identifier is looked at.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheProofIsCheckedBeforeTheIdentifier(): void
    {
        $identity = self::seedChangeable();
        $request  = $this->changes()->requestByCode($identity, 'email', self::EMAIL, Reauthentication::confirmedAt($this->now->subHour()));

        self::assertSame(IdentifierChangeRequestStatus::REAUTHENTICATION_REQUIRED, $request->status);
    }

    /**
     * An identity whose stored identifier its normaliser rejects (a legacy
     * value) may change it: it is not taken for the new one.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testALegacyIdentifierCanBeChanged(): void
    {
        $identity = self::seedChangeable(self::EMAIL, null);

        DB::table('changeable_identities')->update(['phone' => '07700 900123']);

        $request = $this->changes()->requestByCode($identity->fresh() ?? $identity, 'phone', self::NEW_PHONE, Reauthentication::confirmedAt($this->now));

        self::assertTrue($request->isSent());
        self::assertSame('07700 900123', DB::table('identifier_changes')->value('previous'));
    }

    /**
     * Requests are counted on the new identifier and on the identity, so one
     * identity cannot spray codes at many addresses, and on the IP address;
     * once the limit is used up the request is refused with the wait, before
     * anything is written.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRequestsAreLimitedPerIdentifierAndIdentity(): void
    {
        $identity = self::seedChangeable();
        $proof    = Reauthentication::confirmedAt($this->now);

        foreach (range(1, 5) as $attempt) {
            self::assertTrue($this->changes()->requestByLink($identity, 'email', "ada+{$attempt}@example.test", $proof, 'email.confirm')->isSent());
        }

        $this->recordEvents([AuthenticationFailed::class]);

        $refused = $this->changes()->requestByLink($identity, 'email', 'ada+6@example.test', $proof, 'email.confirm');

        self::assertSame([IdentifierChangeRequestStatus::RATE_LIMITED, 3600], [$refused->status, $refused->retryAfter]);
        $failure = $this->failures()[0];

        self::assertSame([FailureReason::RATE_LIMITED, 3600, 'ada+6@example.test'], [$failure->reason, $failure->retryAfter, $failure->identifier]);
        self::assertSame('ada+5@example.test', DB::table('identifier_changes')->value('identifier'));
        self::assertSame(1, self::counterHits('web', 'identifier_change', 'per_identifier', 'ada+1@example.test'));
        self::assertSame(5, self::counterHits('web', 'identifier_change', 'per_ip', self::CLIENT_IP));
    }

    /**
     * The client the caller names is the one the events carry, instead of the
     * request the guard is serving.
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

        $this->changes()->requestByLink($identity, 'email', self::NEW_EMAIL, Reauthentication::confirmedAt($this->now), 'email.confirm', client: $client);

        $event = $this->recordedEvent(IdentifierChangeRequested::class);

        self::assertSame(['198.51.100.4', 'Console/1.0'], [$event->context->client->ip, $event->context->client->userAgent]);
        self::assertSame(1, self::counterHits('web', 'identifier_change', 'per_ip', '198.51.100.4'));
    }

    /**
     * Inside a transaction the caller opened, the event and the delivery wait
     * for its commit, and a rollback undoes the request and dispatches neither.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARequestInsideACallerTransactionWaitsForItsCommit(): void
    {
        $identity = self::seedChangeable();
        $proof    = Reauthentication::confirmedAt($this->now);

        $this->recordEvents([IdentifierChangeRequested::class]);

        DB::beginTransaction();

        $this->changes()->requestByCode($identity, 'email', self::NEW_EMAIL, $proof);

        self::assertSame([], $this->recorded);
        Queue::assertNothingPushed();

        DB::rollBack();

        self::assertSame([], $this->recorded);
        Queue::assertNothingPushed();
        self::assertSame(0, self::rows('identifier_changes'));

        DB::transaction(fn (): IdentifierChangeRequest => $this->changes()->requestByCode($identity, 'email', self::NEW_EMAIL, $proof));

        self::assertSame([IdentifierChangeRequested::class], $this->recordedClasses());
        Queue::assertPushed(SendIdentifierChangeCode::class, 1);
    }

    /**
     * `pending()` reports the identity's live change of the type through this
     * guard, read on the write connection, and nothing for another guard's
     * change, an expired one, or none.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testPendingReportsTheLiveChangeOfThisGuard(): void
    {
        $identity = self::seedChangeable();

        self::assertNull($this->changes()->pending($identity, 'email'));

        $this->changes()->requestByLink($identity, 'email', self::NEW_EMAIL, Reauthentication::confirmedAt($this->now), 'email.confirm');

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
     * `cancel()` removes this guard's pending change and its code, so neither
     * it nor its link confirms anything; it reports whether there was one, and
     * leaves another guard's change alone.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testCancelRemovesThisGuardsChangeAndItsCode(): void
    {
        $identity = self::seedChangeable();

        $this->changes()->requestByCode($identity, 'email', self::NEW_EMAIL, Reauthentication::confirmedAt($this->now));

        self::assertFalse($this->changes('admin')->cancel($identity, 'email'));
        self::assertSame(1, self::rows('identifier_changes'));
        self::assertTrue($this->changes()->cancel($identity, 'email'));
        self::assertSame([0, 0], [self::rows('identifier_changes'), self::rows('one_time_codes')]);
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
}
