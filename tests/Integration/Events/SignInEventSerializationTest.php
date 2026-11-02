<?php

declare(strict_types = 1);

namespace Tests\Integration\Events;

use Carbon\CarbonImmutable;
use Firebase\JWT\JWT;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Application;
use Illuminate\Queue\Worker;
use Illuminate\Queue\WorkerOptions;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Contracts\AdditionalFactorPolicy;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\Enums\RevocationReason;
use SineMacula\Laravel\Authentication\Events\EventContext;
use SineMacula\Laravel\Authentication\Events\SessionCreated;
use SineMacula\Laravel\Authentication\Events\SessionPending;
use SineMacula\Laravel\Authentication\Events\SessionRevoked;
use SineMacula\Laravel\Authentication\Events\SignedIn;
use SineMacula\Laravel\Authentication\Factors\AdditionalFactorContext;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Models\Session;
use SineMacula\Laravel\Authentication\Sessions\Enums\SessionStatus;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;
use Tests\Concerns\InteractsWithSessions;
use Tests\Integration\Fixtures\ActivatableTenant;
use Tests\Integration\Fixtures\ActivatableTenantMember;
use Tests\Integration\Fixtures\ActivatableTenantMembership;
use Tests\Integration\Fixtures\RecordSignedInLater;
use Tests\TestCase;

/**
 * Integration tests for the sign-in events as a queued listener receives them:
 * serialised and restored, with the identity, principal, tenant and session
 * loaded again from the database as Eloquent models (so a change made while the
 * event was queued shows), or `null` once their rows are gone, and the
 * snapshot, the client, the method and the other values kept as they were,
 * whatever was deleted meanwhile; through a real queued listener, on the `sync`
 * connection and through a worker on the `database` one.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SignedIn::class)]
#[CoversClass(SessionCreated::class)]
#[CoversClass(SessionPending::class)]
#[CoversClass(AuthenticationFailed::class)]
#[CoversClass(EventContext::class)]
final class SignInEventSerializationTest extends TestCase
{
    use InteractsWithSessions;

    /** @var \Tests\Integration\Fixtures\ActivatableTenantMember The member who signs in. */
    private ActivatableTenantMember $member;

    /** @var \Tests\Integration\Fixtures\ActivatableTenantMembership The member's membership. */
    private ActivatableTenantMembership $membership;

    /** @var \Tests\Integration\Fixtures\ActivatableTenant The tenant the membership acts within. */
    private ActivatableTenant $tenant;

    /**
     * Freeze the clocks, create the tables and seed a member.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $now = CarbonImmutable::createStrict(2026, 4, 6, 12, 0, 0);

        Carbon::setTestNow($now);
        CarbonImmutable::setTestNow($now);

        JWT::$timestamp = $now->getTimestamp();

        $this->createSessionTables();

        [$this->member, $this->membership, $this->tenant] = $this->seedMember();
    }

    /**
     * Release the clocks and drop the tables.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $this->dropSessionTables();

        Carbon::setTestNow();
        CarbonImmutable::setTestNow();

        JWT::$timestamp = null;

        parent::tearDown();
    }

    /**
     * `SignedIn` and `SessionCreated` from a sign-in on a new session come back
     * with the member, membership, tenant and session reloaded, and the guard,
     * method and client unchanged.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testSignedInAndSessionCreatedRestoreTheirModels(): void
    {
        $this->recordEvents([SignedIn::class, SessionCreated::class]);

        $session = $this->sessions('members')->signIn('password', self::credentials('member@example.test'))->session;

        self::assertNotNull($session);

        $signedIn = self::roundTrip($this->recordedEvent(SignedIn::class));
        $created  = self::roundTrip($this->recordedEvent(SessionCreated::class));

        foreach ([$signedIn, $created] as $event) {
            $this->assertRestoredModels($event->context->identity, $event->context->principal, $event->context->tenant);
            self::assertSameModel($session->record, $event->context->session);
            self::assertSame('Renamed', self::clientNameOf($event->context->session));
            self::assertSame('members', $event->context->guard);
            self::assertSame('password', $event->context->method);
            self::assertEquals(new ClientContext(self::CLIENT_IP, self::CLIENT_AGENT), $event->context->client);
        }

        self::assertFalse($signedIn->refresh);
    }

    /**
     * The `SessionRevoked` (`superseded`) of a session a sign-in replaced comes
     * back with the member, membership and tenant the sign-in admitted, the
     * replaced session reloaded as revoked, the method that session records,
     * and the reason unchanged.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASupersededRevocationRestoresItsModelsAndReason(): void
    {
        $first = $this->sessions('members')->signIn('password', self::credentials('member@example.test'))->session;

        self::assertNotNull($first);

        $this->recordEvents([SessionRevoked::class]);

        $context = new SignInContext(new ClientContext(self::CLIENT_IP, self::CLIENT_AGENT), refreshToken: $first->tokens->refreshToken?->reveal());

        self::assertTrue($this->sessions('members')->start($this->member, $this->membership, 'sso', $context)->isSignedIn());

        $event = self::roundTrip($this->recordedEvent(SessionRevoked::class));

        $this->assertRestoredModels($event->context->identity, $event->context->principal, $event->context->tenant);
        self::assertSame(RevocationReason::SUPERSEDED, $event->reason);
        self::assertSameModel($first->record, $event->context->session);
        self::assertInstanceOf(Session::class, $event->context->session);
        self::assertSame('superseded', $event->context->session->getRevokedReason());
        self::assertSame('Renamed', self::clientNameOf($event->context->session));
        self::assertSame('members', $event->context->guard);
        self::assertSame('password', $event->context->method);
        self::assertEquals(new ClientContext(self::CLIENT_IP, self::CLIENT_AGENT), $event->context->client);
    }

    /**
     * `SessionPending` for a sign-in that waits for a further factor comes back
     * with its models and its pending session reloaded, still pending, and with
     * what the session waits on and when its credential expires.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testSessionPendingRestoresItsModelsAndPendingSession(): void
    {
        self::requireAFactor();

        $this->recordEvents([SessionPending::class]);

        $context = new SignInContext(new ClientContext(self::CLIENT_IP, self::CLIENT_AGENT));
        $pending = $this->sessions('members')->signIn('password', self::credentials('member@example.test'), $context)->pending;

        self::assertNotNull($pending);

        $event = self::roundTrip($this->recordedEvent(SessionPending::class));

        $this->assertRestoredModels($event->context->identity, $event->context->principal, $event->context->tenant);
        self::assertInstanceOf(Session::class, $event->context->session);
        self::assertSame($pending->id, $event->context->session->getSessionIdentifier());
        self::assertSame(SessionStatus::PENDING, $event->context->session->getStatus());
        self::assertSame('password', $event->context->method);
        self::assertEquals(new ClientContext(self::CLIENT_IP, self::CLIENT_AGENT), $event->context->client);
        self::assertSame(['mfa'], $event->requires);
        self::assertSame($pending->expiresAt->getTimestamp(), $event->expiresAt->getTimestamp());
    }

    /**
     * `AuthenticationFailed` for an `attempt()` refused because a further
     * factor is required comes back with the member, membership and tenant
     * reloaded, and its reason and identifier unchanged.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAuthenticationFailedRestoresItsModels(): void
    {
        self::requireAFactor();

        $this->recordEvents([AuthenticationFailed::class]);

        self::assertFalse($this->freshGuard('members')->attempt(self::credentials('member@example.test')));

        $event = self::roundTrip($this->recordedEvent(AuthenticationFailed::class));

        $this->assertRestoredModels($event->context->identity, $event->context->principal, $event->context->tenant);
        self::assertNull($event->context->session);
        self::assertSame(FailureReason::ADDITIONAL_FACTOR_REQUIRED, $event->reason);
        self::assertSame('password', $event->context->method);
        self::assertSame('member@example.test', $event->identifier);
        self::assertSame(self::CLIENT_IP, $event->context->client->ip);
    }

    /**
     * A queued event holds its models as identifiers and never the session's
     * secrets: no token, no refresh digest, no password hash.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAQueuedEventHoldsIdentifiersAndNoSecret(): void
    {
        $this->recordEvents([SignedIn::class]);

        $session = $this->sessions('members')->signIn('password', self::credentials('member@example.test'))->session;

        self::assertNotNull($session);

        $queued = serialize($this->recordedEvent(SignedIn::class));
        $digest = $session->record->getRefreshKey();
        $hash   = $this->member->getAuthPassword();

        self::assertNotNull($digest);
        self::assertStringContainsString('ModelIdentifier', $queued);
        self::assertStringNotContainsString($session->tokens->accessToken->reveal(), $queued);
        self::assertStringNotContainsString($session->tokens->refreshToken?->reveal(), $queued);
        self::assertStringNotContainsString($digest, $queued);
        self::assertStringNotContainsString($hash, $queued);
    }

    /**
     * The identifiers an event snapshots when it is built come back unchanged
     * after a queue, beside the models that are loaded again, and the snapshot
     * of a real sign-in holds exactly the documented keys.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheSnapshotsSurviveTheQueue(): void
    {
        $this->recordEvents([SignedIn::class]);

        $session = $this->sessions('members')->signIn('password', self::credentials('member@example.test'))->session;

        self::assertNotNull($session);

        $context = self::roundTrip($this->recordedEvent(SignedIn::class))->context;

        $keys = [
            'occurred_at', 'guard', 'method', 'ip', 'user_agent', 'identity_type', 'identity_id', 'principal_type', 'principal_id',
            'tenant_type', 'tenant_id', 'session_id', 'credential_id', 'scopes',
        ];

        self::assertSame($this->recordedEvent(SignedIn::class)->context->toArray(), $context->toArray());
        self::assertSame($keys, array_keys($context->toArray()));
        self::assertSame($this->member->getMorphClass(), $context->identityType);
        self::assertSame((string) $this->member->getKey(), $context->identityId); // @phpstan-ignore cast.string
        self::assertSame($this->membership->getMorphClass(), $context->principalType);
        self::assertSame((string) $this->membership->getKey(), $context->principalId); // @phpstan-ignore cast.string
        self::assertSame($this->tenant->getMorphClass(), $context->tenantType);
        self::assertSame((string) $this->tenant->getKey(), $context->tenantId); // @phpstan-ignore cast.string
        self::assertSame($session->record->getKey(), $context->sessionId);
        self::assertTrue(CarbonImmutable::now()->equalTo($context->occurredAt));
    }

    /**
     * An event whose session, identity, principal and tenant were all deleted
     * while it waited (a pruned session, an erased account) still restores: the
     * models are `null`, and the snapshot names them as they were.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnEventWhoseRowsWereDeletedStillRestores(): void
    {
        $this->recordEvents([SignedIn::class]);

        self::assertTrue($this->sessions('members')->signIn('password', self::credentials('member@example.test'))->isSignedIn());

        $event  = $this->recordedEvent(SignedIn::class);
        $queued = serialize($event);

        $this->deleteEverything();

        $copy = unserialize($queued);

        self::assertInstanceOf(SignedIn::class, $copy);
        self::assertNull($copy->context->identity);
        self::assertNull($copy->context->principal);
        self::assertNull($copy->context->tenant);
        self::assertNull($copy->context->session);
        self::assertSame($event->context->toArray(), $copy->context->toArray());
        self::assertFalse($copy->refresh);
    }

    /**
     * A queued listener on the `sync` connection, which serialises the event as
     * any queue does, gets it after an earlier listener deleted its rows: with
     * no models and the whole snapshot.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAQueuedListenerOnTheSyncConnectionGetsTheSnapshotOfDeletedRows(): void
    {
        config()->set('queue.default', 'sync');

        RecordSignedInLater::$received = [];

        Event::listen(SignedIn::class, fn () => $this->deleteEverything());
        Event::listen(SignedIn::class, RecordSignedInLater::class);

        $this->recordEvents([SignedIn::class]);

        self::assertTrue($this->sessions('members')->signIn('password', self::credentials('member@example.test'))->isSignedIn());

        $this->assertReceivedTheSnapshotAlone($this->recordedEvent(SignedIn::class));
    }

    /**
     * A queued listener on the `database` connection, run by a worker after the
     * rows were deleted, gets the event with no models and the whole snapshot.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAQueuedListenerRunByAWorkerGetsTheSnapshotOfDeletedRows(): void
    {
        Schema::create('jobs', static function (Blueprint $blueprint): void {
            $blueprint->id();
            $blueprint->string('queue')->index();
            $blueprint->longText('payload');
            $blueprint->unsignedTinyInteger('attempts');
            $blueprint->unsignedInteger('reserved_at')->nullable();
            $blueprint->unsignedInteger('available_at');
            $blueprint->unsignedInteger('created_at');
        });

        $this->beforeApplicationDestroyed(static fn () => Schema::dropIfExists('jobs'));

        config()->set('queue.default', 'database');
        config()->set('queue.connections.database', ['driver' => 'database', 'table' => 'jobs', 'queue' => 'default', 'retry_after' => 90]);
        config()->set('queue.failed.driver', 'null');

        RecordSignedInLater::$received = [];

        Event::listen(SignedIn::class, RecordSignedInLater::class);

        $this->recordEvents([SignedIn::class]);

        self::assertTrue($this->sessions('members')->signIn('password', self::credentials('member@example.test'))->isSignedIn());
        self::assertSame([], RecordSignedInLater::$received);

        $this->deleteEverything();

        $worker = app('queue.worker');

        self::assertInstanceOf(Worker::class, $worker);

        $worker->runNextJob('database', 'default', new WorkerOptions(sleep: 0, maxTries: 1));

        $this->assertReceivedTheSnapshotAlone($this->recordedEvent(SignedIn::class));
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

        self::configureSessionGuards($app->make(ConfigRepository::class));
    }

    /**
     * The event as a queued listener receives it, after the member, the tenant
     * and every session were renamed while it waited.
     *
     * @template TEvent of object
     *
     * @param  TEvent  $event
     * @return TEvent
     */
    private static function roundTrip(object $event): object
    {
        $queued = serialize($event);

        ActivatableTenantMember::query()->update(['email' => 'renamed@example.test']);
        ActivatableTenant::query()->update(['name' => 'Renamed']);
        Session::query()->update(['client_name' => 'Renamed']);

        $copy = unserialize($queued);

        self::assertInstanceOf($event::class, $copy);
        self::assertNotSame($event, $copy);

        return $copy;
    }

    /**
     * Delete every session, membership, member and tenant, the tenant for good.
     *
     * @return void
     */
    private function deleteEverything(): void
    {
        Session::query()->delete();
        ActivatableTenantMembership::query()->delete();
        ActivatableTenantMember::query()->delete();
        ActivatableTenant::query()->forceDelete();
    }

    /**
     * Assert the queued listener received the event once, with no models and
     * the snapshot of the event as dispatched.
     *
     * @param  \SineMacula\Laravel\Authentication\Events\SignedIn  $dispatched
     * @return void
     */
    private function assertReceivedTheSnapshotAlone(SignedIn $dispatched): void
    {
        self::assertCount(1, RecordSignedInLater::$received);

        $received = RecordSignedInLater::$received[0];

        self::assertNotSame($dispatched, $received);
        self::assertNull($received->context->identity);
        self::assertNull($received->context->principal);
        self::assertNull($received->context->tenant);
        self::assertNull($received->context->session);
        self::assertSame($dispatched->context->toArray(), $received->context->toArray());
        self::assertSame((string) $this->member->getKey(), $received->context->identityId); // @phpstan-ignore cast.string
        self::assertSame($dispatched->context->sessionId, $received->context->sessionId);
    }

    /**
     * The client name stored on a restored session.
     *
     * @param  mixed  $record
     * @return mixed
     */
    private static function clientNameOf(mixed $record): mixed
    {
        self::assertInstanceOf(Session::class, $record);

        return $record->getAttribute('client_name');
    }

    /**
     * Require a further factor of every sign-in.
     *
     * @return void
     */
    private static function requireAFactor(): void
    {
        app()->instance(AdditionalFactorPolicy::class, new class implements AdditionalFactorPolicy {
            /**
             * Always require a further factor.
             *
             * @param  \SineMacula\Laravel\Authentication\Factors\AdditionalFactorContext  $context
             * @return bool
             */
            #[\Override]
            public function requiresAdditionalFactor(AdditionalFactorContext $context): bool
            {
                return true;
            }
        });
    }

    /**
     * Assert the restored identity, principal and tenant are the seeded ones,
     * reloaded as models.
     *
     * @param  mixed  $identity
     * @param  mixed  $principal
     * @param  mixed  $tenant
     * @return void
     */
    private function assertRestoredModels(mixed $identity, mixed $principal, mixed $tenant): void
    {
        self::assertSameModel($this->member, $identity);
        self::assertSameModel($this->membership, $principal);
        self::assertSameModel($this->tenant, $tenant);
        self::assertSame('renamed@example.test', $identity->email); // @phpstan-ignore property.nonObject
        self::assertSame('Renamed', $tenant->name); // @phpstan-ignore property.nonObject
    }

    /**
     * Assert the value is a model reloaded from the database as the expected
     * one, not the instance the event was made with.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $expected
     * @param  mixed  $actual
     * @return void
     */
    private static function assertSameModel(Model $expected, mixed $actual): void
    {
        self::assertInstanceOf($expected::class, $actual);
        self::assertNotSame($expected, $actual);
        self::assertTrue($expected->is($actual));
    }
}
