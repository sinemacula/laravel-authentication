<?php

declare(strict_types = 1);

namespace Tests\Integration\IdentifierChanges;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Queue\ShouldBeEncrypted;
use Illuminate\Database\Eloquent\ModelNotFoundException;
use Illuminate\Foundation\Application;
use Illuminate\Queue\Attributes\DeleteWhenMissingModels;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Queue;
use Illuminate\Support\Facades\Route;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Events\IdentifierChanged;
use SineMacula\Laravel\Authentication\IdentifierChanges\IdentifierChangeNotice;
use SineMacula\Laravel\Authentication\IdentifierChanges\SendIdentifierChangeCode;
use SineMacula\Laravel\Authentication\IdentifierChanges\SendIdentifierChangeNotice;
use SineMacula\Laravel\Authentication\Sessions\Reauthentication;
use Tests\Concerns\ChangesIdentifiers;
use Tests\Integration\Fixtures\ChangeableIdentity;
use Tests\TestCase;

/**
 * Integration tests for the queued deliveries of identifier changes: the code
 * goes to the new identifier only while it and its change request are live and
 * of the guard that queued it, never to a machine, and each job survives the
 * queue encrypted, dropped when its identity is gone; the notice reaches the
 * notifier with the identity as it is when the job runs, on the configured
 * delivery queue.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SendIdentifierChangeCode::class)]
#[CoversClass(SendIdentifierChangeNotice::class)]
#[CoversClass(IdentifierChangeNotice::class)]
final class IdentifierChangeDeliveryTest extends TestCase
{
    use ChangesIdentifiers;

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
     * Both jobs are encrypted on the queue, dropped when their identity is
     * gone, and pushed on the configured delivery connection and queue.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheJobsAreEncryptedAndQueuedOnTheDeliveryQueue(): void
    {
        config()->set('authentication.delivery.queue', ['connection' => 'deliveries', 'name' => 'changes']);
        config()->set('queue.connections.deliveries', ['driver' => 'database']);

        $identity = $this->requestedByCode();

        $this->changes()->confirmByCode($identity, 'email', self::CODE);

        foreach ([SendIdentifierChangeCode::class, SendIdentifierChangeNotice::class] as $class) {
            self::assertContains(ShouldBeEncrypted::class, class_implements($class));
            self::assertNotEmpty((new \ReflectionClass($class))->getAttributes(DeleteWhenMissingModels::class));
            Queue::assertPushedOn('changes', $class, static fn (object $job): bool => $job->connection === 'deliveries'); // @phpstan-ignore property.notFound
        }
    }

    /**
     * The code is not sent once its change was confirmed, cancelled, replaced
     * by a newer request through any guard, or expired, nor once the code was
     * replaced; a retry checks again.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACodeThatNoLongerProvesItsChangeIsNotSent(): void
    {
        $identity = $this->requestedByCode();
        $job      = self::job();

        $this->changes('admin')->requestByLink($identity, 'email', 'ada@third.example.test', Reauthentication::confirmedAt($this->now), 'email.confirm');

        $job->handle(app());

        DB::table('identifier_changes')->delete();
        $this->changes()->requestByCode($identity, 'email', self::NEW_EMAIL, Reauthentication::confirmedAt($this->now));

        $live = self::job();

        $this->moveTo($this->now->addSeconds(600));

        $live->handle(app());

        self::assertSame(0, $this->sender->count());
    }

    /**
     * The code is sent while its request is the identity's pending change of
     * the guard; once another guard's request takes its place under the same
     * request it is not.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACodeIsSentOnlyForItsOwnGuardsChange(): void
    {
        $identity = $this->requestedByCode();
        $job      = self::job();

        DB::table('identifier_changes')->update(['guard' => 'admin']);

        $job->handle(app());

        self::assertSame(0, $this->sender->count());

        DB::table('identifier_changes')->update(['guard' => 'web']);

        $job->handle(app());

        self::assertSame(1, $this->sender->count());
        self::assertTrue($identity->is($this->sender->sent()[0]->identity));
    }

    /**
     * A job whose identity is deleted while it waits sends nothing when it
     * runs.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAJobWhoseIdentityIsGoneSendsNothing(): void
    {
        $identity = $this->requestedByCode();
        $job      = self::job();

        $identity->delete();

        $job->handle(app());

        self::assertSame(0, $this->sender->count());
    }

    /**
     * A job whose identity was deleted before it is taken from the queue cannot
     * be restored, which the queue answers by dropping it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAJobWhoseIdentityWasDeletedCannotBeRestored(): void
    {
        $identity = $this->requestedByCode();
        $payload  = serialize(self::job());

        $identity->delete();

        $this->expectException(ModelNotFoundException::class);

        unserialize($payload);
    }

    /**
     * The notice reaches the notifier after a queue round trip, carrying the
     * identity as stored when the job is taken from the queue.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheNoticeSurvivesTheQueue(): void
    {
        $identity = $this->requestedByCode();

        $this->recordEvents([IdentifierChanged::class]);
        $this->changes()->confirmByCode($identity, 'email', self::CODE);

        $payload = serialize(Queue::pushed(SendIdentifierChangeNotice::class)[0]);

        DB::table('changeable_identities')->update(['phone' => self::PHONE]);

        $job = unserialize($payload);

        self::assertInstanceOf(SendIdentifierChangeNotice::class, $job);

        $job->handle(app());

        $notice = $this->notifier->sent()[0];

        self::assertInstanceOf(ChangeableIdentity::class, $notice->identity);
        self::assertSame([self::EMAIL, self::NEW_EMAIL, self::PHONE], [$notice->previous, $notice->identifier, $notice->identity->phone]);
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
     * Seed an identity and request a change of its address, proven by code.
     *
     * @return \Tests\Integration\Fixtures\ChangeableIdentity
     *
     * @throws \Throwable
     */
    private function requestedByCode(): ChangeableIdentity
    {
        $identity = self::seedChangeable();

        self::assertTrue($this->changes()->requestByCode($identity, 'email', self::NEW_EMAIL, Reauthentication::confirmedAt($this->now))->isSent());

        return $identity;
    }

    /**
     * The last code delivery queued.
     *
     * @return \SineMacula\Laravel\Authentication\IdentifierChanges\SendIdentifierChangeCode
     */
    private static function job(): SendIdentifierChangeCode
    {
        $jobs = Queue::pushed(SendIdentifierChangeCode::class);
        $job  = $jobs[count($jobs) - 1];

        self::assertInstanceOf(SendIdentifierChangeCode::class, $job);

        return $job;
    }
}
