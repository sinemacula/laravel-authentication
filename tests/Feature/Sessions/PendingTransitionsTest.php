<?php

declare(strict_types = 1);

namespace Tests\Feature\Sessions;

use Carbon\CarbonImmutable;
use Firebase\JWT\JWT;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Admission\Admitted;
use SineMacula\Laravel\Authentication\Database\AfterCommit;
use SineMacula\Laravel\Authentication\Events\Enums\AuthenticationFlow;
use SineMacula\Laravel\Authentication\Events\SessionReturnedToPending;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenHasher;
use SineMacula\Laravel\Authentication\Models\Session;
use SineMacula\Laravel\Authentication\Sessions\Enums\PendingRequirement;
use SineMacula\Laravel\Authentication\Sessions\Enums\SessionStatus;
use SineMacula\Laravel\Authentication\Sessions\PendingTransitions;
use SineMacula\Laravel\Authentication\Sessions\ReturnedToPending;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use Tests\Concerns\InteractsWithSessions;
use Tests\TestCase;

/**
 * Feature tests for an active session's return to pending: the one
 * compare-and-swap on the row as it was loaded, what it records, the pending
 * credential it hands out, and its report once committed.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PendingTransitions::class)]
#[CoversClass(ReturnedToPending::class)]
final class PendingTransitionsTest extends TestCase
{
    use InteractsWithSessions;

    /** @var \Carbon\CarbonImmutable Frozen clock reference. */
    private CarbonImmutable $now;

    /**
     * Freeze the clocks and create the tables.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->now = CarbonImmutable::createStrict(2026, 4, 6, 12, 0, 0);

        Carbon::setTestNow($this->now);
        CarbonImmutable::setTestNow($this->now);

        JWT::$timestamp = $this->now->getTimestamp();

        $this->createSessionTables();
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
     * The session returns to pending on `mfa` with a new pending credential of
     * the configured lifetime, its floor moved to now, keeping its principal
     * and tenant; the report follows, naming no previous principal or tenant,
     * since neither changed.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnActiveSessionReturnsToPending(): void
    {
        [$member, $membership, $tenant] = $this->seedMember();

        $session = $this->signedIn();

        $this->recordEvents([SessionReturnedToPending::class]);

        $returned = $this->transitions()->returnToPending($session, new Admitted($member, $membership, $tenant), AuthenticationFlow::REFRESH, $this->now);

        self::assertNotNull($returned);
        self::assertSame([PendingRequirement::MFA], $returned->pending->requires);
        self::assertSame($this->now->addSeconds(300)->getTimestamp(), $returned->pending->expiresAt->getTimestamp());

        [$key, $secret] = explode('.', $returned->credential, 2);

        self::assertSame(IdentifierCoercion::stringify($session->getKey()), $key);

        $row = Session::query()->sole();

        self::assertSame(SessionStatus::PENDING, $row->getStatus());
        self::assertTrue(RefreshTokenHasher::verify($secret, (string) $row->getPendingKey()));
        self::assertSame($this->now->getTimestamp(), $row->getSwitchedAt()?->getTimestamp());
        self::assertSame($this->now->addSeconds(300)->getTimestamp(), $row->getIdleExpiresAt()?->getTimestamp());

        $event = $this->recordedEvent(SessionReturnedToPending::class);

        self::assertSame(AuthenticationFlow::REFRESH, $event->flow);
        self::assertNull($event->previousPrincipalId);
        self::assertNull($event->previousPrincipalMorphClass);
        self::assertNull($event->previousTenantId);
    }

    /**
     * A destination of another principal and tenant records them and reports
     * the ones the session left.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testADestinationElsewhereReportsWhatTheSessionLeft(): void
    {
        [$member, $membership, $tenant] = $this->seedMember();

        $session = $this->signedIn();

        [, $elsewhere, $other] = $this->seedMember('second@example.test');

        $this->recordEvents([SessionReturnedToPending::class]);

        self::assertNotNull($this->transitions()->returnToPending($session, new Admitted($member, $elsewhere, $other), AuthenticationFlow::REFRESH, $this->now));

        $row   = Session::query()->sole();
        $event = $this->recordedEvent(SessionReturnedToPending::class);

        self::assertSame(IdentifierCoercion::stringify($elsewhere->getKey()), $row->principal_id);
        self::assertSame(IdentifierCoercion::stringify($other->getKey()), $row->getTenantId());
        self::assertSame(IdentifierCoercion::stringify($membership->getKey()), $event->previousPrincipalId);
        self::assertSame($membership->getMorphClass(), $event->previousPrincipalMorphClass);
        self::assertSame(IdentifierCoercion::stringify($tenant->getKey()), $event->previousTenantId);
    }

    /**
     * A row that changed since it was loaded (rotated, revoked, a version
     * recorded) is left as it is, and the caller judges it again.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARowChangedSinceItWasLoadedIsLeftAlone(): void
    {
        [$member, $membership, $tenant] = $this->seedMember();

        $session = $this->signedIn();

        DB::table('authentication_sessions')->where('id', $session->getKey())->update(['tenant_policy_version' => 'v9']);

        $this->recordEvents([SessionReturnedToPending::class]);

        self::assertNull($this->transitions()->returnToPending($session, new Admitted($member, $membership, $tenant), AuthenticationFlow::REFRESH, $this->now));
        self::assertSame(SessionStatus::ACTIVE, Session::query()->sole()->getStatus());
        self::assertSame([], $this->recordedClasses());
    }

    /**
     * Register the session guards.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        assert($app instanceof Application);

        self::configureSessionGuards($app->make(ConfigRepository::class));
    }

    /**
     * The transitions of the members' guard.
     *
     * @return \SineMacula\Laravel\Authentication\Sessions\PendingTransitions
     */
    private function transitions(): PendingTransitions
    {
        return new PendingTransitions($this->freshGuard('members')->context(), new AfterCommit(static fn (): mixed => app('db.transactions')), app(ConfigRepository::class));
    }

    /**
     * Sign the seeded member in with its password and return its session.
     *
     * @return \SineMacula\Laravel\Authentication\Models\Session
     *
     * @throws \Throwable
     */
    private function signedIn(): Session
    {
        $session = $this->sessions('members')->signIn('password', self::credentials('member@example.test'))->session?->record;

        self::assertInstanceOf(Session::class, $session);

        return $session;
    }
}
