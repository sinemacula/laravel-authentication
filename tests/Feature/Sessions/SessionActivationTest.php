<?php

declare(strict_types = 1);

namespace Tests\Feature\Sessions;

use Carbon\CarbonImmutable;
use Firebase\JWT\JWT;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\ConnectionResolverInterface;
use Illuminate\Database\DatabaseTransactionRecord;
use Illuminate\Database\DatabaseTransactionsManager;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Foundation\Application;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;
use Illuminate\Testing\TestResponse;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Admission\Admitted;
use SineMacula\Laravel\Authentication\Contracts\AdditionalFactorPolicy;
use SineMacula\Laravel\Authentication\Contracts\AttemptLimiter;
use SineMacula\Laravel\Authentication\Database\AfterCommit;
use SineMacula\Laravel\Authentication\Events\Enums\RevocationReason;
use SineMacula\Laravel\Authentication\Events\SessionActivated;
use SineMacula\Laravel\Authentication\Events\SessionCreated;
use SineMacula\Laravel\Authentication\Events\SessionRevoked;
use SineMacula\Laravel\Authentication\Events\SignedIn;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Factors\AdditionalFactorContext;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Jwt\Enums\Claims;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenHasher;
use SineMacula\Laravel\Authentication\Models\Session;
use SineMacula\Laravel\Authentication\RateLimiting\AttemptReservation;
use SineMacula\Laravel\Authentication\RateLimiting\AttemptSubject;
use SineMacula\Laravel\Authentication\RateLimiting\Enums\AttemptFlow;
use SineMacula\Laravel\Authentication\Requirements\Requirement;
use SineMacula\Laravel\Authentication\Requirements\RequirementPart;
use SineMacula\Laravel\Authentication\Sessions\AdmissionRecheck;
use SineMacula\Laravel\Authentication\Sessions\Enums\SessionStatus;
use SineMacula\Laravel\Authentication\Sessions\RevocationWriter;
use SineMacula\Laravel\Authentication\Sessions\SessionActivation;
use SineMacula\Laravel\Authentication\Sessions\SignedInSession;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use Tests\Concerns\InspectsIssuanceGuards;
use Tests\Concerns\InteractsWithSessions;
use Tests\Fixtures\Events\EventContextAssertions;
use Tests\Fixtures\Sessions\RecordingAttemptLimiter;
use Tests\Integration\Fixtures\ActivatableTenantMember;
use Tests\Integration\Fixtures\ActivatableTenantMembership;
use Tests\TestCase;

/**
 * Feature tests of activating a pending session on its own, against a real
 * database: what the first activation of a sign-in writes, issues, supersedes
 * and reports; a proven session superseded only while it is as it was proven;
 * a later activation moving the session's floor; and a row that changed under
 * the lock refused loudly.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SessionActivation::class)]
final class SessionActivationTest extends TestCase
{
    use InspectsIssuanceGuards, InteractsWithSessions;

    /** @var string Guard over `ActivatableTenantMember`. */
    private const string GUARD = 'members';

    /** @var \Carbon\CarbonImmutable Frozen clock reference. */
    private CarbonImmutable $now;

    /** @var bool Whether the factor policy asks for a further factor. */
    private bool $factorRequired = true;

    /**
     * Freeze the clocks, create the tables, bind a factor policy the test
     * switches, and add a route behind the members' `auth` middleware.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->freezeAt(CarbonImmutable::createStrict(2026, 4, 6, 12, 0, 0));

        $this->createSessionTables();

        app()->instance(AdditionalFactorPolicy::class, new readonly class ($this) implements AdditionalFactorPolicy {
            /**
             * Constructor.
             *
             * @param  \Tests\Feature\Sessions\SessionActivationTest  $test
             */
            public function __construct(

                /** The test whose switch the policy answers with. */
                private SessionActivationTest $test,
            ) {}

            /**
             * Answer with the test's switch.
             *
             * @param  \SineMacula\Laravel\Authentication\Factors\AdditionalFactorContext  $context
             * @return \SineMacula\Laravel\Authentication\Requirements\Requirement
             */
            #[\Override]
            public function requirementFor(AdditionalFactorContext $context): Requirement
            {
                return $this->test->isFactorRequired() ? new Requirement(new RequirementPart) : new Requirement;
            }
        });

        Route::middleware('auth:' . self::GUARD)->get('/members/me', static fn (): array => ['session' => Auth::session()?->getSessionIdentifier()]);
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
     * Whether the factor policy asks for a further factor now.
     *
     * @return bool
     */
    public function isFactorRequired(): bool
    {
        return $this->factorRequired;
    }

    /**
     * A sign-in's first activation makes the session active in place: nothing
     * outstanding, the pending credential consumed, the digest of the pair's
     * rotation id with no previous one, the idle deadline restored to the
     * configured idle lifetime from the activation, the client as its last use,
     * the principal, tenant and policy version recorded, and the proven session
     * and slots forgotten; the pair authenticates, and the activation is
     * reported as the sign-in (`SessionCreated`, then `SignedIn`, which no
     * refresh renewed), not as a reactivation.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFirstActivationStartsTheSessionInPlace(): void
    {
        [$member, $membership, $tenant] = $this->seedMember();

        $pending = $this->pendingSession();
        $client  = new ClientContext('198.51.100.20', 'Activator/2.0');

        $this->recordEvents([SessionCreated::class, SignedIn::class, SessionActivated::class, SessionRevoked::class]);

        $activated = $this->activation()->activate($pending, new Admitted($member, $membership, $tenant), 'v1', $this->actingFor($client), $this->now);

        self::assertNotNull($activated);
        self::assertSame([SessionCreated::class, SignedIn::class], $this->recordedClasses());
        self::assertFalse($this->recordedEvent(SignedIn::class)->refresh);
        self::assertTrue($membership->is($activated->principal));

        $row = Session::query()->sole();

        self::assertSame(SessionStatus::ACTIVE, $row->getStatus());
        self::assertSame([], $row->getRequires());
        self::assertNull($row->getPendingKey());
        $rotationId = self::claimsOf($activated->tokens->refreshToken?->reveal())[Claims::JWT_ID->value] ?? null;

        self::assertIsString($rotationId);
        self::assertSame(RefreshTokenHasher::hash($rotationId), $row->getRefreshKey());
        self::assertNull($row->getRawOriginal('previous_refresh_key'));
        self::assertNull($row->getRawOriginal('refresh_rotated_at'));
        self::assertSame($this->now->addMinutes(config()->integer('authentication.jwt.refresh_idle_ttl_minutes'))->getTimestamp(), $row->getIdleExpiresAt()?->getTimestamp());
        self::assertSame('198.51.100.20', $row->getRawOriginal('last_used_ip'));
        self::assertSame('Activator/2.0', $row->getRawOriginal('last_used_user_agent'));
        self::assertSame($this->now->getTimestamp(), $row->getLastUsedAt()?->getTimestamp());
        self::assertSame(IdentifierCoercion::stringify($membership->getKey()), $row->principal_id);
        self::assertSame(IdentifierCoercion::stringify($tenant->getKey()), $row->getTenantId());
        self::assertSame('v1', $row->getTenantPolicyVersion());
        self::assertNull($row->getRawOriginal('attempt_windows'));
        self::assertNull($row->getSwitchedAt());

        $this->bearer($activated->tokens->accessToken->reveal())->assertOk()->assertExactJson(['session' => $row->getKey()]);
    }

    /**
     * The activation's write of the locked pending row is the session's
     * issuance guard: it comes before the proofs are read for the pair, and the
     * pair is issued without a further write to the row.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheActivationsOwnWriteIsItsIssuanceGuard(): void
    {
        [$member, $membership, $tenant] = $this->seedMember();

        $pending    = $this->pendingSession();
        $statements = [];

        DB::listen(static function (QueryExecuted $query) use (&$statements): void {
            $statements[] = $query->sql;
        });

        $client = new ClientContext('198.51.100.20', 'Activator/2.0');

        self::assertNotNull($this->activation()->activate($pending, new Admitted($member, $membership, $tenant), null, $this->actingFor($client), $this->now));

        $writes = array_values(array_filter($statements, static fn (string $sql): bool => str_starts_with($sql, 'update')));
        $read   = array_key_first(array_filter($statements, static fn (string $sql): bool => str_contains($sql, 'group by')));

        self::assertCount(1, $writes);
        self::assertStringNotContainsString('issuance_sequence', $writes[0]);
        self::assertIsInt($read);
        self::assertLessThan($read, array_search($writes[0], $statements, true));
        self::assertSame(0, self::issuanceGuardWrites($pending->getKey()));
    }

    /**
     * A first activation supersedes the session its sign-in's client proved it
     * holds while that session is as it was proven, reporting the revocation
     * before the sign-in, with the session it was given now holding its
     * revocation as stored.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFirstActivationSupersedesTheProvenSession(): void
    {
        [$member, $membership, $tenant] = $this->seedMember();

        [$pending, $proven] = $this->provenPendingSession();

        $this->recordEvents([SessionRevoked::class, SessionCreated::class, SignedIn::class]);

        $this->activation()->activate($pending, new Admitted($member, $membership, $tenant), null, $this->actingFor(self::client()), $this->now, $proven);

        self::assertSame([SessionRevoked::class, SessionCreated::class, SignedIn::class], $this->recordedClasses());
        self::assertSame(RevocationReason::SUPERSEDED, $this->recordedEvent(SessionRevoked::class)->reason);
        EventContextAssertions::assertSession($proven, $this->recordedEvent(SessionRevoked::class)->context);
        self::assertSame(RevocationReason::SUPERSEDED->value, $proven->getRevokedReason());
        self::assertSame($this->now->getTimestamp(), $proven->getRevokedAt()?->getTimestamp());
        self::assertNull($proven->getRefreshKey());
        self::assertFalse($proven->isDirty());
        self::assertSame(RevocationReason::SUPERSEDED->value, DB::table('authentication_sessions')->where('id', $proven->getKey())->value('revoked_reason'));
        self::assertNull(DB::table('authentication_sessions')->where('id', $pending->getKey())->value('supersedes_session_id'));
        self::assertNull(DB::table('authentication_sessions')->where('id', $pending->getKey())->value('supersedes_refresh_key'));
    }

    /**
     * Rows of `[change]`, one per thing a proven session must still be for the
     * activation to supersede it.
     *
     * @return iterable<string, array{0: \Closure(\SineMacula\Laravel\Authentication\Models\Session): array<string, mixed>}>
     */
    public static function provideChangesToTheProvenSession(): iterable
    {
        yield 'rotated' => [static fn (): array => ['refresh_key' => hash('sha256', 'rotated')]];
        yield 'revoked' => [static fn (): array => ['revoked_at' => '2026-04-06 11:00:00', 'revoked_reason' => 'revoked']];
        yield 'another guard' => [static fn (): array => ['guard' => 'api']];
        yield 'another owner type' => [static fn (): array => ['authenticatable_type' => 'another-type']];
        yield 'another owner' => [static fn (): array => ['authenticatable_id' => '999999']];
        yield 'another principal type' => [static fn (): array => ['principal_type' => 'another-type']];
        yield 'another principal' => [static fn (): array => ['principal_id' => '999999']];
        yield 'returned to pending' => [static fn (): array => ['status' => 'pending']];
    }

    /**
     * A proven session that is no longer as it was proven is not superseded,
     * and the activation writes, issues and reports nothing, so its caller can
     * judge the session again without it: both rows stay as they were.
     *
     * @param  \Closure(\SineMacula\Laravel\Authentication\Models\Session): array<string, mixed>  $change
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideChangesToTheProvenSession')]
    public function testAProvenSessionThatChangedIsNotSuperseded(\Closure $change): void
    {
        [$member, $membership, $tenant] = $this->seedMember();

        [$pending, $proven] = $this->provenPendingSession();

        DB::table('authentication_sessions')->where('id', $proven->getKey())->update($change($proven));

        $row     = (array) DB::table('authentication_sessions')->where('id', $proven->getKey())->sole();
        $waiting = (array) DB::table('authentication_sessions')->where('id', $pending->getKey())->sole();

        $this->recordEvents([SessionRevoked::class, SessionCreated::class, SignedIn::class]);

        self::assertNull($this->activation()->activate($pending, new Admitted($member, $membership, $tenant), null, $this->actingFor(self::client()), $this->now, $proven));
        self::assertSame([], $this->recordedClasses());
        self::assertEquals($row, (array) DB::table('authentication_sessions')->where('id', $proven->getKey())->sole());
        self::assertEquals($waiting, (array) DB::table('authentication_sessions')->where('id', $pending->getKey())->sole());
        self::assertSame(SessionStatus::PENDING, $pending->getStatus());
    }

    /**
     * Rows of `[held]`: a sign-in that checked a credential, and so held
     * attempt-limit slots, and one `start()` began, which held none.
     *
     * @return iterable<string, array{0: bool}>
     */
    public static function provideSignInsAndTheSlotsTheyHeld(): iterable
    {
        yield 'a credential sign-in, which held slots' => [true];
        yield 'a started sign-in, which held none' => [false];
    }

    /**
     * A first activation inside a transaction queues its reports, and nothing
     * is reported before the commit; it gives nothing back itself, but hands
     * up, with the session, each slot its sign-in held, as reserved: for the
     * guard's sign-in flow, the identifier type and IP address the session
     * records, with the windows stored. A sign-in that held none hands up none.
     *
     * @param  bool  $held
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideSignInsAndTheSlotsTheyHeld')]
    public function testAFirstActivationHandsUpTheSlotsItsSignInHeld(bool $held): void
    {
        [$member, $membership, $tenant] = $this->seedMember();

        $pending = $held ? $this->pendingSession() : $this->startedPendingSession($member, $membership);
        $stored  = $pending->getRawOriginal('attempt_windows');
        $windows = is_string($stored) ? json_decode($stored, true, flags: JSON_THROW_ON_ERROR) : [];
        $limiter = new RecordingAttemptLimiter;

        self::assertIsArray($windows);
        self::assertSame($held, $windows !== []);

        app()->instance(AttemptLimiter::class, $limiter);

        $this->recordEvents([SessionCreated::class, SignedIn::class]);

        DB::beginTransaction();

        $activated = $this->activation()->activate($pending, new Admitted($member, $membership, $tenant), null, $this->actingFor(self::client()), $this->now);

        self::assertNotNull($activated);
        self::assertCount(1, $this->queuedCallbacks());
        self::assertSame([], $this->recordedClasses());

        DB::commit();

        $subject = new AttemptSubject(self::GUARD, AttemptFlow::SIGN_IN, null, 'email', self::CLIENT_IP);
        $given   = [];

        foreach ($windows as $window) {
            self::assertIsArray($window);

            $given[] = new AttemptReservation($subject, null, $window);
        }

        self::assertSame([SessionCreated::class, SignedIn::class], $this->recordedClasses());
        self::assertEquals($given, $activated->heldSlots);
        self::assertCount(0, $limiter->released);
    }

    /**
     * Activating a session that returned to pending moves its floor past every
     * token from before the return, keeps what its first activation forgot, and
     * is reported as `SessionActivated` alone; within the second the floor
     * already reaches, it moves one second further.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testALaterActivationMovesTheFloor(): void
    {
        [$member, $membership, $tenant] = $this->seedMember();

        $pending = $this->returnedSession(null);

        $this->recordEvents([SessionCreated::class, SignedIn::class, SessionActivated::class]);

        $this->activation()->activate($pending, new Admitted($member, $membership, $tenant), 'v2', $this->actingFor(self::client()), $this->now);

        self::assertSame([SessionActivated::class], $this->recordedClasses());
        self::assertSame($this->now->getTimestamp(), Session::query()->sole()->getSwitchedAt()?->getTimestamp());
        self::assertSame('v2', Session::query()->sole()->getTenantPolicyVersion());

        DB::table('authentication_sessions')->delete();

        $again = $this->returnedSession($this->now);

        $this->activation()->activate($again, new Admitted($member, $membership, $tenant), 'v2', $this->actingFor(self::client()), $this->now);

        $floor = Session::query()->sole()->getSwitchedAt();

        self::assertNotNull($floor);
        self::assertSame($this->now->addSecond()->getTimestamp(), $floor->getTimestamp());
    }

    /**
     * A row that is no longer pending with the credential it was found by,
     * under the lock its activation holds, is a fault: the activation throws
     * rather than write over it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARowThatChangedUnderTheLockIsRefused(): void
    {
        [$member, $membership, $tenant] = $this->seedMember();

        $pending = $this->pendingSession();

        DB::table('authentication_sessions')->update(['pending_key' => hash('sha256', 'another')]);

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('A pending session changed under the lock its activation holds.');

        $this->activation()->activate($pending, new Admitted($member, $membership, $tenant), null, $this->actingFor(self::client()), $this->now);
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
     * The activation of the members' guard, as the session service builds it.
     *
     * @return \SineMacula\Laravel\Authentication\Sessions\SessionActivation
     */
    private function activation(): SessionActivation
    {
        $guard = $this->freshGuard(self::GUARD);

        return new SessionActivation($guard->context(), $guard->tokens(), new AfterCommit(static fn (): mixed => app('db.transactions')), app());
    }

    /**
     * The call an activation is made for, for the client, as the session
     * service makes it for a pending action: it checks nothing itself.
     *
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Authentication\Sessions\AdmissionRecheck
     */
    private function actingFor(ClientContext $client): AdmissionRecheck
    {
        $guard = app('auth')->guard(self::GUARD);

        self::assertInstanceOf(JwtGuard::class, $guard);

        return new AdmissionRecheck(
            $guard->context(),
            $guard,
            new RevocationWriter(app(ConnectionResolverInterface::class), static fn (): mixed => app('db.transactions')),
            new AfterCommit(static fn (): mixed => app('db.transactions')),
            $client,
            $this->now,
        );
    }

    /**
     * Sign the seeded member in, waiting on a further factor, and return its
     * pending session as stored.
     *
     * @param  ?\SineMacula\Laravel\Authentication\Sessions\SignInContext  $context
     * @return \SineMacula\Laravel\Authentication\Models\Session
     *
     * @throws \Throwable
     */
    private function pendingSession(?SignInContext $context = null): Session
    {
        $this->factorRequired = true;

        $result = $this->sessions(self::GUARD)->signIn('password', self::credentials('member@example.test'), $context);

        self::assertTrue($result->isPending());

        return Session::query()->whereKey($result->pending?->id)->firstOrFail();
    }

    /**
     * Start the seeded member's session as the membership, by a method that
     * checks no credential, waiting on a further factor, and return its pending
     * session as stored.
     *
     * @param  \Tests\Integration\Fixtures\ActivatableTenantMember  $member
     * @param  \Tests\Integration\Fixtures\ActivatableTenantMembership  $membership
     * @return \SineMacula\Laravel\Authentication\Models\Session
     *
     * @throws \Throwable
     */
    private function startedPendingSession(ActivatableTenantMember $member, ActivatableTenantMembership $membership): Session
    {
        $this->factorRequired = true;

        $result = $this->sessions(self::GUARD)->start($member, $membership, 'sso');

        self::assertTrue($result->isPending());

        return Session::query()->whereKey($result->pending?->id)->firstOrFail();
    }

    /**
     * The after-commit callbacks queued on the innermost open transaction of
     * the default connection.
     *
     * @return list<callable(): mixed>
     */
    private function queuedCallbacks(): array
    {
        $manager = app('db.transactions');

        self::assertInstanceOf(DatabaseTransactionsManager::class, $manager);

        $transaction = $manager->callbackApplicableTransactions()->last();

        self::assertInstanceOf(DatabaseTransactionRecord::class, $transaction);

        return array_values($transaction->getCallbacks());
    }

    /**
     * An active session of the seeded member, and a pending one whose sign-in
     * proved it holds it, both as stored.
     *
     * @return array{0: \SineMacula\Laravel\Authentication\Models\Session, 1: \SineMacula\Laravel\Authentication\Models\Session}
     *
     * @throws \Throwable
     */
    private function provenPendingSession(): array
    {
        $this->factorRequired = false;

        $active = $this->sessions(self::GUARD)->signIn('password', self::credentials('member@example.test'))->session;

        self::assertInstanceOf(SignedInSession::class, $active);

        $pending = $this->pendingSession(new SignInContext(self::client(), refreshToken: $active->tokens->refreshToken?->reveal()));

        self::assertSame($active->record->getKey(), $pending->getAttribute('supersedes_session_id'));

        return [$pending, Session::query()->whereKey($active->record->getKey())->firstOrFail()];
    }

    /**
     * A session of the seeded member that activated once and returned to
     * pending, its floor at the time given, as stored.
     *
     * @param  ?\Carbon\CarbonImmutable  $floor
     * @return \SineMacula\Laravel\Authentication\Models\Session
     *
     * @throws \Throwable
     */
    private function returnedSession(?CarbonImmutable $floor): Session
    {
        $this->factorRequired = false;

        $active = $this->sessions(self::GUARD)->signIn('password', self::credentials('member@example.test'))->session;

        self::assertInstanceOf(SignedInSession::class, $active);

        DB::table('authentication_sessions')->where('id', $active->record->getKey())->update([
            'status'      => 'pending',
            'requires'    => '["mfa"]',
            'pending_key' => RefreshTokenHasher::hash('returned-secret'),
            'switched_at' => $floor,
        ]);

        return Session::query()->whereKey($active->record->getKey())->firstOrFail();
    }

    /**
     * The client the activations in these tests act for.
     *
     * @return \SineMacula\Laravel\Authentication\Http\ClientContext
     */
    private static function client(): ClientContext
    {
        return new ClientContext(self::CLIENT_IP, self::CLIENT_AGENT);
    }

    /**
     * Send a request with the bearer token to the protected route.
     *
     * @param  string  $token
     * @return \Illuminate\Testing\TestResponse<\Symfony\Component\HttpFoundation\Response>
     */
    private function bearer(#[\SensitiveParameter] string $token): TestResponse
    {
        Auth::forgetGuards();

        return $this->withHeaders(['Authorization' => 'Bearer ' . $token])->getJson('/members/me');
    }

    /**
     * The claims of a token, unverified.
     *
     * @param  string  $token
     * @return array<string, mixed>
     */
    private static function claimsOf(#[\SensitiveParameter] string $token): array
    {
        $claims = json_decode(JWT::urlsafeB64Decode(explode('.', $token)[1]), true);

        self::assertIsArray($claims);

        /** @var array<string, mixed> $claims */
        return $claims;
    }

    /**
     * Freeze every clock at the time.
     *
     * @param  \Carbon\CarbonImmutable  $time
     * @return void
     */
    private function freezeAt(CarbonImmutable $time): void
    {
        $this->now = $time;

        Carbon::setTestNow($time);
        CarbonImmutable::setTestNow($time);

        JWT::$timestamp = $time->getTimestamp();
    }
}
