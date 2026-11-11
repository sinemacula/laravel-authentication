<?php

declare(strict_types = 1);

namespace Tests\Feature\Sessions;

use Carbon\CarbonImmutable;
use Firebase\JWT\JWT;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Foundation\Application;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversTrait;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\AdditionalFactorPolicy;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Events\Enums\RevocationReason;
use SineMacula\Laravel\Authentication\Events\SessionRevoked;
use SineMacula\Laravel\Authentication\Events\SignedOutEverywhere;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Models\Session;
use SineMacula\Laravel\Authentication\Models\SessionProvenance;
use SineMacula\Laravel\Authentication\Sessions\Concerns\EndsConnectionSessions;
use SineMacula\Laravel\Authentication\Sessions\ConnectionRevocations;
use SineMacula\Laravel\Authentication\Sessions\SessionService;
use SineMacula\Laravel\Authentication\Sessions\SignedInSession;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use Tests\Concerns\InteractsWithExternalSignIns;
use Tests\Concerns\InteractsWithSessions;
use Tests\Fixtures\Events\EventContextAssertions;
use Tests\Fixtures\Factors\AlwaysRequireAdditionalFactor;
use Tests\Integration\Fixtures\IntegrationIdentity;
use Tests\TestCase;

/**
 * Feature tests of the session revocations by connection and by link, against a
 * real database.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ConnectionRevocations::class)]
#[CoversTrait(EndsConnectionSessions::class)]
final class ConnectionRevocationsTest extends TestCase
{
    use InteractsWithExternalSignIns, InteractsWithSessions;

    /**
     * Freeze the clocks and create the tables.
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
     * Rows of `[the revocation of a connection, the reason it records]`.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @return iterable<string, array{0: \Closure(\SineMacula\Laravel\Authentication\Sessions\SessionService, string): int, 1: \SineMacula\Laravel\Authentication\Events\Enums\RevocationReason}>
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    public static function provideConnectionRevocations(): iterable
    {
        yield 'disabled' => [
            static fn (SessionService $sessions, string $connection): int => $sessions->connectionDisabled($connection),
            RevocationReason::CONNECTION_DISABLED,
        ];

        yield 'deleted' => [
            static fn (SessionService $sessions, string $connection): int => $sessions->connectionDeleted($connection),
            RevocationReason::CONNECTION_DELETED,
        ];
    }

    /**
     * A connection disabled or deleted ends every live session it established,
     * and no other.
     *
     * @param  \Closure(\SineMacula\Laravel\Authentication\Sessions\SessionService, string): int  $revoke
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\RevocationReason  $reason
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideConnectionRevocations')]
    public function testAConnectionsEndEndsEverySessionItEstablished(\Closure $revoke, RevocationReason $reason): void
    {
        $ada   = $this->seedIdentity();
        $grace = $this->seedIdentity('grace@example.test');

        $ended = [
            $this->external($ada, 'conn-a'),
            $this->external($ada, 'conn-a', 'admin'),
            $this->external($grace, 'conn-a'),
        ];

        $kept = [
            $this->external($ada, 'conn-b'),
            $this->passwordSession(),
        ];

        $this->recordEvents([SessionRevoked::class, SignedOutEverywhere::class]);

        self::assertSame(3, $revoke($this->sessions(), 'conn-a'));
        self::assertSame(array_fill(0, 3, $reason->value), $this->reasonsOf($ended));
        self::assertSame([null, null], $this->reasonsOf($kept));
        self::assertSame([SessionRevoked::class, SessionRevoked::class, SessionRevoked::class], $this->recordedClasses());
        self::assertEqualsCanonicalizing(
            array_map(static fn (Identity $identity): ?string => IdentifierCoercion::stringify($identity->getAuthIdentifier()), [$ada, $ada, $grace]),
            array_map(static fn (object $event): ?string => $event instanceof SessionRevoked ? $event->context->identityId : null, $this->recorded),
        );
    }

    /**
     * A trigger reads only what it ends.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATriggerReadsOnlyWhatItEnds(): void
    {
        $ada        = $this->seedIdentity();
        $grace      = $this->seedIdentity('grace@example.test');
        $statements = [];

        $this->external($ada, 'conn-a');
        $this->external($ada, 'conn-b');

        DB::listen(static function (QueryExecuted $query) use (&$statements): void {
            $statements[] = [$query->sql, $query->bindings];
        });

        $touching = static function (string $table) use (&$statements): array {
            $touched    = array_values(array_filter($statements, static fn (array $statement): bool => str_contains($statement[0], $table)));
            $statements = [];

            return $touched;
        };

        self::assertSame(1, $this->sessions()->connectionDisabled('conn-a'));
        self::assertSame([['conn-a']], array_column($touching('authentication_provenance'), 1));

        self::assertSame(0, $this->sessions()->connectionDisabled('conn-c'));
        self::assertSame([], $touching('authentication_sessions'));

        self::assertSame(0, $this->sessions()->linkRemoved($grace, 'conn-b', 'link-1'));
        self::assertSame([], $touching('authentication_provenance'));
    }

    /**
     * A link's trigger asks the provenance only about the identity's external
     * sessions.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testALinksTriggerAsksOnlyAboutTheIdentitysExternalSessions(): void
    {
        $ada        = $this->seedIdentity();
        $external   = IdentifierCoercion::stringify($this->external($ada, 'conn-a'));
        $password   = $this->passwordSession();
        $statements = [];

        DB::table('authentication_provenance')->insert([
            'session_id'    => IdentifierCoercion::stringify($password),
            'connection_id' => 'conn-a',
            'link_id'       => 'link-1',
        ]);

        DB::listen(static function (QueryExecuted $query) use (&$statements): void {
            if (!str_contains($query->sql, 'authentication_provenance')) {
                return;
            }

            $statements[] = $query->bindings;
        });

        self::assertSame(1, $this->sessions()->linkScopeWidened($ada, 'conn-a', 'link-1'));
        self::assertSame([[$external, 'conn-a', 'link-1']], $statements);
        self::assertSame([RevocationReason::LINK_SCOPE_WIDENED->value, null], $this->reasonsOf([$external, $password]));
    }

    /**
     * A trigger writes its connection guards before it reads any session.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATriggerWritesItsGuardsBeforeItReadsASession(): void
    {
        $ada        = $this->seedIdentity();
        $statements = [];

        $this->external($ada, 'conn-a');

        DB::listen(static function (QueryExecuted $query) use (&$statements): void {
            if (!str_contains($query->sql, 'authentication_')) {
                return;
            }

            $statements[] = $query->sql;
        });

        $guarded = static function () use (&$statements): array {
            $first      = preg_match('/^insert into [`"]authentication_connection_guards[`"]/', $statements[0] ?? '') === 1;
            $rows       = DB::table('authentication_connection_guards')->orderBy('connection_id')->orderBy('slot')->get();
            $statements = [];

            return [$first, $rows->map(static fn (object $row): string => $row->connection_id . ':' . $row->slot)->all()];
        };

        self::assertSame(1, $this->sessions()->linkRemoved($ada, 'conn-a', 'link-1'));
        self::assertSame([true, ['conn-a:26']], $guarded());

        self::assertSame(0, $this->sessions()->linkScopeWidened($ada, 'conn-b', 'link-2'));
        self::assertSame([true, ['conn-a:26', 'conn-b:32']], $guarded());

        self::assertSame(0, $this->sessions()->connectionDeleted('conn-c'));

        [$first, $guards] = $guarded();

        self::assertTrue($first);
        self::assertCount(66, $guards);
        self::assertSame(
            array_map(static fn (int $slot): string => 'conn-c:' . $slot, range(0, 63)),
            array_values(array_filter($guards, static fn (string $guard): bool => str_starts_with($guard, 'conn-c:'))),
        );

        config()->set('authentication.revocation.link_removed', false);
        config()->set('authentication.revocation.connection_disabled', false);

        self::assertSame(0, $this->sessions()->linkRemoved($ada, 'conn-d', 'link-1'));
        self::assertSame(0, $this->sessions()->connectionDisabled('conn-d'));
        self::assertSame([false, $guards], $guarded());
    }

    /**
     * A pending session the connection established ends with the rest.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPendingSessionTheConnectionEstablishedEnds(): void
    {
        app()->instance(AdditionalFactorPolicy::class, new AlwaysRequireAdditionalFactor);

        $identity = $this->seedIdentity();
        $result   = $this->sessions()->signInExternally($this->linkedResult($identity, 'conn-a'), self::requestContext());

        self::assertTrue($result->isPending());
        self::assertSame(1, $this->sessions()->connectionDisabled('conn-a'));
        self::assertSame(RevocationReason::CONNECTION_DISABLED->value, Session::query()->whereKey($result->pending?->id)->value('revoked_reason'));
    }

    /**
     * Rows of `[the link's trigger, the reason it records]`.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @return iterable<string, array{0: \Closure(\SineMacula\Laravel\Authentication\Sessions\SessionService, \SineMacula\Laravel\Authentication\Contracts\Identity, string, string): int, 1: \SineMacula\Laravel\Authentication\Events\Enums\RevocationReason}>
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    public static function provideLinkRevocations(): iterable
    {
        yield 'removed' => [
            static fn (SessionService $sessions, Identity $identity, string $connection, string $link): int => $sessions->linkRemoved($identity, $connection, $link),
            RevocationReason::LINK_REMOVED,
        ];

        yield 'scope widened' => [
            static fn (SessionService $sessions, Identity $identity, string $connection, string $link): int => $sessions->linkScopeWidened($identity, $connection, $link),
            RevocationReason::LINK_SCOPE_WIDENED,
        ];
    }

    /**
     * A link removed or widened in scope ends only the identity's sessions
     * through that link.
     *
     * @param  \Closure(\SineMacula\Laravel\Authentication\Sessions\SessionService, \SineMacula\Laravel\Authentication\Contracts\Identity, string, string): int  $revoke
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\RevocationReason  $reason
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideLinkRevocations')]
    public function testALinksEndEndsOnlyTheIdentitysSessionsThroughThatLink(\Closure $revoke, RevocationReason $reason): void
    {
        $ada   = $this->seedIdentity();
        $grace = $this->seedIdentity('grace@example.test');

        $ended = [$this->external($ada, 'conn-a'), $this->external($ada, 'conn-a', 'admin')];
        $kept  = [
            $this->external($ada, 'conn-a', link: 'link-2'),
            $this->external($ada, 'conn-b'),
            $this->external($ada, 'conn-a'),
            $this->passwordSession(),
            $this->external($grace, 'conn-a'),
        ];

        SessionProvenance::query()->whereKey(IdentifierCoercion::stringify($kept[2]))->update(['link_id' => null]);

        $this->recordEvents([SessionRevoked::class, SignedOutEverywhere::class]);

        self::assertSame(2, $revoke($this->sessions(), $ada, 'conn-a', 'link-1'));
        self::assertSame(array_fill(0, 2, $reason->value), $this->reasonsOf($ended));
        self::assertSame([null, null, null, null, null], $this->reasonsOf($kept));
        self::assertSame([SessionRevoked::class, SessionRevoked::class], $this->recordedClasses());

        foreach ($this->recorded as $event) {
            self::assertInstanceOf(SessionRevoked::class, $event);
            EventContextAssertions::assertIdentity($ada, $event->context);
            self::assertSame($reason, $event->reason);
        }
    }

    /**
     * A link's widened scope ends sessions with every trigger setting turned
     * off.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAWidenedLinkScopeIsMandatory(): void
    {
        $identity = $this->seedIdentity();
        $session  = $this->external($identity, 'conn-a');

        config()->set('authentication.revocation', [
            'connection_disabled' => false,
            'connection_deleted'  => false,
            'link_removed'        => false,
            'link_scope_widened'  => false,
        ]);

        self::assertSame(0, $this->sessions()->linkRemoved($identity, 'conn-a', 'link-1'));
        self::assertSame(1, $this->sessions()->linkScopeWidened($identity, 'conn-a', 'link-1'));
        self::assertSame([RevocationReason::LINK_SCOPE_WIDENED->value], $this->reasonsOf([$session]));
    }

    /**
     * A link's widened scope reported twice ends the sessions once.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAWidenedLinkScopeCalledTwiceEndsTheSessionsOnce(): void
    {
        $identity = $this->seedIdentity();
        $sessions = [$this->external($identity, 'conn-a'), $this->external($identity, 'conn-a')];

        $this->recordEvents([SessionRevoked::class]);

        $counts = DB::transaction(fn (): array => [
            $this->sessions()->linkScopeWidened($identity, 'conn-a', 'link-1'),
            $this->sessions()->linkScopeWidened($identity, 'conn-a', 'link-1'),
        ]);

        self::assertSame([2, 0], $counts);
        self::assertSame(0, $this->sessions()->linkScopeWidened($identity, 'conn-a', 'link-1'));
        self::assertSame(array_fill(0, 2, RevocationReason::LINK_SCOPE_WIDENED->value), $this->reasonsOf($sessions));
        self::assertCount(2, $this->recorded);
    }

    /**
     * Rows of a trigger that ends the identity's sessions through `conn-a`.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @return iterable<string, array{0: \Closure(\SineMacula\Laravel\Authentication\Sessions\SessionService, \SineMacula\Laravel\Authentication\Contracts\Identity): int}>
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    public static function provideEndingTriggers(): iterable
    {
        foreach (self::provideEveryTrigger() as $name => $trigger) {
            yield $name => [$trigger];
        }
    }

    /**
     * A trigger forgets the guard's binding to a session it ends once it
     * commits.
     *
     * @param  \Closure(\SineMacula\Laravel\Authentication\Sessions\SessionService, \SineMacula\Laravel\Authentication\Contracts\Identity): int  $trigger
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEndingTriggers')]
    public function testATriggerForgetsTheGuardBoundToASessionItEndsOnceItCommits(\Closure $trigger): void
    {
        $ada   = $this->seedIdentity();
        $ended = $this->started($ada, 'conn-a');
        $kept  = $this->started($ada, 'conn-b');
        $later = $this->started($ada, 'conn-a');
        $guard = $this->boundGuard($ended);

        try {
            DB::transaction(static function () use ($trigger, $ada): void {

                $trigger(Auth::sessions('api'), $ada);

                throw new \RuntimeException('rolled back');
            });
        } catch (\RuntimeException) {
            self::assertTrue($guard->check());
        }

        DB::transaction(static function () use ($trigger, $ada, $guard): void {

            self::assertSame(2, $trigger(Auth::sessions('api'), $ada));
            self::assertTrue($guard->check());
        });

        self::assertFalse($guard->check());
        self::assertNull($guard->session());
        self::assertFalse(Auth::guard('api')->check());
        self::assertNotContains(null, $this->reasonsOf([$ended->record->getKey(), $later->record->getKey()]));

        $this->started($ada, 'conn-a');

        $bound = $this->boundGuard($kept);

        self::assertSame(1, $trigger(Auth::sessions('api'), $ada));
        self::assertSame($kept->record->getKey(), $bound->session()?->getSessionIdentifier());
    }

    /**
     * A trigger has another guard bound to a session it ends forget it once it
     * commits.
     *
     * @param  \Closure(\SineMacula\Laravel\Authentication\Sessions\SessionService, \SineMacula\Laravel\Authentication\Contracts\Identity): int  $trigger
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEndingTriggers')]
    public function testATriggerForgetsAnotherGuardBoundToASessionItEndsOnceItCommits(\Closure $trigger): void
    {
        $ada   = $this->seedIdentity();
        $kept  = $this->started($ada, 'conn-b');
        $ended = $this->started($ada, 'conn-a', 'admin');

        [$keptGuard, $endedGuard] = $this->boundGuards($kept, $ended);

        DB::transaction(static function () use ($trigger, $ada, $endedGuard): void {

            self::assertSame(1, $trigger(Auth::sessions('api'), $ada));
            self::assertTrue($endedGuard->check());
        });

        self::assertFalse($endedGuard->check());
        self::assertNull($endedGuard->session());
        self::assertSame($kept->record->getKey(), $keptGuard->session()?->getSessionIdentifier());
    }

    /**
     * Rows of `[the trigger, which ended session the guard is bound to]`.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @return iterable<string, array{0: \Closure(\SineMacula\Laravel\Authentication\Sessions\SessionService, \SineMacula\Laravel\Authentication\Contracts\Identity): int, 1: int}>
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    public static function provideBoundEndedSessions(): iterable
    {
        foreach (self::provideEveryTrigger() as $name => $trigger) {
            yield $name . ', bound to the first session' => [$trigger, 0];
            yield $name . ', bound to the second session' => [$trigger, 1];
        }
    }

    /**
     * A listener that throws leaves the guard bound to no session the trigger
     * ended.
     *
     * @param  \Closure(\SineMacula\Laravel\Authentication\Sessions\SessionService, \SineMacula\Laravel\Authentication\Contracts\Identity): int  $trigger
     * @param  int  $bound
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideBoundEndedSessions')]
    public function testAListenerThatThrowsLeavesTheGuardBoundToNoSessionTheTriggerEnded(\Closure $trigger, int $bound): void
    {
        $ada   = $this->seedIdentity();
        $ended = [$this->started($ada, 'conn-a'), $this->started($ada, 'conn-a')];
        $guard = $this->boundGuard($ended[$bound]);

        Event::listen(SessionRevoked::class, static function (): never {
            throw new \RuntimeException('listener failed');
        });

        try {
            $trigger(Auth::sessions('api'), $ada);

            self::fail('Expected the listener to throw once the trigger committed.');
        } catch (\RuntimeException $exception) {
            self::assertSame('listener failed', $exception->getMessage());
        }

        self::assertFalse($guard->check());
        self::assertNull($guard->session());
        self::assertNotContains(null, $this->reasonsOf([$ended[0]->record->getKey(), $ended[1]->record->getKey()]));
    }

    /**
     * Rows of `[the trigger, its setting]`.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @return iterable<string, array{0: \Closure(\SineMacula\Laravel\Authentication\Sessions\SessionService, \SineMacula\Laravel\Authentication\Contracts\Identity): int, 1: string}>
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    public static function provideTriggers(): iterable
    {
        yield 'a connection disabled' => [static fn (SessionService $sessions): int => $sessions->connectionDisabled('conn-a'), 'connection_disabled'];
        yield 'a connection deleted' => [static fn (SessionService $sessions): int => $sessions->connectionDeleted('conn-a'), 'connection_deleted'];
        yield 'a link removed' => [static fn (SessionService $sessions, Identity $identity): int => $sessions->linkRemoved($identity, 'conn-a', 'link-1'), 'link_removed'];
    }

    /**
     * A trigger turned off ends nothing and reports nothing.
     *
     * @param  \Closure(\SineMacula\Laravel\Authentication\Sessions\SessionService, \SineMacula\Laravel\Authentication\Contracts\Identity): int  $trigger
     * @param  string  $setting
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideTriggers')]
    public function testATriggerTurnedOffEndsNothing(\Closure $trigger, string $setting): void
    {
        $identity = $this->seedIdentity();
        $session  = $this->external($identity, 'conn-a');

        config()->set('authentication.revocation.' . $setting, false);

        $this->recordEvents([SessionRevoked::class]);

        self::assertSame(0, $trigger($this->sessions(), $identity));
        self::assertSame([null], $this->reasonsOf([$session]));
        self::assertSame([], $this->recorded);
    }

    /**
     * A setting that is not a boolean fails closed before anything is written.
     *
     * @param  \Closure(\SineMacula\Laravel\Authentication\Sessions\SessionService, \SineMacula\Laravel\Authentication\Contracts\Identity): int  $trigger
     * @param  string  $setting
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideTriggers')]
    public function testAMalformedSettingFailsClosed(\Closure $trigger, string $setting): void
    {
        $identity = $this->seedIdentity();
        $session  = $this->external($identity, 'conn-a');

        config()->set('authentication.revocation.' . $setting, 'false');

        try {
            $trigger($this->sessions(), $identity);

            self::fail('Expected the malformed setting to be refused.');
        } catch (\InvalidArgumentException $exception) {
            self::assertSame("authentication.revocation.{$setting} must be true or false.", $exception->getMessage());
        }

        self::assertSame([null], $this->reasonsOf([$session]));
    }

    /**
     * A connection id that names nothing is refused.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnEmptyConnectionIdIsRefused(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('A connection is named by its id, which may not be empty.');

        $this->sessions()->connectionDisabled('');
    }

    /**
     * A link's trigger refuses an empty id before its setting is read.
     *
     * @param  \Closure(\SineMacula\Laravel\Authentication\Sessions\SessionService, \SineMacula\Laravel\Authentication\Contracts\Identity, string, string): int  $revoke
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\RevocationReason  $reason
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideLinkRevocations')]
    public function testALinkTriggerRefusesAnEmptyId(\Closure $revoke, RevocationReason $reason): void
    {
        $identity = $this->seedIdentity();
        $session  = $this->external($identity, 'conn-a');

        config()->set('authentication.revocation.link_removed', false);

        foreach ([['', 'link-1', 'A connection'], ['conn-a', '', 'A link']] as [$connection, $link, $what]) {
            try {
                $revoke($this->sessions(), $identity, $connection, $link);

                self::fail('Expected the empty id to be refused.');
            } catch (\InvalidArgumentException $exception) {
                self::assertSame($what . ' is named by its id, which may not be empty.', $exception->getMessage());
            }
        }

        self::assertSame([null], $this->reasonsOf([$session]));
        self::assertSame(0, Session::query()->where('revoked_reason', $reason->value)->count());
    }

    /**
     * Sessions that have already ended are neither revoked again nor counted.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testSessionsThatHaveEndedAreLeftAlone(): void
    {
        $identity = $this->seedIdentity();
        $revoked  = $this->external($identity, 'conn-a');
        $idle     = $this->external($identity, 'conn-a');
        $absolute = $this->external($identity, 'conn-a');

        Session::query()->whereKey($revoked)->update(['revoked_at' => CarbonImmutable::now(), 'revoked_reason' => 'revoked']);
        Session::query()->whereKey($idle)->update(['idle_expires_at' => CarbonImmutable::now()]);
        Session::query()->whereKey($absolute)->update(['absolute_expires_at' => CarbonImmutable::now()]);

        self::assertSame(0, $this->sessions()->linkRemoved($identity, 'conn-a', 'link-1'));
        self::assertSame(0, $this->sessions()->linkScopeWidened($identity, 'conn-a', 'link-1'));
        self::assertSame(0, $this->sessions()->connectionDeleted('conn-a'));
        self::assertSame(['revoked', null, null], $this->reasonsOf([$revoked, $idle, $absolute]));
    }

    /**
     * A session with no absolute deadline is live until its idle one.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASessionWithoutAnAbsoluteDeadlineEnds(): void
    {
        $identity = $this->seedIdentity();
        $session  = $this->external($identity, 'conn-a');

        Session::query()->whereKey($session)->update(['absolute_expires_at' => null]);

        self::assertSame(1, $this->sessions()->linkRemoved($identity, 'conn-a', 'link-1'));
    }

    /**
     * An identity that is not an Eloquent model has no sessions to end.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnIdentityThatIsNotAModelHasNoSessionsThroughALink(): void
    {
        $this->external($this->seedIdentity(), 'conn-a');

        self::assertSame(0, $this->sessions()->linkRemoved(\Mockery::mock(Identity::class), 'conn-a', 'link-1'));
        self::assertSame(0, $this->sessions()->linkScopeWidened(\Mockery::mock(Identity::class), 'conn-a', 'link-1'));
        self::assertSame(0, Session::query()->whereNotNull('revoked_at')->count());
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
     * Every trigger by name, the link's widened scope included.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @return iterable<string, \Closure(\SineMacula\Laravel\Authentication\Sessions\SessionService, \SineMacula\Laravel\Authentication\Contracts\Identity): int>
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    private static function provideEveryTrigger(): iterable
    {
        foreach (self::provideTriggers() as $name => [$trigger]) {
            yield $name => $trigger;
        }

        yield 'a link scope widened' => static fn (SessionService $sessions, Identity $identity): int => $sessions->linkScopeWidened($identity, 'conn-a', 'link-1');
    }

    /**
     * The key of a session the identity started through the connection's link
     * on the guard.
     *
     * @param  \Tests\Integration\Fixtures\IntegrationIdentity  $identity
     * @param  string  $connection
     * @param  string  $guard
     * @param  string  $link
     * @return mixed
     *
     * @throws \Throwable
     */
    private function external(IntegrationIdentity $identity, string $connection, string $guard = 'api', string $link = 'link-1'): mixed
    {
        $subject = $link === 'link-1' ? null : 'subject-' . $link;
        $session = $this->sessions($guard)->signInExternally($this->linkedResult($identity, $connection, $link, $subject), self::requestContext())->session;

        self::assertNotNull($session);

        return $session->record->getKey();
    }

    /**
     * A session the identity started through the connection on the guard.
     *
     * @param  \Tests\Integration\Fixtures\IntegrationIdentity  $identity
     * @param  string  $connection
     * @param  string  $guard
     * @return \SineMacula\Laravel\Authentication\Sessions\SignedInSession
     *
     * @throws \Throwable
     */
    private function started(IntegrationIdentity $identity, string $connection, string $guard = 'api'): SignedInSession
    {
        $session = $this->sessions($guard)->signInExternally($this->linkedResult($identity, $connection), self::requestContext())->session;

        self::assertNotNull($session);

        return $session;
    }

    /**
     * The `api` guard, resolved afresh and bound to the session.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignedInSession  $signedIn
     * @return \SineMacula\Laravel\Authentication\Guards\JwtGuard
     */
    private function boundGuard(SignedInSession $signedIn): JwtGuard
    {
        $guard = $this->freshGuard();

        $guard->login($signedIn->identity, $signedIn->principal, $signedIn->record);

        self::assertSame($signedIn->record->getKey(), $guard->session()?->getSessionIdentifier());

        return $guard;
    }

    /**
     * The key of a session the seeded identity signed in to with its password.
     *
     * @return mixed
     *
     * @throws \Throwable
     */
    private function passwordSession(): mixed
    {
        $session = Auth::sessions('api')->signIn('password', self::credentials(), self::requestContext())->session;

        self::assertNotNull($session);

        return $session->record->getKey();
    }

    /**
     * The revocation reason each session records, in the order given.
     *
     * @param  list<mixed>  $keys
     * @return list<?string>
     */
    private function reasonsOf(array $keys): array
    {
        return array_map(static function (mixed $key): ?string {
            $reason = Session::query()->whereKey($key)->value('revoked_reason');

            return is_string($reason) ? $reason : null;
        }, $keys);
    }
}
