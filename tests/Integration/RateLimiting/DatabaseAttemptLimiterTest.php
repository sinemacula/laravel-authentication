<?php

declare(strict_types = 1);

namespace Tests\Integration\RateLimiting;

use Carbon\Carbon;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Database\QueryException;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\AttemptLimiter;
use SineMacula\Laravel\Authentication\RateLimiting\AttemptReservation;
use SineMacula\Laravel\Authentication\RateLimiting\AttemptSubject;
use SineMacula\Laravel\Authentication\RateLimiting\DatabaseAttemptLimiter;
use SineMacula\Laravel\Authentication\RateLimiting\Enums\AttemptFlow;
use SineMacula\Laravel\Authentication\RateLimiting\RateLimitStore;
use Tests\TestCase;
use Tests\Unit\Stubs\StubReversingNormaliser;

/**
 * Integration tests for the database attempt limiter against the shipped
 * `rate_limits` table, on whichever engine the suite runs against.
 *
 * The `api` guard allows 3 sign-in attempts per identifier and 5 per IP address
 * in 300-second windows, and 2 refresh failures per device and 4 per IP address
 * in 60-second windows. The clock starts 150 seconds into a sign-in window.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DatabaseAttemptLimiter::class)]
#[CoversClass(RateLimitStore::class)]
final class DatabaseAttemptLimiterTest extends TestCase
{
    /** @var string Guard the limits are configured on. */
    private const string GUARD = 'api';

    /** @var string IP address of most attempts. */
    private const string IP = '203.0.113.7';

    /** @var list<string> SQL run since the last reset. */
    private array $statements = [];

    /**
     * Freeze the clock inside a sign-in window and record the statements run.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        Carbon::setTestNow(Carbon::createFromTimestamp(1800000150));

        DB::listen(function (QueryExecuted $query): void {
            $this->statements[] = $query->sql;
        });
    }

    /**
     * Release the clock.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Carbon::setTestNow();

        parent::tearDown();
    }

    /**
     * The limiter is the container's binding for the contract, one instance for
     * the application.
     *
     * @return void
     */
    public function testIsTheContainersAttemptLimiter(): void
    {
        self::assertInstanceOf(DatabaseAttemptLimiter::class, $this->limiter());
        self::assertSame($this->limiter(), $this->limiter());
    }

    /**
     * An identifier gets its limit of attempts in a window, then is refused
     * until the window ends, and a refusal takes nothing.
     *
     * @return void
     */
    public function testIdentifierIsRefusedOnceItsWindowIsFull(): void
    {
        for ($attempt = 1; $attempt <= 3; $attempt++) {
            self::assertTrue($this->limiter()->acquire($this->signIn('ben@example.com', "198.51.100.{$attempt}"))->granted());
        }

        $refused = $this->limiter()->acquire($this->signIn('ben@example.com', '198.51.100.9'));

        self::assertFalse($refused->granted());
        self::assertSame(150, $refused->retryAfter);
        self::assertSame([], $refused->windows);
        self::assertSame([1, 1, 1, 3], $this->hits());
    }

    /**
     * The IP address has its own, larger limit across identifiers, and when it
     * is full the identifier's slot just taken is given back.
     *
     * @return void
     */
    public function testFullIpAddressRefusesAndGivesTheIdentifierSlotBack(): void
    {
        foreach (['a', 'b', 'c', 'd', 'e'] as $name) {
            self::assertTrue($this->limiter()->acquire($this->signIn("{$name}@example.com"))->granted());
        }

        $refused = $this->limiter()->acquire($this->signIn('f@example.com'));

        self::assertSame(150, $refused->retryAfter);
        self::assertSame(0, $this->hitsOf($this->signIn('f@example.com'), 'per_identifier'));
        self::assertSame(5, $this->hitsOf($this->signIn('f@example.com'), 'per_ip'));
    }

    /**
     * A granted reservation records the window of each slot it took, and giving
     * it back returns both slots.
     *
     * @return void
     */
    public function testReleaseGivesBothSlotsBack(): void
    {
        $reservation = $this->limiter()->acquire($this->signIn('ben@example.com'));

        self::assertNull($reservation->retryAfter);
        self::assertCount(2, $reservation->windows);
        self::assertSame([1, 1], $this->hits());

        $this->limiter()->release($reservation);

        self::assertSame([0, 0], $this->hits());

        $this->limiter()->release($reservation);

        self::assertSame([0, 0], $this->hits());
    }

    /**
     * A success gives back only its own slot: the failures before it still
     * count until their window ends.
     *
     * @return void
     */
    public function testSuccessDoesNotForgiveEarlierFailures(): void
    {
        $this->limiter()->acquire($this->signIn('ben@example.com'));
        $this->limiter()->acquire($this->signIn('ben@example.com'));
        $this->limiter()->release($this->limiter()->acquire($this->signIn('ben@example.com')));

        self::assertTrue($this->limiter()->acquire($this->signIn('ben@example.com'))->granted());
        self::assertFalse($this->limiter()->acquire($this->signIn('ben@example.com'))->granted());
    }

    /**
     * A slot given back after its window ended leaves the next window alone, so
     * a late success cannot make room in a window it never counted in.
     *
     * @return void
     */
    public function testReleaseAfterTheWindowEndedLeavesTheNextWindowAlone(): void
    {
        $late = $this->limiter()->acquire($this->signIn('ben@example.com'));

        Carbon::setTestNow(Carbon::createFromTimestamp(1800000300));

        $this->limiter()->acquire($this->signIn('ben@example.com'));
        $this->limiter()->release($late);

        self::assertSame([1, 1], $this->hits());
    }

    /**
     * A window that has ended restarts with the next attempt, which is the
     * first of the new window.
     *
     * @return void
     */
    public function testNextWindowStartsAfresh(): void
    {
        for ($attempt = 0; $attempt < 3; $attempt++) {
            $this->limiter()->acquire($this->signIn('ben@example.com'));
        }

        Carbon::setTestNow(Carbon::createFromTimestamp(1800000299));

        self::assertSame(1, $this->limiter()->acquire($this->signIn('ben@example.com'))->retryAfter);

        Carbon::setTestNow(Carbon::createFromTimestamp(1800000300));

        self::assertTrue($this->limiter()->acquire($this->signIn('ben@example.com'))->granted());
        self::assertSame(1, $this->hitsOf($this->signIn('ben@example.com'), 'per_identifier'));
    }

    /**
     * After `decay_seconds` grows, a counter keeps the window it was started
     * in: the next attempt counts in that window and records it, so its slot
     * goes back to the window it came from.
     *
     * @return void
     */
    public function testASlotTakenAfterTheWindowGrewGoesBackToItsStoredWindow(): void
    {
        $this->limiter()->acquire($this->signIn('ben@example.com'));

        $this->setIdentifierDecay(600);

        $reservation = $this->limiter()->acquire($this->signIn('ben@example.com'));
        $key         = $this->keyOf($this->signIn('ben@example.com'), 'per_identifier');

        self::assertSame($this->windowAt(1800000300), $reservation->windows[$key]);
        self::assertSame(2, $this->hitsOf($this->signIn('ben@example.com'), 'per_identifier'));

        $this->limiter()->release($reservation);

        self::assertSame(1, $this->hitsOf($this->signIn('ben@example.com'), 'per_identifier'));
        self::assertSame($this->windowAt(1800000300), $this->storedWindowOf($key));
    }

    /**
     * After `decay_seconds` shrinks, a counter keeps its longer window too:
     * attempts count in it, a slot goes back to it, and once it is full the
     * wait is until it ends rather than until the shorter window would.
     *
     * @return void
     */
    public function testAWindowThatShrankIsKeptUntilItEnds(): void
    {
        $this->setIdentifierDecay(600);

        $this->limiter()->acquire($this->signIn('ben@example.com'));
        $this->limiter()->acquire($this->signIn('ben@example.com'));

        $this->setIdentifierDecay(300);

        $reservation = $this->limiter()->acquire($this->signIn('ben@example.com'));
        $key         = $this->keyOf($this->signIn('ben@example.com'), 'per_identifier');

        self::assertSame($this->windowAt(1800000600), $reservation->windows[$key]);

        $this->statements = [];

        $refused = $this->limiter()->acquire($this->signIn('ben@example.com'));

        self::assertSame(450, $refused->retryAfter);
        self::assertCount(4, $this->recordedStatements());
        self::assertSame(3, $this->hitsOf($this->signIn('ben@example.com'), 'per_identifier'));

        $this->limiter()->release($reservation);

        self::assertSame(2, $this->hitsOf($this->signIn('ben@example.com'), 'per_identifier'));
    }

    /**
     * A stored window filled by other attempts between the read and the
     * attempt's own increment refuses the attempt with that window's wait.
     *
     * @return void
     */
    public function testAStoredWindowFilledConcurrentlyRefusesTheAttempt(): void
    {
        $this->setIdentifierDecay(600);
        $this->limiter()->acquire($this->signIn('ben@example.com'));
        $this->setIdentifierDecay(300);

        $key = $this->keyOf($this->signIn('ben@example.com'), 'per_identifier');

        $this->beforeFirst('select', static function () use ($key): void {
            DB::table('rate_limits')->where('key', $key)->update(['hits' => 3]);
        });

        $refused = $this->limiter()->acquire($this->signIn('ben@example.com'));

        self::assertSame(450, $refused->retryAfter);
        self::assertSame(3, $this->hitsOf($this->signIn('ben@example.com'), 'per_identifier'));
    }

    /**
     * A stored window that other attempts fill between the read and the
     * attempt's own increment refuses the attempt: the increment counts only
     * while the window has room, so concurrent attempts never exceed `max`.
     *
     * @return void
     */
    public function testAStoredWindowFilledBeforeTheIncrementRefusesTheAttempt(): void
    {
        $this->setIdentifierDecay(600);
        $this->limiter()->acquire($this->signIn('ben@example.com'));
        $this->setIdentifierDecay(300);

        $key = $this->keyOf($this->signIn('ben@example.com'), 'per_identifier');

        $this->beforeTheStoredWindowIncrement(static function () use ($key): void {
            DB::table('rate_limits')->where('key', $key)->update(['hits' => 3]);
        });

        $refused = $this->limiter()->acquire($this->signIn('ben@example.com'));

        self::assertFalse($refused->granted());
        self::assertSame(450, $refused->retryAfter);
        self::assertSame(3, $this->hitsOf($this->signIn('ben@example.com'), 'per_identifier'));
        self::assertSame(1, $this->hitsOf($this->signIn('ben@example.com'), 'per_ip'));
    }

    /**
     * A stored window replaced by a later one between the read and the
     * attempt's own increment is left alone: the increment counts only in the
     * window it read, which is the one a reservation records, so a slot is
     * never taken from a window it could not be given back to.
     *
     * @return void
     */
    public function testAStoredWindowReplacedBeforeTheIncrementIsLeftAlone(): void
    {
        $this->setIdentifierDecay(600);
        $this->limiter()->acquire($this->signIn('ben@example.com'));
        $this->setIdentifierDecay(300);

        $key  = $this->keyOf($this->signIn('ben@example.com'), 'per_identifier');
        $next = $this->windowAt(1800000900);

        $this->beforeTheStoredWindowIncrement(static function () use ($key, $next): void {
            DB::table('rate_limits')->where('key', $key)->update(['hits' => 1, 'window_ends_at' => $next]);
        });

        $refused = $this->limiter()->acquire($this->signIn('ben@example.com'));

        self::assertFalse($refused->granted());
        self::assertSame(450, $refused->retryAfter);
        self::assertSame(1, $this->hitsOf($this->signIn('ben@example.com'), 'per_identifier'));
        self::assertSame($next, $this->storedWindowOf($key));
    }

    /**
     * Rows of `[change]`: what happens to a full counter between the attempt's
     * statements and its read.
     *
     * @return iterable<string, array{string}>
     */
    public static function provideCounterChangesBeforeTheRead(): iterable
    {
        yield 'window ended' => ['ended'];
        yield 'pruned' => ['pruned'];
    }

    /**
     * A full counter whose window ends, or that is pruned, between the
     * attempt's statements refuses the attempt for one second, never for a
     * window that is already over.
     *
     * @param  string  $change
     * @return void
     */
    #[DataProvider('provideCounterChangesBeforeTheRead')]
    public function testACounterThatEndedBeforeItWasReadRefusesForOneSecond(string $change): void
    {
        for ($attempt = 1; $attempt <= 3; $attempt++) {
            $this->limiter()->acquire($this->signIn('ben@example.com', "198.51.100.{$attempt}"));
        }

        $key    = $this->keyOf($this->signIn('ben@example.com'), 'per_identifier');
        $window = $this->windowAt(1800000150);

        $this->beforeFirst('select', static function () use ($change, $key, $window): void {

            $counter = DB::table('rate_limits')->where('key', $key);

            $change === 'pruned' ? $counter->delete() : $counter->update(['window_ends_at' => $window]);
        });

        $refused = $this->limiter()->acquire($this->signIn('ben@example.com'));

        self::assertSame(1, $refused->retryAfter);
        self::assertSame(0, $this->hitsOf($this->signIn('ben@example.com'), 'per_ip'));
    }

    /**
     * Identifiers are counted in their canonical form: through the normaliser
     * of their type, so every casing and padding of an address shares one
     * counter, and without one (or for a value it rejects) trimmed and
     * lower-cased with invalid UTF-8 replaced.
     *
     * @return void
     */
    public function testIdentifiersAreCountedInTheirCanonicalForm(): void
    {
        $this->limiter()->acquire($this->signIn('Ben@Example.com'));
        $this->limiter()->acquire($this->signIn('  ben@EXAMPLE.COM '));

        self::assertSame(2, $this->hitsOf($this->signIn('ben@example.com'), 'per_identifier'));

        $this->limiter()->acquire($this->signIn(' Member-42 ', type: 'member_number'));
        $this->limiter()->acquire($this->signIn('member-42', type: null));

        self::assertSame(2, $this->hitsOf($this->signIn('MEMBER-42', type: null), 'per_identifier'));

        $this->limiter()->acquire($this->signIn("Bad\xC3\x28 ", '198.51.100.1', null));
        $this->limiter()->acquire($this->signIn(' BAD?(', '198.51.100.2', 'email'));

        self::assertSame(2, $this->hitsOf($this->signIn('bad?(', type: null), 'per_identifier'));

        $this->limiter()->acquire($this->signIn('ÉMILE@Exemple.fr', '198.51.100.3', null));
        $this->limiter()->acquire($this->signIn('émile@exemple.FR', '198.51.100.4', null));

        self::assertSame(2, $this->hitsOf($this->signIn('émile@exemple.fr', type: null), 'per_identifier'));
    }

    /**
     * IP addresses are counted in their canonical form: every address of an
     * IPv6 /64 network, however it is written, shares one counter, an
     * IPv4-mapped address and an IPv4 client translated through the NAT64
     * well-known prefix share their IPv4 address's counter (so IPv4 clients
     * seen over IPv6 are not all one /64), an address under any other
     * translation prefix counts by its /64, and anything that is not an address
     * is counted as given.
     *
     * @return void
     */
    public function testIpAddressesAreCountedInTheirCanonicalForm(): void
    {
        $ips = [
            '2001:db8:1:2::1', '2001:DB8:1:2:ffff:ffff:ffff:fffe', '2001:0db8:0001:0002:0:0:0:9', '2001:db8:1:3::1',
            '::ffff:198.51.100.7', '198.51.100.7', '64:ff9b::c633:6407', '64:ff9b::192.0.2.1', '64:FF9B::C000:201',
            '64:ff9b::cb00:7107', '64:ff9b:1::c000:201', 'Not An Address',
        ];

        foreach ($ips as $attempt => $ip) {
            self::assertTrue($this->limiter()->acquire($this->signIn("user{$attempt}@example.com", $ip))->granted());
        }

        self::assertSame(3, $this->hitsOfIp('2001:db8:1:2::/64'));
        self::assertSame(1, $this->hitsOfIp('2001:db8:1:3::/64'));
        self::assertSame(3, $this->hitsOfIp('198.51.100.7'));
        self::assertSame(2, $this->hitsOfIp('192.0.2.1'));
        self::assertSame(1, $this->hitsOfIp('203.0.113.7'));
        self::assertSame(0, $this->hitsOfIp('64:ff9b::/64'));
        self::assertSame(1, $this->hitsOfIp('64:ff9b:1::/64'));
        self::assertSame(1, $this->hitsOfIp('Not An Address'));
    }

    /**
     * An account a subject names is counted under its own key, as given, with
     * the identifier's limit: three password checks use it up whatever
     * identifier found the account, and it is not counted when the identifier
     * limit is off.
     *
     * @return void
     */
    public function testAnAccountIsCountedUnderTheIdentifiersLimit(): void
    {
        $account = new AttemptSubject(self::GUARD, AttemptFlow::SIGN_IN, null, null, null, "App\\Models\\User\x0042");
        $key     = hash('sha256', implode("\0", ['sign_in', 'per_account', "App\\Models\\User\x0042"]));

        for ($attempt = 0; $attempt < 3; $attempt++) {
            self::assertTrue($this->limiter()->acquire($account)->granted());
        }

        self::assertSame(150, $this->limiter()->acquire($account)->retryAfter);
        self::assertEquals(3, DB::table('rate_limits')->where('key', $key)->value('hits'));
        self::assertSame(1, DB::table('rate_limits')->count());

        config()->set('auth.guards.' . self::GUARD . '.rate_limits.sign_in.per_identifier', null);
        $this->statements = [];

        self::assertTrue($this->limiter()->acquire($account)->granted());
        self::assertSame([], $this->recordedStatements());
    }

    /**
     * An account has one counter whichever guard checks it, held to each
     * guard's own identifier limit: three checks through `api` (limit 3) and
     * two through `admin` (limit 5) use it up for both, so adding a guard adds
     * no guesses; a guard whose identifier limit is off neither checks nor
     * counts it.
     *
     * @return void
     */
    public function testAnAccountsCounterIsSharedByEveryGuard(): void
    {
        $api   = new AttemptSubject(self::GUARD, AttemptFlow::SIGN_IN, null, null, null, "App\\Models\\User\x0042");
        $admin = new AttemptSubject('admin', AttemptFlow::SIGN_IN, null, null, null, "App\\Models\\User\x0042");

        for ($attempt = 0; $attempt < 3; $attempt++) {
            self::assertTrue($this->limiter()->acquire($api)->granted());
        }

        self::assertSame(150, $this->limiter()->acquire($api)->retryAfter);

        for ($attempt = 0; $attempt < 2; $attempt++) {
            self::assertTrue($this->limiter()->acquire($admin)->granted());
        }

        self::assertSame(150, $this->limiter()->acquire($admin)->retryAfter);
        self::assertSame(150, $this->limiter()->acquire($api)->retryAfter);
        self::assertSame(1, DB::table('rate_limits')->count());
        self::assertEquals(5, DB::table('rate_limits')->value('hits'));

        config()->set('auth.guards.admin.rate_limits.sign_in.per_identifier', null);
        $this->statements = [];

        self::assertTrue($this->limiter()->acquire($admin)->granted());
        self::assertSame([], $this->recordedStatements());
        self::assertEquals(5, DB::table('rate_limits')->value('hits'));
    }

    /**
     * A normaliser registered for the identifier's type gives the canonical
     * form, even where it differs from trimming and lower-casing.
     *
     * @return void
     */
    public function testTheTypesNormaliserGivesTheCanonicalForm(): void
    {
        config()->set('authentication.identifiers.normalisers.reversed', StubReversingNormaliser::class);

        $this->limiter()->acquire($this->signIn('Abc', type: 'reversed'));

        self::assertEquals(1, DB::table('rate_limits')->where('key', hash('sha256', "api\0sign_in\0per_identifier\0cbA"))->value('hits'));
    }

    /**
     * Counters are stored under digests, never the identifier or the IP
     * address, and are separate per guard, flow and scope (an account's alone
     * is shared by the guards).
     *
     * @return void
     */
    public function testCountersAreDigestsSeparatePerGuardFlowAndScope(): void
    {
        $this->limiter()->acquire($this->signIn('ben@example.com'));
        $this->limiter()->acquire(new AttemptSubject('admin', AttemptFlow::SIGN_IN, 'ben@example.com', 'email', self::IP));
        $this->limiter()->recordFailure(new AttemptSubject(self::GUARD, AttemptFlow::REFRESH, 'ben@example.com', 'email', self::IP));

        $keys = DB::table('rate_limits')->pluck('key')->all();

        self::assertCount(6, array_unique($keys));

        foreach ($keys as $key) {
            self::assertIsString($key);
            self::assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $key);
        }

        self::assertSame(hash('sha256', "api\0sign_in\0per_identifier\0ben@example.com"), $this->keyOf($this->signIn('ben@example.com'), 'per_identifier'));
        self::assertSame(hash('sha256', "api\0sign_in\0per_ip\0" . self::IP), $this->keyOf($this->signIn('ben@example.com'), 'per_ip'));
    }

    /**
     * An attempt without an identifier counts against the IP address only, one
     * without an IP address against the identifier only, and one with neither,
     * or on limits that are off, costs no query at all.
     *
     * @return void
     */
    public function testOnlyTheKnownPartsOfTheSubjectAreCounted(): void
    {
        $this->limiter()->acquire(new AttemptSubject(self::GUARD, AttemptFlow::SIGN_IN, null, 'email', self::IP));
        $this->limiter()->acquire(new AttemptSubject(self::GUARD, AttemptFlow::SIGN_IN, 'ben@example.com', 'email', null));

        self::assertSame([1, 1], $this->hits());

        config()->set('auth.guards.' . self::GUARD . '.rate_limits.sign_in', null);
        $this->statements = [];

        $nothing = $this->limiter()->acquire($this->signIn('ben@example.com'));
        $this->limiter()->release($nothing);

        self::assertNull($this->limiter()->blocked($this->signIn('ben@example.com')));
        $this->limiter()->recordFailure($this->signIn('ben@example.com'));

        self::assertTrue($nothing->granted());
        self::assertSame([], $nothing->windows);
        self::assertSame([], $this->recordedStatements());

        $neither = $this->limiter()->acquire(new AttemptSubject(self::GUARD, AttemptFlow::REFRESH, null, null, null));

        self::assertTrue($neither->granted());
        self::assertSame([], $this->recordedStatements());
    }

    /**
     * A reservation that was refused gives nothing back.
     *
     * @return void
     */
    public function testRefusedReservationReleasesNothing(): void
    {
        $this->limiter()->acquire($this->signIn('ben@example.com'));

        $this->statements = [];

        $this->limiter()->release(new AttemptReservation($this->signIn('ben@example.com'), 10));

        self::assertSame([], $this->recordedStatements());
        self::assertSame([1, 1], $this->hits());
    }

    /**
     * Refresh counts only failures: `blocked()` stays `null` under the limit,
     * reports the wait once a counter is full, and one query reads both.
     *
     * @return void
     */
    public function testBlockedReportsTheWaitOnceFailuresFillAWindow(): void
    {
        $device = $this->refresh('device-1');

        self::assertNull($this->limiter()->blocked($device));

        $this->limiter()->recordFailure($device);

        self::assertNull($this->limiter()->blocked($device));

        $this->limiter()->recordFailure($device);
        $this->statements = [];

        self::assertSame(30, $this->limiter()->blocked($device));
        self::assertCount(1, $this->recordedStatements());
        self::assertNull($this->limiter()->blocked($this->refresh('device-2')));

        $this->limiter()->recordFailure($device);

        self::assertSame(3, $this->hitsOf($device, 'per_identifier'));
    }

    /**
     * A full IP address blocks every device behind it; with both counters full,
     * the wait is until the later window ends.
     *
     * @return void
     */
    public function testBlockedWaitsForTheLaterFullWindow(): void
    {
        config()->set('auth.guards.' . self::GUARD . '.rate_limits.refresh.per_identifier', ['max' => 1, 'decay_seconds' => 300]);

        foreach (['device-1', 'device-2', 'device-3', 'device-4'] as $device) {
            $this->limiter()->recordFailure($this->refresh($device));
        }

        self::assertSame(30, $this->limiter()->blocked($this->refresh('device-9')));
        self::assertSame(150, $this->limiter()->blocked($this->refresh('device-1')));
    }

    /**
     * Failures in a window that has ended no longer block, and the next failure
     * starts a new window.
     *
     * @return void
     */
    public function testEndedWindowsNoLongerBlock(): void
    {
        $device = $this->refresh('device-1');

        $this->limiter()->recordFailure($device);
        $this->limiter()->recordFailure($device);

        Carbon::setTestNow(Carbon::createFromTimestamp(1800000180));

        self::assertNull($this->limiter()->blocked($device));

        $this->limiter()->recordFailure($device);

        self::assertSame(1, $this->hitsOf($device, 'per_identifier'));
    }

    /**
     * A counter created by another request between this one's first update and
     * its insert is found by the retry, so the attempt still counts once.
     *
     * @return void
     */
    public function testCounterCreatedConcurrentlyIsCountedOnRetry(): void
    {
        $this->beforeFirstInsert(fn (): AttemptReservation => $this->limiter()->acquire($this->signIn('ben@example.com', '198.51.100.1')));

        self::assertTrue($this->limiter()->acquire($this->signIn('ben@example.com'))->granted());
        self::assertSame(2, $this->hitsOf($this->signIn('ben@example.com'), 'per_identifier'));
    }

    /**
     * A failure recorded while another request creates the counter is counted
     * on the retry too.
     *
     * @return void
     */
    public function testFailureRecordedConcurrentlyIsCountedOnRetry(): void
    {
        $this->beforeFirstInsert(function (): void {
            $this->limiter()->recordFailure($this->refresh('device-1'));
        });

        $this->limiter()->recordFailure($this->refresh('device-1'));

        self::assertSame(2, $this->hitsOf($this->refresh('device-1'), 'per_identifier'));
    }

    /**
     * Attempts that fill the window between this one's statements leave it
     * refused, never over the limit.
     *
     * @return void
     */
    public function testWindowFilledConcurrentlyRefusesTheAttempt(): void
    {
        $this->beforeFirstInsert(function (): void {
            for ($attempt = 1; $attempt <= 3; $attempt++) {
                $this->limiter()->acquire($this->signIn('ben@example.com', "198.51.100.{$attempt}"));
            }
        });

        self::assertFalse($this->limiter()->acquire($this->signIn('ben@example.com'))->granted());
        self::assertSame(3, $this->hitsOf($this->signIn('ben@example.com'), 'per_identifier'));
        self::assertSame(0, $this->hitsOf($this->signIn('ben@example.com'), 'per_ip'));
    }

    /**
     * Counters live on the configured connection, and the limiter never reads
     * or writes them anywhere else.
     *
     * @return void
     */
    public function testCountersLiveOnTheConfiguredConnection(): void
    {
        config()->set('database.connections.limits', ['driver' => 'sqlite', 'database' => ':memory:', 'prefix' => '']);
        config()->set('authentication.rate_limits.connection', 'limits');

        $migration = require __DIR__ . '/../../../database/migrations/2026_04_06_000002_create_rate_limits_table.php';
        $migration->up();

        $this->limiter()->acquire($this->signIn('ben@example.com'));

        self::assertSame(2, DB::connection('limits')->table('rate_limits')->count());
        self::assertSame(0, DB::table('rate_limits')->count());
    }

    /**
     * A database error is never read as room for another attempt: it
     * propagates.
     *
     * @return void
     */
    public function testDatabaseErrorsPropagate(): void
    {
        Schema::drop('rate_limits');

        $this->expectException(QueryException::class);

        $this->limiter()->acquire($this->signIn('ben@example.com'));
    }

    /**
     * Configure the guard's limits.
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

        /** @var \Illuminate\Config\Repository $config */
        $config = $app->make(ConfigRepository::class);

        $config->set('auth.guards.' . self::GUARD, [
            'driver'      => 'jwt',
            'provider'    => 'users',
            'rate_limits' => [
                'sign_in' => [
                    'per_identifier' => ['max' => 3, 'decay_seconds' => 300],
                    'per_ip'         => ['max' => 5, 'decay_seconds' => 300],
                ],
                'refresh' => [
                    'per_identifier' => ['max' => 2, 'decay_seconds' => 60],
                    'per_ip'         => ['max' => 4, 'decay_seconds' => 60],
                ],
            ],
        ]);
        $config->set('auth.guards.admin', ['driver' => 'jwt', 'provider' => 'users']);
    }

    /**
     * The container's attempt limiter.
     *
     * @return \SineMacula\Laravel\Authentication\Contracts\AttemptLimiter
     */
    private function limiter(): AttemptLimiter
    {
        $limiter = $this->app?->make(AttemptLimiter::class);

        self::assertInstanceOf(AttemptLimiter::class, $limiter);

        return $limiter;
    }

    /**
     * A sign-in attempt on the guard.
     *
     * @param  string  $identifier
     * @param  string  $ip
     * @param  ?string  $type
     * @return \SineMacula\Laravel\Authentication\RateLimiting\AttemptSubject
     */
    private function signIn(string $identifier, string $ip = self::IP, ?string $type = 'email'): AttemptSubject
    {
        return new AttemptSubject(self::GUARD, AttemptFlow::SIGN_IN, $identifier, $type, $ip);
    }

    /**
     * A refresh of the device on the guard.
     *
     * @param  string  $device
     * @return \SineMacula\Laravel\Authentication\RateLimiting\AttemptSubject
     */
    private function refresh(string $device): AttemptSubject
    {
        return new AttemptSubject(self::GUARD, AttemptFlow::REFRESH, $device, null, self::IP);
    }

    /**
     * Every counter's hits, in ascending order.
     *
     * @return list<int>
     */
    private function hits(): array
    {
        $hits = array_map(static fn (mixed $hits): int => is_numeric($hits) ? (int) $hits : -1, DB::table('rate_limits')->pluck('hits')->all());

        sort($hits);

        return $hits;
    }

    /**
     * The hits of the subject's counter in the scope, 0 when it has none.
     *
     * @param  \SineMacula\Laravel\Authentication\RateLimiting\AttemptSubject  $subject
     * @param  string  $scope
     * @return int
     */
    private function hitsOf(AttemptSubject $subject, string $scope): int
    {
        $hits = DB::table('rate_limits')->where('key', $this->keyOf($subject, $scope))->value('hits');

        return is_numeric($hits) ? (int) $hits : 0;
    }

    /**
     * The hits of the guard's sign-in counter for the IP address in its
     * documented canonical form, 0 when it has none.
     *
     * @param  string  $canonicalIp
     * @return int
     */
    private function hitsOfIp(string $canonicalIp): int
    {
        $hits = DB::table('rate_limits')->where('key', hash('sha256', implode("\0", [self::GUARD, 'sign_in', 'per_ip', $canonicalIp])))->value('hits');

        return is_numeric($hits) ? (int) $hits : 0;
    }

    /**
     * The key of the subject's counter in the scope, computed here from the
     * documented digest and canonical forms rather than by the limiter.
     *
     * @param  \SineMacula\Laravel\Authentication\RateLimiting\AttemptSubject  $subject
     * @param  string  $scope
     * @return string
     */
    private function keyOf(AttemptSubject $subject, string $scope): string
    {
        $value = $scope === 'per_ip' ? $subject->ip : $subject->identifier;

        if ($scope === 'per_identifier' && $subject->identifierType === 'email') {
            $value = mb_strtolower(trim((string) $value));
        }

        if ($scope === 'per_identifier' && $subject->identifierType !== 'email') {
            $value = mb_strtolower(trim(mb_scrub((string) $value, 'UTF-8')), 'UTF-8');
        }

        return hash('sha256', implode("\0", [$subject->guard, $subject->flow->value, $scope, (string) $value]));
    }

    /**
     * Set the length of the guard's sign-in windows per identifier, keeping its
     * maximum.
     *
     * @param  int  $seconds
     * @return void
     */
    private function setIdentifierDecay(int $seconds): void
    {
        config()->set('auth.guards.' . self::GUARD . '.rate_limits.sign_in.per_identifier', ['max' => 3, 'decay_seconds' => $seconds]);
    }

    /**
     * A Unix time as the counters store a window's end.
     *
     * @param  int  $timestamp
     * @return string
     */
    private function windowAt(int $timestamp): string
    {
        return Carbon::createFromTimestamp($timestamp, date_default_timezone_get())->format('Y-m-d H:i:s');
    }

    /**
     * The end of the counter's window, as stored.
     *
     * @param  string  $key
     * @return ?string
     */
    private function storedWindowOf(string $key): ?string
    {
        $window = DB::table('rate_limits')->where('key', $key)->value('window_ends_at');

        return is_string($window) ? $window : null;
    }

    /**
     * Run a callback once, just before the first statement on the default
     * connection that contains the given word, as another request would between
     * this one's statements.
     *
     * @param  string  $word
     * @param  \Closure(): mixed  $callback
     * @return void
     */
    private function beforeFirst(string $word, \Closure $callback): void
    {
        $ran = false;

        DB::connection()->beforeExecuting(static function (string $query) use (&$ran, $word, $callback): void {
            if ($ran || !str_contains(strtolower($query), $word)) {
                return;
            }

            $ran = true;

            $callback();
        });
    }

    /**
     * Run a callback once, just before the first conditional increment of a
     * counter's stored window on the default connection (an update that adds
     * one without the window-moving `case`), as another request would between
     * this one's read and its increment.
     *
     * @param  \Closure(): mixed  $callback
     * @return void
     */
    private function beforeTheStoredWindowIncrement(\Closure $callback): void
    {
        $ran = false;

        DB::connection()->beforeExecuting(static function (string $query) use (&$ran, $callback): void {

            $sql = strtolower($query);

            if ($ran || !str_starts_with($sql, 'update') || !str_contains($sql, '+ 1') || str_contains($sql, 'case')) {
                return;
            }

            $ran = true;

            $callback();
        });
    }

    /**
     * Run a callback once, just before the first insert of a counter on the
     * default connection, as another request would between this one's
     * statements.
     *
     * @param  \Closure(): mixed  $callback
     * @return void
     */
    private function beforeFirstInsert(\Closure $callback): void
    {
        $ran = false;

        DB::connection()->beforeExecuting(static function (string $query) use (&$ran, $callback): void {
            if ($ran || !str_contains(strtolower($query), 'insert')) {
                return;
            }

            $ran = true;

            $callback();
        });
    }

    /**
     * The SQL run since the last reset.
     *
     * @return list<string>
     */
    private function recordedStatements(): array
    {
        return $this->statements;
    }
}
