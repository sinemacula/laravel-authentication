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
use Tests\Concerns\InteractsWithRateLimits;
use Tests\Fixtures\Database\ShippedMigrations;
use Tests\TestCase;
use Tests\Unit\Stubs\StubReversingNormalizer;

/**
 * Integration tests of the database attempt limiter against the shipped
 * `rate_limits` table.
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
    use InteractsWithRateLimits;

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
     * The limiter is the container's single binding for the contract.
     *
     * @return void
     */
    public function testIsTheContainersAttemptLimiter(): void
    {
        self::assertInstanceOf(DatabaseAttemptLimiter::class, $this->limiter());
        self::assertSame($this->limiter(), $this->limiter());
    }

    /**
     * An identifier is refused once its window is full, and a refusal takes
     * nothing.
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
     * A full IP address refuses the attempt and gives the identifier's slot
     * back.
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
     * Releasing a granted reservation gives both its slots back.
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
     * A success gives back only its own slot, so earlier failures still count.
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
     * A slot given back after its window ended leaves the next window alone.
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
     * A window that has ended restarts with the next attempt.
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
     * in.
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
     * After `decay_seconds` shrinks, a counter keeps its longer window until it
     * ends.
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
     * A stored window filled between the read and the increment refuses the
     * attempt with its wait.
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
     * A stored window filled before the increment refuses the attempt, never
     * exceeding `max`.
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
     * A stored window replaced before the increment is left alone.
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
     * Rows of `[change]`: what happens to a full counter before the attempt
     * reads it.
     *
     * @return iterable<string, array{string}>
     */
    public static function provideCounterChangesBeforeTheRead(): iterable
    {
        yield 'window ended' => ['ended'];
        yield 'pruned' => ['pruned'];
    }

    /**
     * A counter that ends or is pruned before the read refuses the attempt for
     * one second.
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
     * Identifiers are counted in their canonical form.
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
     * IP addresses are counted in their canonical form.
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
     * An account is counted under its own key with the identifier's limit.
     *
     * @return void
     */
    public function testAnAccountIsCountedUnderTheIdentifiersLimit(): void
    {
        $account = new AttemptSubject(self::GUARD, AttemptFlow::SIGN_IN, null, null, null, "App\\Models\\User\x0042");
        $key     = self::counterKey('sign_in', 'per_account', "App\\Models\\User\x0042");

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
     * An account's counter is shared by every guard, each holding it to its own
     * limit.
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
     * form.
     *
     * @return void
     */
    public function testTheTypesNormalizerGivesTheCanonicalForm(): void
    {
        config()->set('authentication.identifiers.normalizers.reversed', StubReversingNormalizer::class);

        $this->limiter()->acquire($this->signIn('Abc', type: 'reversed'));

        self::assertEquals(1, self::counterHits('api', 'sign_in', 'per_identifier', 'cbA'));
    }

    /**
     * Counters are keyed digests, separate per guard, flow and scope.
     *
     * @return void
     */
    public function testCountersAreDigestsSeparatePerGuardFlowAndScope(): void
    {
        $this->limiter()->acquire($this->signIn('ben@example.com'));
        $this->limiter()->acquire(new AttemptSubject('admin', AttemptFlow::SIGN_IN, 'ben@example.com', 'email', self::IP));
        $this->limiter()->recordFailure(new AttemptSubject(self::GUARD, AttemptFlow::REFRESH, 'ben@example.com', 'email', self::IP));

        $keys = array_map(self::storedString(...), DB::table('rate_limits')->pluck('key')->all());

        self::assertCount(6, array_unique($keys));

        foreach ($keys as $key) {
            self::assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $key);
        }

        self::assertSame(self::counterKey('api', 'sign_in', 'per_identifier', 'ben@example.com'), $this->keyOf($this->signIn('ben@example.com'), 'per_identifier'));
        self::assertSame(self::counterKey('api', 'sign_in', 'per_ip', self::IP), $this->keyOf($this->signIn('ben@example.com'), 'per_ip'));
        self::assertNotContains(hash('sha256', implode("\0", ['api', 'sign_in', 'per_identifier', 'ben@example.com'])), $keys);
        self::assertNotContains(hash('sha256', implode("\0", ['api', 'sign_in', 'per_ip', self::IP])), $keys);
    }

    /**
     * Rotating the application key starts every counter afresh.
     *
     * @return void
     */
    public function testRotatingTheApplicationKeyStartsTheCountersAfresh(): void
    {
        for ($attempt = 1; $attempt <= 3; $attempt++) {
            self::assertTrue($this->limiter()->acquire($this->signIn('ben@example.com', "198.51.100.{$attempt}"))->granted());
        }

        self::assertFalse($this->limiter()->acquire($this->signIn('ben@example.com', '198.51.100.9'))->granted());

        config()->set('app.key', 'base64:' . base64_encode('a rotated application key, 32 b.'));

        self::assertTrue($this->limiter()->acquire($this->signIn('ben@example.com', '198.51.100.9'))->granted());
        self::assertSame(1, self::counterHits('api', 'sign_in', 'per_identifier', 'ben@example.com'));
    }

    /**
     * Only the known parts of a subject are counted; with neither, no query
     * runs.
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
     * `blocked()` reports the wait once refresh failures fill a window, in one
     * query.
     *
     * @return void
     */
    public function testBlockedReportsTheWaitOnceFailuresFillAWindow(): void
    {
        $session = $this->refresh('session-1');

        self::assertNull($this->limiter()->blocked($session));

        $this->limiter()->recordFailure($session);

        self::assertNull($this->limiter()->blocked($session));

        $this->limiter()->recordFailure($session);
        $this->statements = [];

        self::assertSame(30, $this->limiter()->blocked($session));
        self::assertCount(1, $this->recordedStatements());
        self::assertNull($this->limiter()->blocked($this->refresh('session-2')));

        $this->limiter()->recordFailure($session);

        self::assertSame(3, $this->hitsOf($session, 'per_identifier'));
    }

    /**
     * A full IP address blocks every session behind it, until the later full
     * window ends.
     *
     * @return void
     */
    public function testBlockedWaitsForTheLaterFullWindow(): void
    {
        config()->set('auth.guards.' . self::GUARD . '.rate_limits.refresh.per_identifier', ['max' => 1, 'decay_seconds' => 300]);

        foreach (['session-1', 'session-2', 'session-3', 'session-4'] as $session) {
            $this->limiter()->recordFailure($this->refresh($session));
        }

        self::assertSame(30, $this->limiter()->blocked($this->refresh('session-9')));
        self::assertSame(150, $this->limiter()->blocked($this->refresh('session-1')));
    }

    /**
     * Failures in an ended window no longer block, and the next starts a new
     * window.
     *
     * @return void
     */
    public function testEndedWindowsNoLongerBlock(): void
    {
        $session = $this->refresh('session-1');

        $this->limiter()->recordFailure($session);
        $this->limiter()->recordFailure($session);

        Carbon::setTestNow(Carbon::createFromTimestamp(1800000180));

        self::assertNull($this->limiter()->blocked($session));

        $this->limiter()->recordFailure($session);

        self::assertSame(1, $this->hitsOf($session, 'per_identifier'));
    }

    /**
     * A counter created concurrently is found by the retry and counted once.
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
     * on the retry.
     *
     * @return void
     */
    public function testFailureRecordedConcurrentlyIsCountedOnRetry(): void
    {
        $this->beforeFirstInsert(function (): void {
            $this->limiter()->recordFailure($this->refresh('session-1'));
        });

        $this->limiter()->recordFailure($this->refresh('session-1'));

        self::assertSame(2, $this->hitsOf($this->refresh('session-1'), 'per_identifier'));
    }

    /**
     * Attempts that fill the window concurrently leave this one refused, never
     * over the limit.
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
     * Counters are read and written only on the configured connection.
     *
     * @return void
     */
    public function testCountersLiveOnTheConfiguredConnection(): void
    {
        config()->set('database.connections.limits', ['driver' => 'sqlite', 'database' => ':memory:', 'prefix' => '']);
        config()->set('authentication.rate_limits.connection', 'limits');

        ShippedMigrations::up('2026_04_06_000002_create_rate_limits_table.php');

        $this->limiter()->acquire($this->signIn('ben@example.com'));

        self::assertSame(2, DB::connection('limits')->table('rate_limits')->count());
        self::assertSame(0, DB::table('rate_limits')->count());
    }

    /**
     * A database error propagates.
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
     * A refresh of the session on the guard.
     *
     * @param  string  $session
     * @return \SineMacula\Laravel\Authentication\RateLimiting\AttemptSubject
     */
    private function refresh(string $session): AttemptSubject
    {
        return new AttemptSubject(self::GUARD, AttemptFlow::REFRESH, $session, null, self::IP);
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
     * The hits of the guard's sign-in counter for the canonical IP address, 0
     * when it has none.
     *
     * @param  string  $canonicalIp
     * @return int
     */
    private function hitsOfIp(string $canonicalIp): int
    {
        return self::counterHits(self::GUARD, 'sign_in', 'per_ip', $canonicalIp);
    }

    /**
     * The key of the subject's counter, computed from the documented digest
     * rather than by the limiter.
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

        return self::counterKey($subject->guard, $subject->flow->value, $scope, (string) $value);
    }

    /**
     * Set the length of the guard's sign-in windows per identifier.
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
     * Run a callback once, before the first statement containing the word on
     * the default connection.
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
     * Run a callback once, before the first conditional increment of a
     * counter's stored window.
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
     * Run a callback once, before the first insert of a counter on the default
     * connection.
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
