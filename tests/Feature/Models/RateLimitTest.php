<?php

declare(strict_types = 1);

namespace Tests\Feature\Models;

use Carbon\Carbon;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Models\RateLimit;
use Tests\TestCase;

/**
 * Feature tests for the attempt counter model: its configured table and
 * connection, and pruning counters whose window has ended.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RateLimit::class)]
final class RateLimitTest extends TestCase
{
    /**
     * Release the clock and drop the shipped table, whatever table name a test
     * left configured.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Carbon::setTestNow();
        Schema::dropIfExists('rate_limits');

        parent::tearDown();
    }

    /**
     * The model reads its table and connection from the configuration each time
     * it is built; an empty connection name means the storage connection, the
     * default one unless it names another.
     *
     * @return void
     */
    public function testUsesTheConfiguredTableAndConnection(): void
    {
        self::assertSame('rate_limits', (new RateLimit)->getTable());
        self::assertNull((new RateLimit)->getConnectionName());

        config()->set('authentication.rate_limits.table', 'attempt_counters');
        config()->set('authentication.rate_limits.connection', 'limits');
        config()->set('authentication.storage.connection', 'package_store');

        self::assertSame('attempt_counters', (new RateLimit)->getTable());
        self::assertSame('limits', (new RateLimit)->getConnectionName());

        config()->set('authentication.rate_limits.connection', '');

        self::assertSame('package_store', (new RateLimit)->getConnectionName());

        config()->set('authentication.storage.connection', null);

        self::assertNull((new RateLimit)->getConnectionName());
    }

    /**
     * Connections that are neither a name nor `null` or empty.
     *
     * @return iterable<string, array{0: mixed}>
     */
    public static function provideMalformedConnections(): iterable
    {
        yield from [
            'a list of names' => [['limits']],
            'true'            => [true],
            'false'           => [false],
            'an integer'      => [1],
        ];
    }

    /**
     * A connection that is not a name fails closed instead of counting on the
     * storage connection, inside the transactions a separate connection keeps
     * the counts out of.
     *
     * @param  mixed  $connection
     * @return void
     */
    #[DataProvider('provideMalformedConnections')]
    public function testRefusesAConnectionThatIsNotAName(mixed $connection): void
    {
        config()->set('authentication.rate_limits.connection', $connection);

        try {
            new RateLimit;

            self::fail('Expected the connection to be refused.');
        } catch (\InvalidArgumentException $e) {
            self::assertSame('`authentication.rate_limits.connection` must be a connection name, or null or empty for the storage connection.', $e->getMessage());
        } finally {
            config()->set('authentication.rate_limits.connection', null);
        }
    }

    /**
     * A counter is keyed by its digest, has no timestamps, reads its hits as an
     * integer and its window end as a date, and accepts no mass assignment.
     *
     * @return void
     */
    public function testHydratesCountersByTheirDigest(): void
    {
        $key = hash('sha256', 'counter');

        DB::table('rate_limits')->insert(['key' => $key, 'hits' => 4, 'window_ends_at' => '2027-01-15 10:05:00']);

        $counter = RateLimit::query()->find($key);

        self::assertInstanceOf(RateLimit::class, $counter);
        self::assertSame(4, $counter->hits);
        self::assertSame(4, (new RateLimit)->newFromBuilder(['key' => $key, 'hits' => '4'])->hits);
        self::assertSame('2027-01-15 10:05:00', $counter->window_ends_at->format('Y-m-d H:i:s'));
        self::assertFalse($counter->usesTimestamps());
        self::assertFalse($counter->getIncrementing());
        self::assertSame('string', $counter->getKeyType());
        self::assertTrue((new RateLimit)->isGuarded('hits'));
    }

    /**
     * `model:prune` deletes the counters whose window has ended, from the
     * second it ends, and keeps the others.
     *
     * @return void
     */
    public function testPruningDeletesCountersWhoseWindowHasEnded(): void
    {
        Carbon::setTestNow(Carbon::parse('2027-01-15 10:05:00'));

        DB::table('rate_limits')->insert([
            ['key' => hash('sha256', 'ended'), 'hits' => 3, 'window_ends_at' => '2027-01-15 10:00:00'],
            ['key' => hash('sha256', 'ending'), 'hits' => 3, 'window_ends_at' => '2027-01-15 10:05:00'],
            ['key' => hash('sha256', 'open'), 'hits' => 3, 'window_ends_at' => '2027-01-15 10:05:01'],
        ]);

        self::assertEqualsCanonicalizing([hash('sha256', 'ended'), hash('sha256', 'ending')], (new RateLimit)->prunable()->pluck('key')->all());

        Artisan::call('model:prune', ['--model' => [RateLimit::class]]);

        self::assertSame([hash('sha256', 'open')], DB::table('rate_limits')->pluck('key')->all());
    }
}
