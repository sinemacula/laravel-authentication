<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use Carbon\CarbonImmutable;
use Firebase\JWT\JWT;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Queue;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Testing\FakeIdentifierChangeNotifier;
use SineMacula\Laravel\Authentication\Testing\FakeOneTimeCodeSender;

/**
 * The set-up feature and integration tests of identifier changes start from:
 * frozen clocks, the `changeable_identities` table, known codes, the sender and
 * notifier fakes, and a faked queue, on top of the changeable identities'
 * helpers.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait ChangesIdentifiers
{
    use InteractsWithChangeableIdentities;

    /** @var \Carbon\CarbonImmutable The moment a test starts at. */
    protected CarbonImmutable $now;

    /** @var \SineMacula\Laravel\Authentication\Testing\FakeOneTimeCodeSender The sender change codes are delivered through. */
    protected FakeOneTimeCodeSender $sender;

    /** @var \SineMacula\Laravel\Authentication\Testing\FakeIdentifierChangeNotifier The notifier old identifiers are told through. */
    protected FakeIdentifierChangeNotifier $notifier;

    /**
     * Freeze the clocks, create the table, issue known codes, fake the sender
     * and the notifier, and fake a queue that a worker would run, so a delivery
     * is pushed as soon as it is dispatched.
     *
     * @return void
     */
    protected function startChanging(): void
    {
        $this->now = CarbonImmutable::createStrict(2026, 4, 6, 12, 0, 0);

        $this->moveTo($this->now);

        self::createChangeableIdentitiesTable();
        self::issueCodes([self::CODE, '246802', '975310', '864200', '531975', '102938']);

        config()->set('queue.default', 'database');
        config()->set('queue.connections.database', ['driver' => 'database']);

        Queue::fake();

        $this->sender   = FakeOneTimeCodeSender::fake($this->app);
        $this->notifier = FakeIdentifierChangeNotifier::fake($this->app);
    }

    /**
     * Drop the table and release the clocks.
     *
     * @return void
     */
    protected function stopChanging(): void
    {
        self::dropChangeableIdentitiesTable();

        CarbonImmutable::setTestNow();
        Carbon::setTestNow();

        JWT::$timestamp = null;
    }

    /**
     * Move the frozen clock, the token library's included, to the time given.
     *
     * @param  \Carbon\CarbonImmutable  $at
     * @return void
     */
    protected function moveTo(CarbonImmutable $at): void
    {
        CarbonImmutable::setTestNow($at);
        Carbon::setTestNow($at);

        JWT::$timestamp = $at->getTimestamp();
    }

    /**
     * Run every queued job of the class pushed so far, oldest first, and forget
     * them.
     *
     * @param  class-string  $class
     * @return int
     */
    protected function runQueued(string $class): int
    {
        $jobs = Queue::pushed($class);

        foreach ($jobs as $job) {
            $job->handle(app()); // @phpstan-ignore method.notFound
        }

        Queue::fake();

        return count($jobs);
    }

    /**
     * The `AuthenticationFailed` events recorded, in order.
     *
     * @return list<\SineMacula\Laravel\Authentication\Events\AuthenticationFailed>
     */
    protected function failures(): array
    {
        return array_values(array_filter($this->recorded, static fn (object $event): bool => $event instanceof AuthenticationFailed));
    }

    /**
     * How many rows the table holds now.
     *
     * @param  string  $table
     * @return int
     *
     * @phpstan-impure
     */
    protected static function rows(string $table): int
    {
        return DB::table($table)->count();
    }

    /**
     * The column of the table's first row, as a string.
     *
     * @param  string  $table
     * @param  string  $column
     * @return string
     *
     * @phpstan-impure
     */
    protected static function stored(string $table, string $column): string
    {
        $value = DB::table($table)->value($column);

        self::assertIsString($value);

        return $value;
    }

    /**
     * The attempts counted against the one code stored.
     *
     * @return int
     *
     * @phpstan-impure
     */
    protected static function codeAttempts(): int
    {
        $attempts = DB::table('one_time_codes')->value('attempts');

        self::assertIsNumeric($attempts);

        return (int) $attempts;
    }
}
