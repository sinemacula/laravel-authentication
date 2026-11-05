<?php

declare(strict_types = 1);

namespace Tests\Feature\Console;

use Carbon\Carbon;
use Illuminate\Console\Command;
use Illuminate\Database\Events\ModelPruningFinished;
use Illuminate\Database\Events\ModelPruningStarting;
use Illuminate\Database\Events\ModelsPruned;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Console\PruneSessionsCommand;
use SineMacula\Laravel\Authentication\Models\Session;
use Tests\Integration\Fixtures\IntegerKeyPruningSession;
use Tests\TestCase;

/**
 * Feature tests for `authentication:prune-sessions`: what it deletes and
 * prints, what `--pretend` and `--chunk` do, the events it dispatches around a
 * run, and how it fails.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PruneSessionsCommand::class)]
final class PruneSessionsCommandTest extends TestCase
{
    /** @var string The frozen time every test prunes at. */
    private const string NOW = '2027-01-15 10:00:00';

    /** @var string The cutoff for the default 30 days of retention. */
    private const string CUTOFF = '2026-12-16 10:00:00';

    /**
     * Freeze the clock.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        Carbon::setTestNow(Carbon::parse(self::NOW));
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
     * The command deletes the ended sessions, keeps the live one, and prints
     * the session model being pruned and the total, as `model:prune` does.
     *
     * @return void
     */
    public function testPrunesTheEndedSessionsAndPrintsTheTotal(): void
    {
        $this->insertSessions(3);

        $live = $this->insertSession(null);

        self::assertSame(Command::SUCCESS, Artisan::call('authentication:prune-sessions'));

        $output = Artisan::output();

        self::assertSame(1, substr_count($output, 'Pruning [' . Session::class . '] records.'));
        self::assertMatchesRegularExpression('/' . preg_quote(Session::class, '/') . '\W.*\b3 records/', $output);
        self::assertStringNotContainsString('No prunable', $output);
        self::assertSame([$live], DB::table('authentication_sessions')->pluck('id')->all());
    }

    /**
     * `--chunk` sets how many sessions each chunk deletes, and each chunk
     * prints its running total under the one heading.
     *
     * @return void
     */
    public function testPrintsALinePerChunk(): void
    {
        $this->insertSessions(5);

        self::assertSame(Command::SUCCESS, Artisan::call('authentication:prune-sessions', ['--chunk' => '2']));

        $output = Artisan::output();

        self::assertSame(1, substr_count($output, 'Pruning [' . Session::class . '] records.'));
        self::assertSame(1, preg_match_all('/\b2 records/', $output));
        self::assertSame(1, preg_match_all('/\b4 records/', $output));
        self::assertSame(1, preg_match_all('/\b5 records/', $output));
        self::assertLessThan(strpos($output, '4 records'), strpos($output, '2 records'));
        self::assertLessThan(strpos($output, '5 records'), strpos($output, '4 records'));
        self::assertSame(0, DB::table('authentication_sessions')->count());
    }

    /**
     * With nothing to prune the command says so, deletes nothing, and prints no
     * heading.
     *
     * @return void
     */
    public function testSaysWhenNothingIsPrunable(): void
    {
        $this->insertSession(null);

        self::assertSame(Command::SUCCESS, Artisan::call('authentication:prune-sessions'));

        $output = Artisan::output();

        self::assertStringContainsString('No prunable [' . Session::class . '] records found.', $output);
        self::assertStringNotContainsString('Pruning [', $output);
        self::assertSame(1, DB::table('authentication_sessions')->count());
    }

    /**
     * `ModelPruningStarting` and `ModelPruningFinished` name the session model
     * around the run, before the first chunk is reported and after the last, as
     * `model:prune` dispatches them.
     *
     * @return void
     */
    public function testDispatchesThePruningEventsAroundTheRun(): void
    {
        $this->insertSessions(1);

        $order = [];

        Event::listen(ModelPruningStarting::class, static function (ModelPruningStarting $event) use (&$order): void {
            $order[] = ['starting', $event->models];
        });
        Event::listen(ModelsPruned::class, static function (ModelsPruned $event) use (&$order): void {
            $order[] = ['pruned', $event->model];
        });
        Event::listen(ModelPruningFinished::class, static function (ModelPruningFinished $event) use (&$order): void {
            $order[] = ['finished', $event->models];
        });

        Artisan::call('authentication:prune-sessions');

        self::assertSame([['starting', [Session::class]], ['pruned', Session::class], ['finished', [Session::class]]], $order);
    }

    /**
     * With nothing to prune, the run is still announced and finished.
     *
     * @return void
     */
    public function testDispatchesThePruningEventsWhenNothingIsPrunable(): void
    {
        Event::fake([ModelPruningStarting::class, ModelPruningFinished::class]);

        Artisan::call('authentication:prune-sessions');

        Event::assertDispatched(ModelPruningStarting::class, static fn (ModelPruningStarting $event): bool => $event->models === [Session::class]);
        Event::assertDispatched(ModelPruningFinished::class, static fn (ModelPruningFinished $event): bool => $event->models === [Session::class]);
    }

    /**
     * `--pretend` counts the sessions pruning would delete, deletes nothing and
     * dispatches no pruning event.
     *
     * @return void
     */
    public function testPretendCountsWithoutDeleting(): void
    {
        $this->insertSessions(2);
        $this->insertSession(null);

        Event::fake([ModelPruningStarting::class, ModelPruningFinished::class, ModelsPruned::class]);

        self::assertSame(Command::SUCCESS, Artisan::call('authentication:prune-sessions', ['--pretend' => true]));

        $output = Artisan::output();

        self::assertStringContainsString('2 [' . Session::class . '] records will be pruned.', $output);
        self::assertStringNotContainsString('Pruning [', $output);
        self::assertSame(3, DB::table('authentication_sessions')->count());

        Event::assertNothingDispatched();
    }

    /**
     * `--pretend` with nothing to prune says so, naming the configured session
     * model.
     *
     * @return void
     */
    public function testPretendSaysWhenNothingIsPrunableForTheConfiguredModel(): void
    {
        config()->set('authentication.session.model', IntegerKeyPruningSession::class);

        $this->insertSession(null);

        self::assertSame(Command::SUCCESS, Artisan::call('authentication:prune-sessions', ['--pretend' => true]));
        self::assertStringContainsString('No prunable [' . IntegerKeyPruningSession::class . '] records found.', Artisan::output());
    }

    /**
     * Chunk options that are not digits naming an integer from 1 up to PHP's
     * largest.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function refusedChunks(): iterable
    {
        yield 'zero' => ['0'];
        yield 'negative' => ['-1'];
        yield 'signed' => ['+5'];
        yield 'fraction' => ['1.5'];
        yield 'text' => ['abc'];
        yield 'empty' => [''];
        yield 'padded with whitespace' => [' 5'];
        yield 'beyond PHP integers' => ['99999999999999999999'];
    }

    /**
     * A refused chunk fails the command before anything is read, and deletes
     * nothing.
     *
     * @param  string  $chunk
     * @return void
     */
    #[DataProvider('refusedChunks')]
    public function testRefusesAChunkThatIsNotAPositiveInteger(string $chunk): void
    {
        $this->insertSessions(1);

        $queries = 0;

        DB::listen(static function () use (&$queries): void {
            $queries++;
        });

        self::assertSame(Command::FAILURE, Artisan::call('authentication:prune-sessions', ['--chunk' => $chunk]));
        self::assertStringContainsString('The --chunk option must be an integer of 1 or more.', Artisan::output());
        self::assertSame(0, $queries);
        self::assertSame(1, DB::table('authentication_sessions')->count());
    }

    /**
     * The largest chunk PHP can count is accepted.
     *
     * @return void
     */
    public function testAcceptsTheLargestChunk(): void
    {
        $this->insertSessions(1);

        self::assertSame(Command::SUCCESS, Artisan::call('authentication:prune-sessions', ['--chunk' => (string) PHP_INT_MAX]));
        self::assertSame(0, DB::table('authentication_sessions')->count());
    }

    /**
     * An invalid retention fails the run, as it failed `model:prune`, and
     * deletes nothing.
     *
     * @return void
     */
    public function testAnInvalidRetentionFails(): void
    {
        $this->insertSessions(1);

        config()->set('authentication.session.prune_after_days', 'thirty');

        try {
            Artisan::call('authentication:prune-sessions');

            self::fail('The retention was accepted.');
        } catch (\InvalidArgumentException $exception) {
            self::assertSame('authentication.session.prune_after_days must be an integer from 0 to 3650.', $exception->getMessage());
        }

        self::assertSame(1, DB::table('authentication_sessions')->count());
    }

    /**
     * Insert that many sessions revoked at the cutoff.
     *
     * @param  int  $count
     * @return void
     */
    private function insertSessions(int $count): void
    {
        for ($index = 0; $index < $count; $index++) {
            $this->insertSession(Carbon::parse(self::CUTOFF));
        }
    }

    /**
     * Insert one session of the shipped table, revoked then or live, and return
     * its key.
     *
     * @param  ?\Carbon\Carbon  $revokedAt
     * @return string
     */
    private function insertSession(?Carbon $revokedAt): string
    {
        $id     = (string) Str::uuid7();
        $future = Carbon::parse(self::NOW)->addDays(30);

        DB::table('authentication_sessions')->insert([
            'id'                   => $id,
            'generation'           => (string) Str::uuid7(),
            'authenticatable_type' => 'users',
            'authenticatable_id'   => '1',
            'guard'                => 'api',
            'idle_expires_at'      => $future,
            'absolute_expires_at'  => $future->copy()->addDays(30),
            'revoked_at'           => $revokedAt,
            'revoked_reason'       => $revokedAt === null ? null : 'revoked',
            'signed_in_at'         => Carbon::parse(self::NOW),
            'created_at'           => Carbon::parse(self::NOW),
            'updated_at'           => Carbon::parse(self::NOW),
        ]);

        return $id;
    }
}
