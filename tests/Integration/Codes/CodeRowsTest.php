<?php

declare(strict_types = 1);

namespace Tests\Integration\Codes;

use Carbon\CarbonImmutable;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Codes\CodeRows;
use SineMacula\Laravel\Authentication\Codes\Enums\CodeCheck;
use SineMacula\Laravel\Authentication\Models\OneTimeCode;
use Tests\Fixtures\Database\LockMarkingSQLiteGrammar;
use Tests\TestCase;

/**
 * Integration tests for the code table as the engine reads it: a key's row read
 * from the write PDO, with a lock when asked, whether it can still be checked,
 * and whether a stored transaction is the one given.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CodeRows::class)]
final class CodeRowsTest extends TestCase
{
    /** @var string The key the row is stored under. */
    private const string KEY = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';

    /**
     * A key's row is read from the write PDO, locked only when asked; a key
     * with no row reads as none.
     *
     * @return void
     */
    public function testFindsTheRowLockedWhenAsked(): void
    {
        $connection = DB::connection();

        if ($connection->getDriverName() === 'sqlite') {
            $connection->setQueryGrammar(new LockMarkingSQLiteGrammar($connection));
        }

        self::insertRow([]);

        $reads = [];

        $connection->listen(static function (QueryExecuted $query) use (&$reads): void {
            $reads[] = str_contains($query->sql, 'for update');
        });

        self::assertSame(self::KEY, CodeRows::find(self::KEY)?->id);
        self::assertSame(self::KEY, CodeRows::find(self::KEY, true)?->id);
        self::assertNull(CodeRows::find(str_repeat('b', 64)));
        self::assertSame([false, true, false], $reads);
        self::assertSame('one_time_codes', CodeRows::table()->from);
    }

    /**
     * Rows of `[the row's columns, max attempts, answer]`: a row can be checked
     * while it is unused, unexpired and under its attempts.
     *
     * @return iterable<string, array{0: ?array<string, mixed>, 1: int, 2: ?\SineMacula\Laravel\Authentication\Codes\Enums\CodeCheck}>
     */
    public static function provideRows(): iterable
    {
        yield from [
            'none'                => [null, 5, CodeCheck::INVALID],
            'used'                => [['consumed_at' => '2026-04-06 11:59:00'], 5, CodeCheck::INVALID],
            'expired this second' => [['expires_at' => '2026-04-06 12:00:00'], 5, CodeCheck::EXPIRED],
            'out of attempts'     => [['attempts' => 5], 5, CodeCheck::EXHAUSTED],
            'one attempt left'    => [['attempts' => 4], 5, null],
            'live'                => [[], 5, null],
        ];
    }

    /**
     * Each row is live, or says why not.
     *
     * @param  ?array<string, mixed>  $columns
     * @param  int  $max
     * @param  ?\SineMacula\Laravel\Authentication\Codes\Enums\CodeCheck  $answer
     * @return void
     */
    #[DataProvider('provideRows')]
    public function testSaysWhetherARowIsLive(?array $columns, int $max, ?CodeCheck $answer): void
    {
        if ($columns !== null) {
            self::insertRow($columns);
        }

        $row  = CodeRows::find(self::KEY);
        $live = CodeRows::live($row, $max, CarbonImmutable::createStrict(2026, 4, 6, 12, 0, 0));

        self::assertSame($answer ?? $row, $live);
    }

    /**
     * Two transactions are the same when both are absent or both are the same
     * digest, and never when only one is present.
     *
     * @return void
     */
    public function testComparesTransactions(): void
    {
        $digest = str_repeat('c', 64);

        self::assertTrue(CodeRows::isSameContext(null, null));
        self::assertTrue(CodeRows::isSameContext($digest, str_repeat('c', 64)));
        self::assertFalse(CodeRows::isSameContext($digest, str_repeat('d', 64)));
        self::assertFalse(CodeRows::isSameContext($digest, null));
        self::assertFalse(CodeRows::isSameContext(null, $digest));
    }

    /**
     * The class is a utility container only.
     *
     * @return void
     *
     * @SuppressWarnings("php:S3011")
     */
    public function testConstructorIsPrivate(): void
    {
        $reflection  = new \ReflectionClass(CodeRows::class);
        $constructor = $reflection->getConstructor();

        self::assertNotNull($constructor);
        self::assertTrue($constructor->isPrivate());

        $instance = $reflection->newInstanceWithoutConstructor();
        $constructor->invoke($instance);

        self::assertInstanceOf(CodeRows::class, $instance);
    }

    /**
     * Insert the row with the columns given over a live code's.
     *
     * @param  array<string, mixed>  $columns
     * @return void
     */
    private static function insertRow(array $columns): void
    {
        DB::table((new OneTimeCode)->getTable())->insert([
            'id'                => self::KEY,
            'challenge_id'      => '0195f4a2-7b1c-4000-8000-00000000000c',
            'purpose'           => 'sign_in',
            'guard'             => 'mobile',
            'issue_id'          => '0195f4a2-7b1c-4000-8000-00000000000a',
            'code_hash'         => str_repeat('f', 64),
            'attempts'          => 0,
            'deliveries'        => 1,
            'window_started_at' => '2026-04-06 11:55:00',
            'issued_at'         => '2026-04-06 11:55:00',
            'expires_at'        => '2026-04-06 12:05:00',
            ...$columns,
        ]);
    }
}
