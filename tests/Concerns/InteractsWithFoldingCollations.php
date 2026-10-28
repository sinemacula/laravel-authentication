<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Tests\Integration\Fixtures\NamedIdentity;

/**
 * Owner columns under a collation that counts distinct keys as equal: MySQL's
 * default `utf8mb4_unicode_ci`, a PostgreSQL ICU collation that ignores case
 * and accents, and SQLite's `NOCASE`, which folds ASCII case only; and
 * identities keyed by name, whose keys can differ only in case or accent.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait InteractsWithFoldingCollations
{
    /**
     * Distinct keys the folding collations count as equal to `alice`.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideFoldedKeys(): iterable
    {
        yield from [
            'another case'   => ['Alice'],
            'another accent' => ["alic\u{E9}"],
        ];
    }

    /**
     * A saved identity keyed by the name, which no table needs to hold.
     *
     * @param  string  $key
     * @return \Tests\Integration\Fixtures\NamedIdentity
     */
    protected static function namedIdentity(string $key): NamedIdentity
    {
        $identity = new NamedIdentity(['id' => $key]);

        $identity->exists = true;

        return $identity;
    }

    /**
     * Put the table's string columns under the folding collation of the engine,
     * keeping whether they are nullable.
     *
     * @param  string  $table
     * @param  list<string>  $columns
     * @param  bool  $nullable
     * @return void
     */
    protected static function foldColumns(string $table, array $columns, bool $nullable = false): void
    {
        $collation = match (DB::connection()->getDriverName()) {
            'mysql' => 'utf8mb4_unicode_ci',
            'pgsql' => self::createFoldingPostgresCollation(),
            default => 'NOCASE',
        };

        Schema::table($table, static function (Blueprint $blueprint) use ($columns, $collation, $nullable): void {
            foreach ($columns as $column) {
                $blueprint->string($column)->collation($collation)->nullable($nullable)->change();
            }
        });
    }

    /**
     * Check the column finds the stored key by the folded one, which is what
     * made an owner condition match a key that is not the owner's; SQLite
     * cannot fold an accent, so the test is skipped there.
     *
     * @param  string  $table
     * @param  string  $column
     * @param  string  $folded
     * @return void
     */
    protected static function assertColumnFolds(string $table, string $column, string $folded): void
    {
        if (DB::connection()->getDriverName() === 'sqlite' && !mb_check_encoding($folded, 'ASCII')) {
            self::markTestSkipped('SQLite\'s NOCASE folds ASCII case only.');
        }

        self::assertSame(1, DB::table($table)->where($column, $folded)->count());
    }

    /**
     * Create a PostgreSQL collation that compares text ignoring case and
     * accents, and return its name.
     *
     * @return string
     */
    private static function createFoldingPostgresCollation(): string
    {
        DB::statement('create collation if not exists accent_insensitive (provider = icu, locale = \'und-u-ks-level1\', deterministic = false)');

        return 'accent_insensitive';
    }
}
