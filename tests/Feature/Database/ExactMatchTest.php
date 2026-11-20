<?php

declare(strict_types = 1);

namespace Tests\Feature\Database;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Database\ExactMatch;
use SineMacula\Laravel\Authentication\Models\Session;
use Tests\Concerns\PretendsStorageEngines;
use Tests\TestCase;

/**
 * Feature tests of the byte-exact comparison each engine compiles.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ExactMatch::class)]
final class ExactMatchTest extends TestCase
{
    use PretendsStorageEngines;

    /**
     * A column is compared under its collation and then byte for byte, in the
     * engine's own syntax.
     *
     * @param  string  $driver
     * @return void
     */
    #[DataProvider('provideStorageEngines')]
    public function testAColumnIsComparedByteForByte(string $driver): void
    {
        $statements = self::statementsOn($driver, static function (): void {
            $model = new Session;

            ExactMatch::where($model->newQuery(), $model, ['tenant_id' => 'alice'])->get();
        });

        $exact = [
            'mysql'   => '`authentication_sessions`.`tenant_id` = ? and cast(convert(`authentication_sessions`.`tenant_id` using utf8mb4) as binary) = ?',
            'mariadb' => '`authentication_sessions`.`tenant_id` = ? and cast(convert(`authentication_sessions`.`tenant_id` using utf8mb4) as binary) = ?',
            'pgsql'   => '"authentication_sessions"."tenant_id" = ? and cast("authentication_sessions"."tenant_id" as text) collate "C" = ?',
            'sqlite'  => '"authentication_sessions"."tenant_id" = ? and "authentication_sessions"."tenant_id" collate binary = ?',
            'sqlsrv'  => '[authentication_sessions].[tenant_id] = ? and concat([authentication_sessions].[tenant_id], \'.\') collate Latin1_General_BIN2 = concat(?, \'.\')',
        ];

        self::assertCount(1, $statements);
        self::assertStringEndsWith(' where ' . $exact[$driver], $statements[0]);
    }

    /**
     * A null value matches no row on any engine.
     *
     * @param  string  $driver
     * @return void
     */
    #[DataProvider('provideStorageEngines')]
    public function testANullValueMatchesNoRow(string $driver): void
    {
        $statements = self::statementsOn($driver, static function (): void {
            $model = new Session;

            ExactMatch::where($model->newQuery(), $model, ['tenant_id' => null, 'principal_id' => null])->get();
        });

        self::assertCount(1, $statements);
        self::assertStringEndsWith(' where 0 = 1 and 0 = 1', $statements[0]);
    }
}
