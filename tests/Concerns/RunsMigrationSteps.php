<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use Illuminate\Database\Migrations\Migration;

/**
 * Runs a shipped migration's `up()` or `down()`, which the base `Migration`
 * class does not declare.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait RunsMigrationSteps
{
    /**
     * Run the migration's step, failing the test when it has none.
     *
     * @param  \Illuminate\Database\Migrations\Migration  $migration
     * @param  string  $step
     * @return void
     */
    protected static function runMigrationStep(Migration $migration, string $step = 'up'): void
    {
        $run = [$migration, $step];

        self::assertIsCallable($run, sprintf('The migration has no %s() step.', $step));

        $run();
    }
}
