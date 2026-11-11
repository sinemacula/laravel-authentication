<?php

declare(strict_types = 1);

namespace Tests\Unit\Factors\Enums;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Factors\Enums\FactorChange;
use SineMacula\Laravel\Authentication\Freshness\Operations;

/**
 * Unit tests for the changes the factor-change gate is asked about.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FactorChange::class)]
final class FactorChangeTest extends TestCase
{
    /**
     * The changes carry the factor package's values for the same operations.
     *
     * @return void
     */
    public function testTheChangesCarryTheirValues(): void
    {
        self::assertSame(
            ['mfa.add_factor', 'mfa.add_first_additional_factor', 'mfa.replace_factor', 'mfa.remove_factor', 'mfa.generate_recovery_codes'],
            array_map(static fn (FactorChange $change): string => $change->value, FactorChange::cases()),
        );
    }

    /**
     * Rows of `[change, operation, names a factor]`.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Authentication\Factors\Enums\FactorChange, 1: string, 2: bool}>
     */
    public static function provideChanges(): iterable
    {
        yield 'adding a factor' => [FactorChange::ADD, Operations::FACTOR_CHANGE, false];
        yield 'adding the first factor' => [FactorChange::ADD_FIRST, Operations::FIRST_ADDITIONAL_FACTOR, false];
        yield 'replacing a factor' => [FactorChange::REPLACE, Operations::FACTOR_CHANGE, true];
        yield 'removing a factor' => [FactorChange::REMOVE, Operations::FACTOR_CHANGE, true];
        yield 'generating recovery codes' => [FactorChange::GENERATE_RECOVERY_CODES, Operations::FACTOR_CHANGE, false];
    }

    /**
     * A first additional factor is fresh for `first_additional_factor` and
     * every other change for `factor_change`.
     *
     * @param  \SineMacula\Laravel\Authentication\Factors\Enums\FactorChange  $change
     * @param  string  $operation
     * @param  bool  $namesFactor
     * @return void
     */
    #[DataProvider('provideChanges')]
    public function testEachChangeIsFreshForItsOperation(FactorChange $change, string $operation, bool $namesFactor): void
    {
        self::assertSame($operation, $change->operation());
        self::assertSame($namesFactor, $change->namesFactor());
    }
}
