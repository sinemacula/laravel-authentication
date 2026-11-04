<?php

declare(strict_types = 1);

namespace Tests\Unit\Factors\Enums;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Factors\Enums\FactorChangeMade;

/**
 * Unit tests for the changes the factor package judges the current session
 * again after.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FactorChangeMade::class)]
final class FactorChangeMadeTest extends TestCase
{
    /**
     * A factor confirmed, a passkey registered as a factor, a factor removed
     * and any other change, named by these values, none of them a freshness
     * operation's.
     *
     * @return void
     */
    public function testTheChangesCarryTheirValues(): void
    {
        self::assertSame(
            ['factor_confirmed', 'passkey_factor_registered', 'factor_removed', 'other'],
            array_map(static fn (FactorChangeMade $change): string => $change->value, FactorChangeMade::cases()),
        );
    }
}
