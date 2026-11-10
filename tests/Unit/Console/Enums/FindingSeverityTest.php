<?php

declare(strict_types = 1);

namespace Tests\Unit\Console\Enums;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Console\Enums\FindingSeverity;

/**
 * Unit tests for the severities of a configuration finding.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FindingSeverity::class)]
final class FindingSeverityTest extends TestCase
{
    /**
     * A finding is an error or a warning, by these values.
     *
     * @return void
     */
    public function testThereAreTwoSeverities(): void
    {
        self::assertSame(['error', 'warning'], array_map(static fn (FindingSeverity $severity): string => $severity->value, FindingSeverity::cases()));
        self::assertSame(FindingSeverity::ERROR, FindingSeverity::from('error'));
        self::assertSame(FindingSeverity::WARNING, FindingSeverity::from('warning'));
    }
}
