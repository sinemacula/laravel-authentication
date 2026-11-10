<?php

declare(strict_types = 1);

namespace Tests\Unit\Console;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Console\ConfigurationFinding;
use SineMacula\Laravel\Authentication\Console\Enums\FindingSeverity;

/**
 * Unit tests for the value a configuration check answers.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ConfigurationFinding::class)]
final class ConfigurationFindingTest extends TestCase
{
    /**
     * A finding holds its severity, message and guard, and names no guard by
     * default.
     *
     * @return void
     */
    public function testAFindingHoldsWhatItWasGiven(): void
    {
        $finding = new ConfigurationFinding(FindingSeverity::WARNING, 'Message.', 'api');

        self::assertSame(FindingSeverity::WARNING, $finding->severity);
        self::assertSame('Message.', $finding->message);
        self::assertSame('api', $finding->guard);
        self::assertNull((new ConfigurationFinding(FindingSeverity::ERROR, 'Message.'))->guard);
    }

    /**
     * The named constructors give an error and a warning, with or without a
     * guard.
     *
     * @return void
     */
    public function testTheNamedConstructorsSetTheSeverity(): void
    {
        $error   = ConfigurationFinding::error('Wrong.', 'api');
        $warning = ConfigurationFinding::warning('Odd.');

        self::assertSame(FindingSeverity::ERROR, $error->severity);
        self::assertSame('Wrong.', $error->message);
        self::assertSame('api', $error->guard);
        self::assertSame(FindingSeverity::WARNING, $warning->severity);
        self::assertSame('Odd.', $warning->message);
        self::assertNull($warning->guard);
    }
}
