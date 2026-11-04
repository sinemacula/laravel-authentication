<?php

declare(strict_types = 1);

namespace Tests\Unit\Sessions\Enums;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Sessions\Enums\FactorChangeStatus;

/**
 * Unit tests for what judging the current session again after a change of the
 * factor package's can do to it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FactorChangeStatus::class)]
final class FactorChangeStatusTest extends TestCase
{
    /**
     * The session is kept active, returned to pending, revoked or skipped,
     * named by these values.
     *
     * @return void
     */
    public function testTheStatusesAreTheirValues(): void
    {
        self::assertSame(['active', 'pending', 'revoked', 'skipped'], array_map(static fn (FactorChangeStatus $status): string => $status->value, FactorChangeStatus::cases()));
    }
}
