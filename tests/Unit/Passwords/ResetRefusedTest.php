<?php

declare(strict_types = 1);

namespace Tests\Unit\Passwords;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Passwords\ResetRefused;

/**
 * Unit tests for the refusal a password reset throws to roll back its
 * transaction.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ResetRefused::class)]
final class ResetRefusedTest extends TestCase
{
    /**
     * It carries the reason, and names only the reason in its message.
     *
     * @return void
     */
    public function testCarriesTheReason(): void
    {
        $thrown = new ResetRefused(FailureReason::IDENTITY_INACTIVE);

        self::assertInstanceOf(\RuntimeException::class, $thrown);
        self::assertSame(FailureReason::IDENTITY_INACTIVE, $thrown->reason);
        self::assertSame('The password reset was refused: identity_inactive.', $thrown->getMessage());
    }
}
