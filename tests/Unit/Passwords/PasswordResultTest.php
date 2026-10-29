<?php

declare(strict_types = 1);

namespace Tests\Unit\Passwords;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Passwords\Enums\PasswordFlow;
use SineMacula\Laravel\Authentication\Passwords\Enums\PasswordViolation;
use SineMacula\Laravel\Authentication\Passwords\PasswordCheck;
use SineMacula\Laravel\Authentication\Passwords\PasswordResult;

/**
 * Unit tests for the password results and the values their enums carry, which
 * applications store and branch on.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PasswordResult::class)]
#[CoversClass(PasswordCheck::class)]
final class PasswordResultTest extends TestCase
{
    /**
     * A password set reports how many devices its flow revoked and no
     * violation; one rejected reports its violations, nothing revoked.
     *
     * @return void
     */
    public function testASetPasswordAndARejectedOne(): void
    {
        $set      = PasswordResult::set(3);
        $rejected = PasswordResult::rejected([PasswordViolation::TOO_SHORT, PasswordViolation::SYMBOLS]);

        self::assertSame([true, [], 3], [$set->set, $set->violations, $set->revoked]);
        self::assertSame([false, [PasswordViolation::TOO_SHORT, PasswordViolation::SYMBOLS], 0], [$rejected->set, $rejected->violations, $rejected->revoked]);
    }

    /**
     * A check passes only with no violation.
     *
     * @return void
     */
    public function testACheckPassesOnlyWithNoViolation(): void
    {
        self::assertTrue((new PasswordCheck([]))->passes());
        self::assertFalse((new PasswordCheck([PasswordViolation::BREACHED]))->passes());
    }

    /**
     * The flows and violations, in order, with their values.
     *
     * @return void
     */
    public function testTheEnumValues(): void
    {
        self::assertSame(['registration', 'change', 'reset'], array_map(static fn (PasswordFlow $flow): string => $flow->value, PasswordFlow::cases()));
        self::assertSame(
            ['too_short', 'too_long', 'letters', 'mixed_case', 'numbers', 'symbols', 'breached', 'breach_check_unavailable'],
            array_map(static fn (PasswordViolation $violation): string => $violation->value, PasswordViolation::cases()),
        );
    }
}
