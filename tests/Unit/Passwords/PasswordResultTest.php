<?php

declare(strict_types = 1);

namespace Tests\Unit\Passwords;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
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
     * A password set reports how many sessions its flow revoked and no
     * violation; one rejected reports its violations, nothing revoked.
     *
     * @return void
     */
    public function testASetPasswordAndARejectedOne(): void
    {
        $set        = PasswordResult::set(3);
        $violations = [PasswordViolation::TOO_SHORT, PasswordViolation::SYMBOLS];
        $rejected   = PasswordResult::rejected($violations);

        self::assertSame([true, true, [], 3, null, null], [$set->set, $set->isSet(), $set->violations, $set->revoked, $set->reason, $set->retryAfter]);
        self::assertSame([false, false, $violations, 0, null], [$rejected->set, $rejected->isSet(), $rejected->violations, $rejected->revoked, $rejected->reason]);
    }

    /**
     * A refused change or establishment carries why, and for a rate limit the
     * wait, with nothing set, violated or revoked.
     *
     * @return void
     */
    public function testARefusedChangeCarriesWhy(): void
    {
        $refused = PasswordResult::refused(FailureReason::PASSWORD_NOT_SET);
        $limited = PasswordResult::refused(FailureReason::RATE_LIMITED, 42);

        self::assertSame(
            [false, [], 0, FailureReason::PASSWORD_NOT_SET, null],
            [$refused->isSet(), $refused->violations, $refused->revoked, $refused->reason, $refused->retryAfter],
        );
        self::assertSame([FailureReason::RATE_LIMITED, 42], [$limited->reason, $limited->retryAfter]);
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
        self::assertSame(['registration', 'change', 'reset', 'establishment'], array_map(static fn (PasswordFlow $flow): string => $flow->value, PasswordFlow::cases()));
        self::assertSame(
            ['too_short', 'too_long', 'null_character', 'letters', 'mixed_case', 'numbers', 'symbols', 'breached', 'breach_check_unavailable'],
            array_map(static fn (PasswordViolation $violation): string => $violation->value, PasswordViolation::cases()),
        );
    }
}
