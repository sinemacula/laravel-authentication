<?php

declare(strict_types = 1);

namespace Tests\Unit\Passwords;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Passwords\Enums\PasswordViolation;
use SineMacula\Laravel\Authentication\Passwords\Enums\ResetStatus;
use SineMacula\Laravel\Authentication\Passwords\ResetResult;

/**
 * Unit tests for how a password reset ends, and the values its statuses carry,
 * which applications branch on.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ResetResult::class)]
final class ResetResultTest extends TestCase
{
    /**
     * A reset carries the devices it revoked; a limited one the wait; a
     * rejected one the violations; an invalid one nothing. Only a reset is
     * reset.
     *
     * @return void
     */
    public function testEachResetOutcomeCarriesOnlyItsOwnDetail(): void
    {
        $violations = [PasswordViolation::TOO_SHORT, PasswordViolation::BREACHED];

        $outcomes = [
            [ResetResult::reset(3), ResetStatus::RESET, [], null, 3, true],
            [ResetResult::invalid(), ResetStatus::INVALID, [], null, 0, false],
            [ResetResult::rateLimited(900), ResetStatus::RATE_LIMITED, [], 900, 0, false],
            [ResetResult::passwordRejected($violations), ResetStatus::PASSWORD_REJECTED, $violations, null, 0, false],
        ];

        foreach ($outcomes as [$result, $status, $expected, $retryAfter, $revoked, $reset]) {
            self::assertSame([$status, $expected, $retryAfter], [$result->status, $result->violations, $result->retryAfter]);
            self::assertSame([$revoked, $reset], [$result->revoked, $result->isReset()]);
        }
    }

    /**
     * The reset statuses, in order, with their values.
     *
     * @return void
     */
    public function testTheStatusValues(): void
    {
        $resets = array_map(static fn (ResetStatus $status): string => $status->value, ResetStatus::cases());

        self::assertSame(['reset', 'invalid', 'rate_limited', 'password_rejected'], $resets);
    }
}
