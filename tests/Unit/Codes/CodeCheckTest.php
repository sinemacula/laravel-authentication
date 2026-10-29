<?php

declare(strict_types = 1);

namespace Tests\Unit\Codes;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Codes\Enums\CodeCheck;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;

/**
 * Unit tests for the failure reason each outcome of a code check reports: none
 * for an accepted code, its own reason for an expired or exhausted one, and
 * `invalid_credentials` for any other, so a code that was never issued looks
 * like a wrong one.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CodeCheck::class)]
final class CodeCheckTest extends TestCase
{
    /**
     * Rows of `[check, reason]`: every outcome and the reason it reports.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Authentication\Codes\Enums\CodeCheck, 1: ?\SineMacula\Laravel\Authentication\Events\Enums\FailureReason}>
     */
    public static function provideChecks(): iterable
    {
        yield from [
            'accepted'  => [CodeCheck::ACCEPTED, null],
            'invalid'   => [CodeCheck::INVALID, FailureReason::INVALID_CREDENTIALS],
            'expired'   => [CodeCheck::EXPIRED, FailureReason::CODE_EXPIRED],
            'exhausted' => [CodeCheck::EXHAUSTED, FailureReason::CODE_EXHAUSTED],
        ];
    }

    /**
     * Each outcome reports its reason.
     *
     * @param  \SineMacula\Laravel\Authentication\Codes\Enums\CodeCheck  $check
     * @param  ?\SineMacula\Laravel\Authentication\Events\Enums\FailureReason  $reason
     * @return void
     */
    #[DataProvider('provideChecks')]
    public function testEachOutcomeReportsItsReason(CodeCheck $check, ?FailureReason $reason): void
    {
        self::assertSame($reason, $check->failure());
    }

    /**
     * Every outcome has a row above.
     *
     * @return void
     */
    public function testEveryOutcomeIsListed(): void
    {
        self::assertSame(CodeCheck::cases(), array_column(iterator_to_array(self::provideChecks()), 0));
    }
}
