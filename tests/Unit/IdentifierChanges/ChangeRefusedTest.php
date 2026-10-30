<?php

declare(strict_types = 1);

namespace Tests\Unit\IdentifierChanges;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\IdentifierChanges\ChangeRefused;
use SineMacula\Laravel\Authentication\IdentifierChanges\Enums\IdentifierChangeOutcome;

/**
 * Unit tests for the refusal a confirmation throws to roll its transaction
 * back.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ChangeRefused::class)]
final class ChangeRefusedTest extends TestCase
{
    /**
     * It carries the outcome and the reason, and names the reason, nothing
     * more, in its message.
     *
     * @return void
     */
    public function testCarriesTheOutcomeAndTheReason(): void
    {
        $refusal = new ChangeRefused(IdentifierChangeOutcome::TAKEN, FailureReason::IDENTIFIER_TAKEN);

        self::assertSame([IdentifierChangeOutcome::TAKEN, FailureReason::IDENTIFIER_TAKEN], [$refusal->outcome, $refusal->reason]);
        self::assertSame('The identifier change was refused: identifier_taken.', $refusal->getMessage());
    }
}
