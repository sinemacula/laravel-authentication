<?php

declare(strict_types = 1);

namespace Tests\Unit\Factors;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Factors\FactorReference;

/**
 * Unit tests for the rule every reference the factor package hands this package
 * is held to.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FactorReference::class)]
final class FactorReferenceTest extends TestCase
{
    /**
     * The longest reference accepted is the width a proof's factor reference
     * holds.
     *
     * @return void
     */
    public function testTheLongestReferenceIsTheWidthAProofRecords(): void
    {
        self::assertSame(255, FactorReference::MAX_LENGTH);
    }

    /**
     * References of one character, and of 255 counted in characters rather than
     * bytes, are accepted.
     *
     * @return void
     */
    public function testAcceptsAReferenceOfOneTo255Characters(): void
    {
        self::assertTrue(FactorReference::isValid('f'));
        self::assertTrue(FactorReference::isValid(str_repeat("\u{1F511}", 255)));
    }

    /**
     * Malformed references: missing, empty, and one character too long.
     *
     * @return iterable<string, array{?string}>
     */
    public static function provideMalformedReferences(): iterable
    {
        yield 'missing' => [null];
        yield 'empty' => [''];
        yield 'too long' => [str_repeat('f', 256)];
    }

    /**
     * A missing, empty or overlong reference is refused.
     *
     * @param  ?string  $reference
     * @return void
     */
    #[DataProvider('provideMalformedReferences')]
    public function testRefusesAMalformedReference(?string $reference): void
    {
        self::assertFalse(FactorReference::isValid($reference));
    }
}
