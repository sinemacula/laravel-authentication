<?php

declare(strict_types = 1);

namespace Tests\Unit\Passkeys;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Passkeys\PasskeyFactorAssociation;

/**
 * Unit tests for a factor package's association of a passkey being registered.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PasskeyFactorAssociation::class)]
final class PasskeyFactorAssociationTest extends TestCase
{
    /**
     * The association carries the factor package's reference, of 1 to 255
     * characters, multibyte ones counted as one.
     *
     * @return void
     */
    public function testCarriesTheFactorsReference(): void
    {
        self::assertSame('factor-1', (new PasskeyFactorAssociation('factor-1'))->factor);
        self::assertSame('f', (new PasskeyFactorAssociation('f'))->factor);
        self::assertSame(str_repeat("\u{1F511}", 255), (new PasskeyFactorAssociation(str_repeat("\u{1F511}", 255)))->factor);
    }

    /**
     * An association carries no completion unless the gate gives it one, and
     * then carries that very object.
     *
     * @return void
     */
    public function testCarriesTheFactorPackagesCompletionOnlyWhenGiven(): void
    {
        $completion = new \stdClass;

        self::assertNull((new PasskeyFactorAssociation('factor-1'))->completion);
        self::assertSame($completion, (new PasskeyFactorAssociation('factor-1', $completion))->completion);
    }

    /**
     * Rows of references an association refuses.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideMalformedReferences(): iterable
    {
        yield 'empty' => [''];
        yield 'too long' => [str_repeat('f', 256)];
    }

    /**
     * An empty reference, or one longer than 255 characters, is refused.
     *
     * @param  string  $factor
     * @return void
     */
    #[DataProvider('provideMalformedReferences')]
    public function testRefusesAMalformedReference(string $factor): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('A passkey factor\'s reference must be 1 to 255 characters.');

        new PasskeyFactorAssociation($factor);
    }
}
