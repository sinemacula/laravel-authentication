<?php

declare(strict_types = 1);

namespace Tests\Unit\Passkeys;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Passkeys\PasskeyRemoval;

/**
 * Unit tests for how removing a passkey ends.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PasskeyRemoval::class)]
final class PasskeyRemovalTest extends TestCase
{
    /**
     * A removal carries only the completion it was given.
     *
     * @return void
     */
    public function testARemovalCarriesTheCompletionGiven(): void
    {
        $completion = new \stdClass;
        $removal    = PasskeyRemoval::removed($completion);

        self::assertTrue($removal->isRemoved());
        self::assertSame($completion, $removal->completion);
        self::assertTrue(PasskeyRemoval::removed()->isRemoved());
        self::assertNull(PasskeyRemoval::removed()->completion);
    }

    /**
     * A passkey that was not removed carries no completion.
     *
     * @return void
     */
    public function testAPasskeyNotRemovedCarriesNothing(): void
    {
        $removal = PasskeyRemoval::notRemoved();

        self::assertFalse($removal->isRemoved());
        self::assertNull($removal->completion);
    }

    /**
     * Removals are made only through their named constructors.
     *
     * @return void
     */
    public function testTheConstructorIsPrivate(): void
    {
        self::assertTrue((new \ReflectionMethod(PasskeyRemoval::class, '__construct'))->isPrivate());
    }
}
