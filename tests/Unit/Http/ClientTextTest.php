<?php

declare(strict_types = 1);

namespace Tests\Unit\Http;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Http\ClientText;

/**
 * Unit tests for the cleaning of text a client supplied, before it is stored.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ClientText::class)]
final class ClientTextTest extends TestCase
{
    /**
     * Any client-supplied value is cleaned to the length asked for, counted in
     * characters, with NUL bytes removed and invalid UTF-8 replaced, and
     * nothing left reads as `null`.
     *
     * @return void
     */
    public function testCleanCutsToTheGivenLengthInCharacters(): void
    {
        self::assertSame('Pixé', ClientText::clean("Pi\0xé 9", 4));
        self::assertSame('ab?', ClientText::clean("ab\xC3", 3));
        self::assertNull(ClientText::clean("\0\0", 4));
        self::assertNull(ClientText::clean(null, 4));
    }

    /**
     * Rows of `[given, cleaned]`.
     *
     * @return iterable<string, array{0: string, 1: ?string}>
     */
    public static function provideControlCharacters(): iterable
    {
        yield from [
            'NUL'                        => ["a\u{0000}b", 'ab'],
            'tab, line feed and return'  => ["a\tb\nc\rd", 'abcd'],
            'escape sequence'            => ["a\u{001B}[31mb", 'a[31mb'],
            'last C0 control'            => ["a\u{001F}b", 'ab'],
            'space kept'                 => ["a\u{0020}b", 'a b'],
            'tilde kept'                 => ["a\u{007E}b", 'a~b'],
            'DEL'                        => ["a\u{007F}b", 'ab'],
            'first C1 control'           => ["a\u{0080}b", 'ab'],
            'next line'                  => ["a\u{0085}b", 'ab'],
            'last C1 control'            => ["a\u{009F}b", 'ab'],
            'no-break space kept'        => ["a\u{00A0}b", "a\u{00A0}b"],
            'Arabic letter mark'         => ["a\u{061C}b", 'ab'],
            'Arabic neighbours kept'     => ["a\u{061B}\u{061D}b", "a\u{061B}\u{061D}b"],
            'left-to-right mark'         => ["a\u{200E}b", 'ab'],
            'right-to-left mark'         => ["a\u{200F}b", 'ab'],
            'zero-width joiner kept'     => ["a\u{200D}b", "a\u{200D}b"],
            'hyphen kept'                => ["a\u{2010}b", "a\u{2010}b"],
            'left-to-right embedding'    => ["a\u{202A}b", 'ab'],
            'right-to-left override'     => ["a\u{202E}b", 'ab'],
            'paragraph separator kept'   => ["a\u{2029}b", "a\u{2029}b"],
            'narrow no-break space kept' => ["a\u{202F}b", "a\u{202F}b"],
            'invisible plus kept'        => ["a\u{2064}b", "a\u{2064}b"],
            'left-to-right isolate'      => ["a\u{2066}b", 'ab'],
            'pop directional isolate'    => ["a\u{2069}b", 'ab'],
            'inhibit swapping kept'      => ["a\u{206A}b", "a\u{206A}b"],
            'only controls'              => ["\u{202E}\u{001B}\u{0085}", null],
        ];
    }

    /**
     * The C0 controls (NUL, tab and escape among them), DEL, the C1 controls
     * and every bidirectional mark, embedding, override and isolate are
     * removed, wherever they stand; the characters around them are kept.
     *
     * @param  string  $given
     * @param  ?string  $cleaned
     * @return void
     */
    #[DataProvider('provideControlCharacters')]
    public function testCleanRemovesControlAndBidirectionalCharacters(string $given, ?string $cleaned): void
    {
        self::assertSame($cleaned, ClientText::clean($given, 64));
    }

    /**
     * Removed characters never use up the length kept: the cut counts only what
     * is left.
     *
     * @return void
     */
    public function testCleanCutsAfterRemoving(): void
    {
        self::assertSame('abcd', ClientText::clean("\u{202E}\u{001B}\u{0085}abcde", 4));
    }

    /**
     * `ClientText` is a static utility; instantiation is disallowed through the
     * private constructor. Reflection invokes it so the line is covered while
     * still documenting the access modifier.
     *
     * @return void
     *
     * @SuppressWarnings("php:S3011")
     */
    public function testConstructorIsPrivate(): void
    {
        $reflection  = new \ReflectionClass(ClientText::class);
        $constructor = $reflection->getConstructor();

        self::assertNotNull($constructor);
        self::assertTrue($constructor->isPrivate());

        $instance = $reflection->newInstanceWithoutConstructor();
        $constructor->invoke($instance);
    }
}
